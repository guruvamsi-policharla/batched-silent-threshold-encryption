use ark_ec::{
    pairing::{Pairing, PairingOutput},
    VariableBaseMSM,
};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};

use ark_std::{One, Zero};

use crate::ste::{
    aggregate::AggregateKey, crs::CRS, encryption::Ciphertext, setup::PartialDecryption,
    utils::interp_mostly_zero,
};

pub fn agg_dec<E: Pairing>(
    partial_decryptions: &Vec<PartialDecryption<E>>, //insert 0 if a party did not respond or verification failed
    ct: &Ciphertext<E>,
    selector: &[bool],
    agg_key: &AggregateKey<E>,
    crs: &CRS<E>,
) -> Vec<PairingOutput<E>> {
    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(crs.n).unwrap();
    let domain_elements: Vec<E::ScalarField> = domain.elements().collect();

    // points is where B is set to zero
    // parties is the set of parties who have signed
    let mut points = vec![];
    let mut parties: Vec<usize> = Vec::new(); // parties indexed from 0..n-1
    for i in 0..crs.n {
        if selector[i] {
            parties.push(i);
        } else {
            points.push(domain_elements[i]);
        }
    }

    let b = interp_mostly_zero(&points);
    let b_evals = domain.fft(&b.coeffs);

    debug_assert_eq!(
        b.degree(),
        points.len(),
        "b.degree should be equal to points.len()"
    );
    debug_assert!(b.evaluate(&E::ScalarField::zero()) == E::ScalarField::one());

    // commit to b in g2
    let b_g2: Vec<E::G2> = (0..crs.l)
        .map(|chunk| crs.commit_g2(&b.coeffs, chunk))
        .collect();

    // q0 = (b-1)/x
    let q0_g1: Vec<E::G1> = (0..crs.l)
        .map(|chunk| crs.compute_opening_proof(&b.coeffs, &E::ScalarField::zero(), chunk))
        .collect();

    // bhat = x^{t} * b
    // insert t 0s at the beginning of bhat.coeffs
    let mut bhat_coeffs = vec![E::ScalarField::zero(); ct.t];
    bhat_coeffs.append(&mut b.coeffs.clone());
    let bhat = DensePolynomial::from_coefficients_vec(bhat_coeffs);
    debug_assert_eq!(bhat.degree(), crs.n);

    let bhat_g1: Vec<E::G1> = (0..crs.l)
        .map(|chunk| crs.commit_g1(&bhat.coeffs, chunk))
        .collect();

    let n_inv = E::ScalarField::one() / E::ScalarField::from(crs.n as u128);

    // compute the aggregate public key
    let mut bases: Vec<Vec<<E as Pairing>::G1Affine>> = vec![vec![]; crs.l];
    let mut scalars: Vec<<E as Pairing>::ScalarField> = Vec::new();
    for chunk in 0..crs.l {
        for &i in &parties {
            bases[chunk].push(agg_key.lag_pks[i].bls_pk[chunk].into());
        }
    }

    for &i in &parties {
        scalars.push(b_evals[i]);
    }

    let apk = (0..crs.l)
        .map(|chunk| E::G1::msm(bases[chunk].as_slice(), scalars.as_slice()).unwrap() * n_inv)
        .collect::<Vec<_>>();

    // computing [sk * s_3 * r[i] * gamma]_T directly from pd instead of via sigma
    let mut sigma_t = vec![PairingOutput::<E>::zero(); crs.l];
    let mut bases: Vec<<E as Pairing>::G1Affine> = vec![];
    let mut scalars: Vec<<E as Pairing>::ScalarField> = Vec::new();
    for &i in &parties {
        bases.push(partial_decryptions[i].pd.into());
    }
    for &i in &parties {
        scalars.push(b_evals[i]);
    }

    let agg_pd = E::G1::msm(bases.as_slice(), scalars.as_slice()).unwrap() * n_inv;

    for chunk in 0..crs.l {
        sigma_t[chunk] = E::pairing(agg_pd, crs.gamma_g2[chunk]);
    }

    // compute Qx, Qhatx and Qz
    let mut bases: Vec<Vec<<E as Pairing>::G1Affine>> = vec![vec![]; crs.l];
    let mut scalars: Vec<<E as Pairing>::ScalarField> = Vec::new();
    for chunk in 0..crs.l {
        for &i in &parties {
            bases[chunk].push(agg_key.lag_pks[i].sk_li_x[chunk].into());
        }
    }
    for &i in &parties {
        scalars.push(b_evals[i]);
    }

    let qx = (0..crs.l)
        .map(|chunk| E::G1::msm(bases[chunk].as_slice(), scalars.as_slice()).unwrap())
        .collect::<Vec<_>>();

    let mut bases: Vec<Vec<<E as Pairing>::G1Affine>> = vec![vec![]; crs.l];
    let mut scalars: Vec<<E as Pairing>::ScalarField> = Vec::new();
    for chunk in 0..crs.l {
        for &i in &parties {
            bases[chunk].push(agg_key.lag_pks[i].sk_li_minus0[chunk].into());
        }
    }
    for &i in &parties {
        scalars.push(b_evals[i]);
    }
    let qhatx = (0..crs.l)
        .map(|chunk| E::G1::msm(bases[chunk].as_slice(), scalars.as_slice()).unwrap())
        .collect::<Vec<_>>();

    let mut bases: Vec<Vec<<E as Pairing>::G1Affine>> = vec![vec![]; crs.l];
    let mut scalars: Vec<<E as Pairing>::ScalarField> = Vec::new();
    for chunk in 0..crs.l {
        for &i in &parties {
            bases[chunk].push(agg_key.agg_sk_li_lj_z[chunk][i].into());
        }
    }
    for &i in &parties {
        scalars.push(b_evals[i]);
    }
    let qz = (0..crs.l)
        .map(|chunk| E::G1::msm(bases[chunk].as_slice(), scalars.as_slice()).unwrap())
        .collect::<Vec<_>>();

    // e(w1||sa1, sa2||w2)
    let minus1 = -E::ScalarField::one();
    let w1 = (0..crs.l)
        .map(|chunk| {
            [
                apk[chunk] * (minus1),
                qz[chunk] * (minus1),
                qx[chunk] * (minus1),
                qhatx[chunk],
                bhat_g1[chunk] * (minus1),
                q0_g1[chunk] * (minus1),
            ]
        })
        .collect::<Vec<_>>();
    let w2 = (0..crs.l).map(|chunk| [b_g2[chunk]]).collect::<Vec<_>>();

    let mut enc_key = vec![PairingOutput::<E>::zero(); crs.l];
    for chunk in 0..crs.l {
        let mut enc_key_lhs = w1[chunk].to_vec();
        enc_key_lhs.append(&mut ct.sa1[0..1].to_vec());

        let mut enc_key_rhs = ct.sa2.to_vec();
        enc_key_rhs.append(&mut w2[chunk].to_vec());

        enc_key[chunk] = E::multi_pairing(enc_key_lhs, enc_key_rhs) + sigma_t[chunk];
    }

    (0..crs.l)
        .map(|chunk| ct.ct[chunk] - enc_key[chunk])
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dlog::Markers,
        ste::{
            crs::CRS,
            encryption::encrypt,
            setup::{PartialDecryption, SecretKey},
        },
    };
    use ark_ec::PrimeGroup;

    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn test_decryption() {
        let mut rng = ark_std::test_rng();
        let n = 1 << 3;
        let l = 8;
        let t: usize = n / 2;
        let dlog_size = 20;
        debug_assert!(t < n);

        let crs = CRS::new(n, l, &mut rng);

        let gen_t = PairingOutput::<E>::generator();

        let m = vec![gen_t; crs.l];

        let sk = (0..n)
            .map(|i| SecretKey::<E>::new(&mut rng, i))
            .collect::<Vec<_>>();

        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &crs))
            .collect::<Vec<_>>();

        let (ak, ek) = AggregateKey::<E>::new(pk, &crs);

        let ct = encrypt::<E>(&ek, t, &crs, &m, &mut rng);

        // compute partial decryptions
        let mut partial_decryptions: Vec<PartialDecryption<E>> = Vec::new();
        for i in 0..t {
            partial_decryptions.push(sk[i].partial_decryption(&ct));
        }
        for _ in t..n {
            partial_decryptions.push(PartialDecryption::<E>::zero());
        }

        // compute the selector
        let mut selector: Vec<bool> = Vec::new();
        for _ in 0..t {
            selector.push(true);
        }
        for _ in t..n {
            selector.push(false);
        }

        let recovered_m = agg_dec(&partial_decryptions, &ct, &selector, &ak, &crs);
        assert_eq!(recovered_m, m);

        // read the markers
        let path = &format!("markers_{}.bin", dlog_size);
        let markers = if std::path::Path::new(path).exists() {
            Markers::<PairingOutput<E>>::read_from_file(path)
        } else {
            println!("Markers file not found, generating new markers...");
            let m = Markers::<PairingOutput<E>>::new(dlog_size);
            m.save_to_file(path);
            m
        };
        for i in 0..crs.l {
            println!("{}", markers.compute_dlog(&recovered_m[i]).unwrap());
        }
    }
}
