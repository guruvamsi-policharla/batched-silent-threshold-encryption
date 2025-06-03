use crate::ste::crs::CRS;
use crate::ste::encryption::Ciphertext;
use crate::ste::utils::{lagrange_poly, open_all_values};
use ark_ec::{pairing::Pairing, AffineRepr, VariableBaseMSM};
use ark_ff::FftField;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_serialize::*;
use ark_std::{rand::RngCore, UniformRand, Zero};

use crate::utils::{ark_de, ark_se};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct LagPolys<F: FftField> {
    pub l: Vec<DensePolynomial<F>>,
    pub l_minus0: Vec<DensePolynomial<F>>,
    pub l_x: Vec<DensePolynomial<F>>,
    pub li_lj_z: Vec<Vec<DensePolynomial<F>>>,
    pub denom: F,
}

impl<F: FftField> LagPolys<F> {
    // domain is the roots of unity of size n
    pub fn new(n: usize) -> Self {
        let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();

        // compute polynomial L_i(X)
        let mut l = vec![DensePolynomial::zero(); n];
        for i in 0..n {
            l[i] = lagrange_poly(n, i);
        }

        // compute polynomial (L_i(X) - L_i(0))*X
        let mut l_minus0 = vec![DensePolynomial::zero(); n];
        for i in 0..n {
            let mut li_minus0_coeffs = l[i].coeffs.clone();
            li_minus0_coeffs[0] = F::zero();
            li_minus0_coeffs.insert(0, F::zero());
            l_minus0[i] = DensePolynomial::from_coefficients_vec(li_minus0_coeffs);
        }

        // compute polynomial (L_i(X) - L_i(0))/X
        let mut l_x = vec![DensePolynomial::zero(); n];
        for i in 0..n {
            l_x[i] = DensePolynomial::from_coefficients_vec(l_minus0[i].coeffs[2..].to_vec());
        }

        // compute polynomial L_i(X)*L_j(X)/Z(X) and (L_i(X)*L_i(X) - L_i(X))/Z(X)
        let mut li_lj_z = vec![vec![DensePolynomial::zero(); n]; n];
        for i in 0..n {
            for j in 0..n {
                li_lj_z[i][j] = if i == j {
                    (&l[i] * &l[i] - &l[i]).divide_by_vanishing_poly(domain).0
                } else {
                    (&l[i] * &l[j]).divide_by_vanishing_poly(domain).0
                };
            }
        }

        let mut denom = F::one();
        for i in 1..n {
            denom *= F::one() - domain.element(i);
        }

        // for i in 0..n {
        //     for j in 0..n {
        //         let monomial =
        //             DensePolynomial::from_coefficients_vec(vec![-domain.element(j), F::one()]);

        //         let computed = &l[i] / &monomial;
        //         assert_eq!(
        //             li_lj_z[i][j].evaluate(&F::zero()),
        //             computed.evaluate(&F::zero()) / (denom * domain.element(n - j))
        //         );
        //     }
        // }

        Self {
            l,
            l_minus0,
            l_x,
            li_lj_z,
            denom: denom.inverse().unwrap(),
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone)]
pub struct SecretKey<E: Pairing> {
    pub id: usize,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    sk: E::ScalarField,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PartialDecryption<E: Pairing> {
    /// Party id
    pub id: usize,
    /// Party commitment
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub pd: E::G1, // sk * (s_3 * [1]_1)
}

impl<E: Pairing> PartialDecryption<E> {
    pub fn zero() -> Self {
        PartialDecryption {
            id: 0,
            pd: E::G1::zero(),
        }
    }
}

/// Position oblivious public key -- slower to aggregate
#[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub bls_pk: Vec<E::G1>, //BLS pk
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub hints: Vec<Vec<E::G1Affine>>, //hints
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub y: Vec<Vec<E::G1Affine>>, // preprocessed toeplitz matrix. only for efficiency and can be computed from hints
    pub id: usize, // canonically assigned unique id in the system
}

/// Public key that can only be used in a fixed position -- faster to aggregate
#[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone)]
pub struct LagPublicKey<E: Pairing> {
    pub id: usize,       //id of the party
    pub position: usize, //position in the aggregate key
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub bls_pk: Vec<E::G1>, //BLS pk
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sk_li: Vec<E::G1>, //hint
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sk_li_minus0: Vec<E::G1>, //hint
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sk_li_lj_z: Vec<Vec<E::G1>>, //hint
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sk_li_x: Vec<E::G1>, //hint
}

impl<E: Pairing> LagPublicKey<E> {
    pub fn new(
        id: usize,
        position: usize,
        bls_pk: Vec<E::G1>,
        sk_li: Vec<E::G1>,
        sk_li_minus0: Vec<E::G1>,
        sk_li_lj_z: Vec<Vec<E::G1>>, //i = id
        sk_li_x: Vec<E::G1>,
    ) -> Self {
        LagPublicKey {
            id,
            position,
            bls_pk,
            sk_li,
            sk_li_minus0,
            sk_li_lj_z,
            sk_li_x,
        }
    }
}

impl<E: Pairing> SecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R, id: usize) -> Self {
        SecretKey {
            id,
            sk: E::ScalarField::rand(rng),
        }
    }

    pub fn from_scalar(sk: E::ScalarField, id: usize) -> Self {
        SecretKey { id, sk }
    }

    pub fn get_pk(&self, crs: &CRS<E>) -> PublicKey<E> {
        let mut hints = vec![vec![E::G1Affine::zero(); crs.n + 1]; crs.l];
        let bls_pk = crs.gen_g.iter().map(|&g| g * self.sk).collect::<Vec<_>>();

        for j in 0..crs.l {
            for i in 0..crs.n + 1 {
                hints[j][i] = (crs.powers_of_g[j][i] * self.sk).into();
            }
        }

        // compute y
        let mut y = vec![vec![E::G1Affine::zero(); 2 * crs.n]; crs.l];
        for j in 0..crs.l {
            for i in 0..2 * crs.n {
                y[j][i] = (crs.y[j][i] * self.sk).into();
            }
        }

        PublicKey {
            id: self.id,
            bls_pk,
            hints,
            y,
        }
    }

    pub fn get_lagrange_pk(&self, position: usize, crs: &CRS<E>) -> LagPublicKey<E> {
        let bls_pk = crs.gen_g.iter().map(|&g| g * self.sk).collect::<Vec<_>>();

        let sk_li = crs
            .li
            .iter()
            .map(|li| li[position] * self.sk)
            .collect::<Vec<_>>();

        let sk_li_minus0 = crs
            .li_minus0
            .iter()
            .map(|li_minus0| li_minus0[position] * self.sk)
            .collect::<Vec<_>>();

        let sk_li_x = crs
            .li_x
            .iter()
            .map(|li_x| li_x[position] * self.sk)
            .collect::<Vec<_>>();

        let mut sk_li_lj_z = vec![vec![E::G1::zero(); crs.n]; crs.l];
        for k in 0..crs.l {
            for j in 0..crs.n {
                sk_li_lj_z[k][j] = crs.li_lj_z[k][position][j] * self.sk;
            }
        }

        LagPublicKey {
            id: self.id,
            position,
            bls_pk,
            sk_li,
            sk_li_minus0,
            sk_li_lj_z,
            sk_li_x,
        }
    }

    pub fn partial_decryption(&self, ct: &Ciphertext<E>) -> PartialDecryption<E> {
        // todo: fix this
        PartialDecryption {
            id: self.id,
            pd: ct.sa1[1] * self.sk,
        }
    }
}

impl<E: Pairing> PublicKey<E> {
    pub fn get_lag_public_key(
        &self,
        position: usize,
        crs: &CRS<E>,
        lag_polys: &LagPolys<E::ScalarField>,
    ) -> LagPublicKey<E> {
        assert!(position < crs.n, "position out of bounds");

        let bls_pk = self.bls_pk.clone();

        // compute sk_li
        let mut sk_li = vec![E::G1::zero(); crs.l];
        for j in 0..crs.l {
            sk_li[j] = E::G1::msm(
                &self.hints[j][0..lag_polys.l[position].degree() + 1],
                &lag_polys.l[position],
            )
            .unwrap();
        }

        // compute sk_li_minus0
        let mut sk_li_minus0 = vec![E::G1::zero(); crs.l];
        for j in 0..crs.l {
            sk_li_minus0[j] = E::G1::msm(
                &self.hints[j][0..lag_polys.l_minus0[position].degree() + 1],
                &lag_polys.l_minus0[position],
            )
            .unwrap();
        }

        // compute sk_li_x
        let mut sk_li_x = vec![E::G1::zero(); crs.l];
        for j in 0..crs.l {
            sk_li_x[j] = E::G1::msm(
                &self.hints[j][0..lag_polys.l_x[position].degree() + 1],
                &lag_polys.l_x[position],
            )
            .unwrap();
        }

        // compute sk*Li*Lj/Z = sk*Li/(X-omega^j)*(omega^j/denom) for all j in [n]\{i}
        // for j = i: (Li^2 - Li)/Z = (Li - 1)/(X-omega^i)*(omega^i/denom)
        // this is the same as computing KZG opening proofs at all points
        // in the roots of unity domain for the polynomial Li(X), where the
        // crs is {g^sk, g^{sk * tau}, g^{sk * tau^2}, ...}
        // todo: optimize and maybe move to https://eprint.iacr.org/2024/1279.pdf
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(crs.n).unwrap();
        let mut sk_li_lj_z = vec![vec![E::G1::zero(); crs.n]; crs.l];
        for k in 0..crs.l {
            sk_li_lj_z[k] =
                open_all_values::<E>(&self.y[k], &lag_polys.l[position].coeffs, &domain);
            for j in 0..crs.n {
                sk_li_lj_z[k][j] *= domain.element(j) * lag_polys.denom;
            }
        }

        // // compute sk_li_lj_z
        // let mut sk_li_lj_z = vec![E::G1::zero(); crs.n];

        // let timer = start_timer!(|| "msm version");
        // for j in 0..crs.n {
        //     sk_li_lj_z[j] = E::G1::msm(
        //         &self.hints[0..lag_polys.li_lj_z[id][j].degree() + 1],
        //         &lag_polys.li_lj_z[id][j],
        //     )
        //     .unwrap();
        // }
        // end_timer!(timer);

        // assert_eq!(sk_li_lj_z, my_sk_li_lj_z);

        LagPublicKey {
            id: self.id,
            position,
            bls_pk,
            sk_li,
            sk_li_minus0,
            sk_li_lj_z,
            sk_li_x,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ste::aggregate::AggregateKey;
    type E = ark_bls12_381::Bls12_381;
    type F = ark_bls12_381::Fr;

    #[test]
    fn test_setup() {
        let mut rng = ark_std::test_rng();
        let n = 1 << 4;
        let l = 8;
        let crs = CRS::<E>::new(n, l, &mut rng);

        assert_eq!(crs.gen_g.len(), l);
        assert_eq!(crs.gen_h.len(), l);

        assert_eq!(crs.powers_of_g.len(), l);
        assert_eq!(crs.powers_of_g[0].len(), n + 1);

        assert_eq!(crs.powers_of_h.len(), l);
        assert_eq!(crs.powers_of_h[0].len(), n + 1);

        assert_eq!(crs.li.len(), l);
        assert_eq!(crs.li[0].len(), n);

        assert_eq!(crs.li_minus0.len(), l);
        assert_eq!(crs.li_minus0[0].len(), n);

        assert_eq!(crs.li_x.len(), l);
        assert_eq!(crs.li_x[0].len(), n);

        assert_eq!(crs.li_lj_z.len(), l);
        assert_eq!(crs.li_lj_z[0].len(), n);
        assert_eq!(crs.li_lj_z[0][0].len(), n);

        assert_eq!(crs.gamma_g2.len(), l);

        assert_eq!(crs.y.len(), l);
        assert_eq!(crs.y[0].len(), 2 * n);

        let sk = SecretKey::<E>::new(&mut rng, 0);
        let pk = sk.get_pk(&crs);

        assert_eq!(pk.id, sk.id);
        assert_eq!(pk.bls_pk.len(), l);
        assert_eq!(pk.hints.len(), l);
        assert_eq!(pk.hints[0].len(), n + 1);
        assert_eq!(pk.y.len(), l);
        assert_eq!(pk.y[0].len(), 2 * n);

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<LagPublicKey<E>> = Vec::new();
        let mut lagrange_pk: Vec<LagPublicKey<E>> = Vec::new();

        for i in 0..n {
            sk.push(SecretKey::<E>::new(&mut rng, i));
            pk.push(sk[i].get_lagrange_pk(i, &crs));
            lagrange_pk.push(sk[i].get_lagrange_pk(i, &crs));

            assert_eq!(pk[i].sk_li, lagrange_pk[i].sk_li);
            assert_eq!(pk[i].sk_li_minus0, lagrange_pk[i].sk_li_minus0);
            assert_eq!(pk[i].sk_li_x, lagrange_pk[i].sk_li_x); //computed incorrectly go fix it
            assert_eq!(pk[i].sk_li_lj_z, lagrange_pk[i].sk_li_lj_z);
        }

        let _ak = AggregateKey::<E>::new(pk, &crs);
    }

    #[test]
    fn test_setup_lag_setup() {
        let mut rng = ark_std::test_rng();
        let n = 8;
        let l = 8;
        let crs = CRS::<E>::new(n, l, &mut rng);
        let lagpolys = LagPolys::<F>::new(n);

        let sk = SecretKey::<E>::new(&mut rng, 0);
        let pk = sk.get_pk(&crs);

        let lag_pk = sk.get_lagrange_pk(0, &crs);

        let computed_lag_pk = pk.get_lag_public_key(0, &crs, &lagpolys);

        assert_eq!(computed_lag_pk.bls_pk, lag_pk.bls_pk);
        assert_eq!(computed_lag_pk.sk_li, lag_pk.sk_li);
        assert_eq!(computed_lag_pk.sk_li_minus0, lag_pk.sk_li_minus0);
        assert_eq!(computed_lag_pk.sk_li_x, lag_pk.sk_li_x);
        assert_eq!(computed_lag_pk.sk_li_lj_z, lag_pk.sk_li_lj_z);
    }
}
