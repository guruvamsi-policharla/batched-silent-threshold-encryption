use crate::ste::utils::lagrange_poly;
use crate::utils::{ark_de, ark_se};
use ark_ec::{pairing::Pairing, PrimeGroup, ScalarMul, VariableBaseMSM};
use ark_ff::{Field, PrimeField};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, One, UniformRand, Zero};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
pub struct CRS<E: Pairing> {
    pub n: usize, // maximum number of parties in a committee
    pub l: usize, // number of messages encrypted in a homomorphic ciphertext

    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub gen_g: Vec<E::G1>, // generators for G1
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub gen_h: Vec<E::G2>, // generators for G2

    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub powers_of_g: Vec<Vec<E::G1Affine>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub powers_of_h: Vec<Vec<E::G2Affine>>,

    // preprocessed lagrange polynomials
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub li: Vec<Vec<E::G1>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub li_minus0: Vec<Vec<E::G1>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub li_x: Vec<Vec<E::G1>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub li_lj_z: Vec<Vec<Vec<E::G1>>>,

    // preprocessed lagrange polynomials in g2 (only needed for verifying hints)
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub li_g2: Vec<E::G2>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub li_minus0_g2: Vec<E::G2>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub li_x_g2: Vec<E::G2>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub li_lj_z_g2: Vec<Vec<E::G2>>,

    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub gamma_g2: Vec<E::G2>,

    // preprocessed Toeplitz matrix
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub y: Vec<Vec<E::G1Affine>>,
}

impl<E: Pairing> CRS<E> {
    pub fn new(n: usize, l: usize, rng: &mut impl Rng) -> Self {
        let tau = E::ScalarField::rand(rng);
        let r = (0..l)
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();

        // let r = (0..l)
        //     .map(|_| E::ScalarField::from(1u32))
        //     .collect::<Vec<_>>();

        let gen_g = (0..l)
            .map(|i| E::G1::generator() * r[i])
            .collect::<Vec<_>>();
        let gen_h = (0..l)
            .map(|i| E::G2::generator() * r[i])
            .collect::<Vec<_>>();

        let gamma = E::ScalarField::rand(rng);

        Self::deterministic_new(n, l, tau, gen_g, gen_h, gamma)
    }

    pub fn deterministic_new(
        n: usize,
        l: usize,
        tau: E::ScalarField,
        gen_g: Vec<E::G1>,
        gen_h: Vec<E::G2>,
        gamma: E::ScalarField,
    ) -> Self {
        let mut powers_of_tau = vec![E::ScalarField::one()];

        let mut cur = tau;
        for _ in 0..=n {
            powers_of_tau.push(cur);
            cur *= &tau;
        }

        let powers_of_g = gen_g
            .iter()
            .map(|g| g.batch_mul(&powers_of_tau[0..n + 1]))
            .collect::<Vec<_>>();

        let powers_of_h = gen_h
            .iter()
            .map(|h| h.batch_mul(&powers_of_tau[0..n + 1]))
            .collect::<Vec<_>>();

        // lagrange powers
        let mut li_evals: Vec<E::ScalarField> = vec![E::ScalarField::zero(); n];
        let mut li_evals_minus0: Vec<E::ScalarField> = vec![E::ScalarField::zero(); n];
        let mut li_evals_x: Vec<E::ScalarField> = vec![E::ScalarField::zero(); n];

        let tau2_inv: <E as Pairing>::ScalarField = (tau * tau).inverse().unwrap();
        for i in 0..n {
            let li = lagrange_poly(n, i);
            li_evals[i] = li.evaluate(&tau);

            li_evals_minus0[i] = (li_evals[i] - li.coeffs[0]) * tau;

            li_evals_x[i] = li_evals_minus0[i] * tau2_inv;
        }

        let z_eval = tau.pow(&[n as u64]) - E::ScalarField::one();
        let z_eval_inv = z_eval.inverse().unwrap();

        let mut li = vec![vec![E::G1::zero(); n]; l];
        let mut li_g2 = vec![E::G2::zero(); n];

        for j in 0..l {
            for i in 0..n {
                li[j][i] = gen_g[j] * li_evals[i];
            }
        }
        for i in 0..n {
            li_g2[i] = gen_h[0] * li_evals[i];
        }

        let mut li_minus0 = vec![vec![E::G1::zero(); n]; l];
        let mut li_minus0_g2 = vec![E::G2::zero(); n];

        for j in 0..l {
            for i in 0..n {
                li_minus0[j][i] = gen_g[j] * li_evals_minus0[i];
            }
        }

        for i in 0..n {
            li_minus0_g2[i] = gen_h[0] * li_evals_minus0[i];
        }

        let mut li_x = vec![vec![E::G1::zero(); n]; l];
        let mut li_x_g2 = vec![E::G2::zero(); n];

        for j in 0..l {
            for i in 0..n {
                li_x[j][i] = gen_g[j] * li_evals_x[i];
            }
        }

        for i in 0..n {
            li_x_g2[i] = gen_h[0] * li_evals_x[i];
        }

        let mut li_lj_z = vec![vec![vec![E::G1::zero(); n]; n]; l];
        let mut li_lj_z_g2 = vec![vec![E::G2::zero(); n]; n];

        for k in 0..l {
            for i in 0..n {
                for j in 0..n {
                    li_lj_z[k][i][j] = if i == j {
                        gen_g[k] * ((li_evals[i] * li_evals[i] - li_evals[i]) * z_eval_inv)
                    } else {
                        gen_g[k] * (li_evals[i] * li_evals[j] * z_eval_inv)
                    };
                }
            }
        }

        for i in 0..n {
            for j in 0..n {
                li_lj_z_g2[i][j] = if i == j {
                    gen_h[0] * ((li_evals[i] * li_evals[i] - li_evals[i]) * z_eval_inv)
                } else {
                    gen_h[0] * (li_evals[i] * li_evals[j] * z_eval_inv)
                };
            }
        }

        // Sample gamma and put it in the different basis
        let gamma_g2 = gen_h.iter().map(|&h| h * gamma).collect::<Vec<_>>();

        // Compute the Toeplitz matrix preprocessing ==================================================
        let mut top_tau = powers_of_tau.clone();
        top_tau.truncate(n);
        top_tau.reverse();
        top_tau.resize(2 * n, E::ScalarField::zero());

        let top_domain = Radix2EvaluationDomain::<E::ScalarField>::new(2 * n).unwrap();
        let top_tau = top_domain.fft(&top_tau);

        // Compute powers of top_tau
        let y = gen_g
            .iter()
            .map(|g| g.batch_mul(&top_tau))
            .collect::<Vec<_>>();

        Self {
            n,
            l,

            gen_g,
            gen_h,

            powers_of_g,
            powers_of_h,

            li,
            li_minus0,
            li_x,
            li_lj_z,

            li_g2,
            li_minus0_g2,
            li_x_g2,
            li_lj_z_g2,

            gamma_g2,

            y,
        }
    }

    pub fn commit_g1(&self, coeffs: &Vec<E::ScalarField>, chunk: usize) -> E::G1 {
        assert!(
            coeffs.len() <= self.powers_of_g[chunk].len(),
            "Too many coefficients {} for the given powers of tau {}",
            coeffs.len(),
            self.powers_of_g[chunk].len()
        );

        let plain_coeffs = coeffs.iter().map(|c| c.into_bigint()).collect::<Vec<_>>();
        <E::G1 as VariableBaseMSM>::msm_bigint(
            &self.powers_of_g[chunk][..coeffs.len()],
            plain_coeffs.as_slice(),
        )
    }

    pub fn commit_g2(&self, coeffs: &Vec<E::ScalarField>, chunk: usize) -> E::G2 {
        assert!(
            coeffs.len() <= self.powers_of_h[chunk].len(),
            "Too many coefficients for the given powers of tau"
        );

        let plain_coeffs = coeffs.iter().map(|c| c.into_bigint()).collect::<Vec<_>>();
        <E::G2 as VariableBaseMSM>::msm_bigint(
            &self.powers_of_h[chunk][..coeffs.len()],
            plain_coeffs.as_slice(),
        )
    }

    pub fn compute_opening_proof(
        &self,
        coeffs: &Vec<E::ScalarField>,
        point: &E::ScalarField,
        chunk: usize,
    ) -> E::G1 {
        let polynomial = DensePolynomial::from_coefficients_slice(&coeffs);
        let eval = polynomial.evaluate(point);

        let mut numerator = polynomial.clone();
        numerator.coeffs[0] -= eval;

        let divisor = DensePolynomial::from_coefficients_vec(vec![
            E::ScalarField::zero() - point,
            E::ScalarField::one(),
        ]);
        let witness_polynomial = &numerator / &divisor;

        self.commit_g1(&witness_polynomial.coeffs, chunk)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381 as E;
    use ark_bls12_381::Fr as F;
    use ark_ec::{pairing::Pairing, pairing::PairingOutput};
    use ark_poly::{
        univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
        Radix2EvaluationDomain,
    };
    use ark_std::{UniformRand, Zero};

    use crate::ste::utils::interp_mostly_zero;

    #[test]
    fn test_sumcheck() {
        // A(X).B(X) = \sum_i A(i).B(i) + X * Q_x(X) + Z(X) * Q_Z(X)
        let rng = &mut ark_std::test_rng();

        let n = 1 << 5;
        let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();

        // sample n random evals
        let a_evals = (0..n).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let b_evals = (0..n).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let mut s = F::zero();
        for i in 0..n {
            s += a_evals[i] * b_evals[i];
        }

        let a_coeffs = domain.ifft(&a_evals);
        let b_coeffs = domain.ifft(&b_evals);

        let a_poly = DensePolynomial::from_coefficients_vec(a_coeffs);
        let b_poly = DensePolynomial::from_coefficients_vec(b_coeffs);

        let c_poly = &a_poly * &b_poly;

        println!("a_poly deg: {}", a_poly.degree());
        println!("b_poly deg: {}", b_poly.degree());
        println!("c_poly deg: {}", c_poly.degree());

        let (qz, rem) = c_poly.divide_by_vanishing_poly(domain);
        println!("qz deg: {}", qz.degree());
        println!("rem deg: {}", rem.degree());

        assert_eq!(s / F::from(n as u64), rem.evaluate(&F::zero()));
    }

    #[test]
    fn test_kzg() {
        let rng = &mut ark_std::test_rng();

        let n = 1 << 3;
        let l = 8;
        let crs = crate::ste::crs::CRS::<E>::new(n, l, rng);

        let e_gh: Vec<PairingOutput<E>> = crs
            .gen_g
            .iter()
            .map(|g| E::pairing(g, crs.powers_of_h[0][0]))
            .collect();

        // sample n random coeffs
        let coeffs = interp_mostly_zero(&vec![F::from(1u32), F::from(3u32)]);

        let point = F::zero();

        for chunk in 0..l {
            let com = crs.commit_g1(&coeffs.coeffs, chunk);
            let pi = crs.compute_opening_proof(&coeffs.coeffs, &point, chunk);

            assert_eq!(
                E::pairing(com, crs.powers_of_h[0][0]) - E::pairing(pi, crs.powers_of_h[0][1]),
                e_gh[chunk]
            );
        }
    }
}
