use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
use ark_std::{rand::Rng, UniformRand};

#[derive(Clone, Debug)]
pub struct Crs<E: Pairing> {
    pub max_degree: usize,
    pub g1_powers: Vec<E::G1Affine>,
    pub g2_powers: Vec<E::G2Affine>,
}

impl<E: Pairing> Crs<E> {
    pub fn new(max_degree: usize, rng: &mut impl Rng) -> Self {
        let tau = E::ScalarField::rand(rng);
        Self::deterministic_new(max_degree, tau)
    }

    pub fn deterministic_new(max_degree: usize, tau: E::ScalarField) -> Self {
        let mut powers = Vec::with_capacity(max_degree + 1);
        let mut cur = E::ScalarField::one();
        for _ in 0..=max_degree {
            powers.push(cur);
            cur *= tau;
        }

        let g1 = E::G1::generator();
        let g2 = E::G2::generator();
        let g1_powers = powers.iter().map(|&x| (g1 * x).into_affine()).collect();
        let g2_powers = powers.iter().map(|&x| (g2 * x).into_affine()).collect();

        Self {
            max_degree,
            g1_powers,
            g2_powers,
        }
    }

    pub fn commit(&self, coeffs: &[E::ScalarField]) -> E::G1 {
        assert!(
            coeffs.len() <= self.max_degree + 1,
            "polynomial degree exceeds KZG CRS"
        );
        if coeffs.is_empty() {
            return E::G1::zero();
        }

        let scalars = coeffs.iter().map(|c| c.into_bigint()).collect::<Vec<_>>();
        E::G1::msm_bigint(&self.g1_powers[..coeffs.len()], &scalars)
    }

    pub fn open(&self, coeffs: &[E::ScalarField], point: E::ScalarField) -> KzgOpening<E> {
        let value = evaluate_polynomial(coeffs, point);
        let quotient = quotient_by_linear(coeffs, point);
        let proof = self.commit(&quotient);
        KzgOpening { value, proof }
    }

    pub fn open_two_points(
        &self,
        coeffs: &[E::ScalarField],
        point_0: E::ScalarField,
        point_1: E::ScalarField,
    ) -> KzgTwoPointOpening<E> {
        assert_ne!(point_0, point_1, "points must be distinct");
        let value_0 = evaluate_polynomial(coeffs, point_0);
        let value_1 = evaluate_polynomial(coeffs, point_1);
        let interpolation = linear_interpolation(point_0, value_0, point_1, value_1);
        let numerator = polynomial_sub(coeffs, &interpolation);
        let divisor = vec![
            point_0 * point_1,
            -(point_0 + point_1),
            E::ScalarField::one(),
        ];
        let proof = self.commit(&quotient_by_monic(&numerator, &divisor));
        KzgTwoPointOpening {
            value_0,
            value_1,
            proof,
        }
    }

    pub fn verify(
        &self,
        commitment: E::G1,
        point: E::ScalarField,
        opening: &KzgOpening<E>,
    ) -> bool {
        let lhs_g1 = commitment - self.g1_powers[0].into_group() * opening.value;
        let rhs_g2 = self.g2_powers[1].into_group() - self.g2_powers[0].into_group() * point;
        E::pairing(lhs_g1, self.g2_powers[0]) == E::pairing(opening.proof, rhs_g2)
    }

    pub fn verify_two_points(
        &self,
        commitment: E::G1,
        point_0: E::ScalarField,
        point_1: E::ScalarField,
        opening: &KzgTwoPointOpening<E>,
    ) -> bool {
        if point_0 == point_1 {
            return false;
        }
        let interpolation =
            linear_interpolation(point_0, opening.value_0, point_1, opening.value_1);
        let interpolation_commitment = self.commit(&interpolation);
        let divisor = vec![
            point_0 * point_1,
            -(point_0 + point_1),
            E::ScalarField::one(),
        ];
        let divisor_commitment = self.commit_g2(&divisor);
        E::pairing(commitment - interpolation_commitment, self.g2_powers[0])
            == E::pairing(opening.proof, divisor_commitment)
    }

    /// Commit to f(X) = value + blinding * (X - 1), so f(1) = value.
    pub fn commit_value_with_blinding(
        &self,
        value: E::ScalarField,
        blinding: E::ScalarField,
    ) -> E::G1 {
        self.commit(&value_commitment_polynomial(value, blinding))
    }

    fn commit_g2(&self, coeffs: &[E::ScalarField]) -> E::G2 {
        assert!(
            coeffs.len() <= self.max_degree + 1,
            "polynomial degree exceeds KZG CRS"
        );
        if coeffs.is_empty() {
            return E::G2::zero();
        }

        let scalars = coeffs.iter().map(|c| c.into_bigint()).collect::<Vec<_>>();
        E::G2::msm_bigint(&self.g2_powers[..coeffs.len()], &scalars)
    }
}

#[derive(Clone, Debug)]
pub struct KzgOpening<E: Pairing> {
    pub value: E::ScalarField,
    pub proof: E::G1,
}

#[derive(Clone, Debug)]
pub struct KzgTwoPointOpening<E: Pairing> {
    pub value_0: E::ScalarField,
    pub value_1: E::ScalarField,
    pub proof: E::G1,
}

pub fn value_commitment_polynomial<F: PrimeField>(value: F, blinding: F) -> Vec<F> {
    vec![value - blinding, blinding]
}

pub fn evaluate_polynomial<F: PrimeField>(coeffs: &[F], point: F) -> F {
    coeffs
        .iter()
        .rev()
        .fold(F::zero(), |acc, coeff| acc * point + coeff)
}

pub fn quotient_by_linear<F: PrimeField>(coeffs: &[F], point: F) -> Vec<F> {
    if coeffs.len() <= 1 {
        return vec![F::zero()];
    }

    let mut quotient = vec![F::zero(); coeffs.len() - 1];
    quotient[coeffs.len() - 2] = coeffs[coeffs.len() - 1];
    for i in (1..coeffs.len() - 1).rev() {
        quotient[i - 1] = coeffs[i] + quotient[i] * point;
    }
    quotient
}

pub fn quotient_by_monic<F: PrimeField>(coeffs: &[F], divisor: &[F]) -> Vec<F> {
    assert!(!divisor.is_empty(), "divisor must be non-empty");
    assert_eq!(*divisor.last().unwrap(), F::one(), "divisor must be monic");
    if coeffs.len() < divisor.len() {
        return vec![F::zero()];
    }

    let mut remainder = coeffs.to_vec();
    let mut quotient = vec![F::zero(); coeffs.len() - divisor.len() + 1];
    while remainder.len() >= divisor.len() {
        let degree = remainder.len() - divisor.len();
        let coeff = *remainder.last().unwrap();
        quotient[degree] = coeff;
        for (i, divisor_coeff) in divisor.iter().enumerate() {
            remainder[degree + i] -= coeff * divisor_coeff;
        }
        trim(&mut remainder);
    }
    quotient
}

fn linear_interpolation<F: PrimeField>(x0: F, y0: F, x1: F, y1: F) -> Vec<F> {
    let slope = (y1 - y0) / (x1 - x0);
    vec![y0 - slope * x0, slope]
}

fn polynomial_sub<F: PrimeField>(a: &[F], b: &[F]) -> Vec<F> {
    let len = a.len().max(b.len());
    let mut out = vec![F::zero(); len];
    for i in 0..len {
        if i < a.len() {
            out[i] += a[i];
        }
        if i < b.len() {
            out[i] -= b[i];
        }
    }
    trim(&mut out);
    out
}

fn trim<F: PrimeField>(coeffs: &mut Vec<F>) {
    while coeffs.len() > 1 && coeffs.last().is_some_and(|c| c.is_zero()) {
        coeffs.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::test_rng;

    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    #[test]
    fn kzg_opening_verifies() {
        let mut rng = test_rng();
        let crs = Crs::<E>::new(8, &mut rng);
        let coeffs = vec![Fr::from(3u64), Fr::from(7u64), Fr::from(11u64)];
        let commitment = crs.commit(&coeffs);
        let opening = crs.open(&coeffs, Fr::from(5u64));
        assert!(crs.verify(commitment, Fr::from(5u64), &opening));
    }

    #[test]
    fn kzg_rejects_wrong_value() {
        let mut rng = test_rng();
        let crs = Crs::<E>::new(8, &mut rng);
        let coeffs = vec![Fr::from(3u64), Fr::from(7u64), Fr::from(11u64)];
        let commitment = crs.commit(&coeffs);
        let mut opening = crs.open(&coeffs, Fr::from(5u64));
        opening.value += Fr::from(1u64);
        assert!(!crs.verify(commitment, Fr::from(5u64), &opening));
    }

    #[test]
    fn blinded_value_commitment_opens_at_one() {
        let mut rng = test_rng();
        let crs = Crs::<E>::new(8, &mut rng);
        let value = Fr::from(42u64);
        let blinding = Fr::from(99u64);
        let coeffs = value_commitment_polynomial(value, blinding);
        let commitment = crs.commit_value_with_blinding(value, blinding);
        let opening = crs.open(&coeffs, Fr::one());
        assert_eq!(opening.value, value);
        assert!(crs.verify(commitment, Fr::one(), &opening));
    }

    #[test]
    fn kzg_two_point_opening_verifies() {
        let mut rng = test_rng();
        let crs = Crs::<E>::new(8, &mut rng);
        let coeffs = vec![
            Fr::from(3u64),
            Fr::from(7u64),
            Fr::from(11u64),
            Fr::from(13u64),
        ];
        let commitment = crs.commit(&coeffs);
        let opening = crs.open_two_points(&coeffs, Fr::from(5u64), Fr::from(9u64));
        assert!(crs.verify_two_points(commitment, Fr::from(5u64), Fr::from(9u64), &opening));
    }
}
