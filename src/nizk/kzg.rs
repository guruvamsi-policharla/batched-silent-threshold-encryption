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

    pub fn verify_batch(
        &self,
        statements: &[KzgOpeningStatement<E>],
        weights: &[E::ScalarField],
    ) -> bool {
        if statements.len() != weights.len() {
            return false;
        }
        if statements.is_empty() {
            return true;
        }

        let mut lhs_bases = Vec::new();
        let mut lhs_scalars = Vec::new();
        let mut proof_sum_bases = Vec::new();
        let mut proof_sum_scalars = Vec::new();
        let g0 = self.g1_powers[0].into_group();
        for (statement, &weight) in statements.iter().zip(weights) {
            for &(base, scalar) in &statement.commitment_terms {
                lhs_bases.push(base);
                lhs_scalars.push(scalar * weight);
            }
            lhs_bases.push(g0);
            lhs_scalars.push(-(statement.opening.value * weight));
            lhs_bases.push(statement.opening.proof);
            lhs_scalars.push(statement.point * weight);

            proof_sum_bases.push(statement.opening.proof);
            proof_sum_scalars.push(weight);
        }

        let lhs = msm_g1::<E>(&lhs_bases, &lhs_scalars);
        let proof_sum = msm_g1::<E>(&proof_sum_bases, &proof_sum_scalars);
        E::pairing(lhs, self.g2_powers[0]) == E::pairing(proof_sum, self.g2_powers[1])
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

    pub fn verify_two_points_batch(
        &self,
        statements: &[KzgTwoPointOpeningStatement<E>],
        weights: &[E::ScalarField],
    ) -> bool {
        if statements.len() != weights.len() || self.g2_powers.len() < 3 {
            return false;
        }
        if statements.is_empty() {
            return true;
        }

        let mut lhs_g2_0_bases = Vec::new();
        let mut lhs_g2_0_scalars = Vec::new();
        let mut lhs_g2_1_bases = Vec::new();
        let mut lhs_g2_1_scalars = Vec::new();
        let mut rhs_g2_2_bases = Vec::new();
        let mut rhs_g2_2_scalars = Vec::new();
        let g0 = self.g1_powers[0].into_group();
        let g1 = self.g1_powers[1].into_group();
        for (statement, &weight) in statements.iter().zip(weights) {
            if statement.point_0 == statement.point_1 {
                return false;
            }
            let interpolation = linear_interpolation(
                statement.point_0,
                statement.opening.value_0,
                statement.point_1,
                statement.opening.value_1,
            );
            let point_sum = statement.point_0 + statement.point_1;
            let point_product = statement.point_0 * statement.point_1;

            for &(base, scalar) in &statement.commitment_terms {
                lhs_g2_0_bases.push(base);
                lhs_g2_0_scalars.push(scalar * weight);
            }
            lhs_g2_0_bases.push(g0);
            lhs_g2_0_scalars.push(-(interpolation[0] * weight));
            lhs_g2_0_bases.push(g1);
            lhs_g2_0_scalars.push(-(interpolation[1] * weight));
            lhs_g2_0_bases.push(statement.opening.proof);
            lhs_g2_0_scalars.push(-(point_product * weight));

            lhs_g2_1_bases.push(statement.opening.proof);
            lhs_g2_1_scalars.push(point_sum * weight);
            rhs_g2_2_bases.push(statement.opening.proof);
            rhs_g2_2_scalars.push(weight);
        }

        let lhs_g2_0 = msm_g1::<E>(&lhs_g2_0_bases, &lhs_g2_0_scalars);
        let lhs_g2_1 = msm_g1::<E>(&lhs_g2_1_bases, &lhs_g2_1_scalars);
        let rhs_g2_2 = msm_g1::<E>(&rhs_g2_2_bases, &rhs_g2_2_scalars);
        E::pairing(lhs_g2_0, self.g2_powers[0]) + E::pairing(lhs_g2_1, self.g2_powers[1])
            == E::pairing(rhs_g2_2, self.g2_powers[2])
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
pub struct KzgOpeningStatement<E: Pairing> {
    pub commitment_terms: Vec<(E::G1, E::ScalarField)>,
    pub point: E::ScalarField,
    pub opening: KzgOpening<E>,
}

#[derive(Clone, Debug)]
pub struct KzgTwoPointOpening<E: Pairing> {
    pub value_0: E::ScalarField,
    pub value_1: E::ScalarField,
    pub proof: E::G1,
}

#[derive(Clone, Debug)]
pub struct KzgTwoPointOpeningStatement<E: Pairing> {
    pub commitment_terms: Vec<(E::G1, E::ScalarField)>,
    pub point_0: E::ScalarField,
    pub point_1: E::ScalarField,
    pub opening: KzgTwoPointOpening<E>,
}

fn msm_g1<E: Pairing>(bases: &[E::G1], scalars: &[E::ScalarField]) -> E::G1 {
    debug_assert_eq!(bases.len(), scalars.len());
    if bases.is_empty() {
        return E::G1::zero();
    }
    let bases = E::G1::normalize_batch(bases);
    let scalars = scalars.iter().map(|s| s.into_bigint()).collect::<Vec<_>>();
    E::G1::msm_bigint(&bases, &scalars)
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

    #[test]
    fn kzg_batch_openings_verify() {
        let mut rng = test_rng();
        let crs = Crs::<E>::new(8, &mut rng);
        let coeffs_a = vec![Fr::from(3u64), Fr::from(7u64), Fr::from(11u64)];
        let coeffs_b = vec![Fr::from(2u64), Fr::from(5u64), Fr::from(13u64)];
        let commitment_a = crs.commit(&coeffs_a);
        let commitment_b = crs.commit(&coeffs_b);
        let opening_a = crs.open(&coeffs_a, Fr::from(4u64));
        let opening_b = crs.open(&coeffs_b, Fr::from(6u64));
        let statements = vec![
            KzgOpeningStatement {
                commitment_terms: vec![(commitment_a, Fr::one())],
                point: Fr::from(4u64),
                opening: opening_a,
            },
            KzgOpeningStatement {
                commitment_terms: vec![(commitment_b, Fr::one())],
                point: Fr::from(6u64),
                opening: opening_b,
            },
        ];
        assert!(crs.verify_batch(&statements, &[Fr::from(17u64), Fr::from(19u64)]));
    }

    #[test]
    fn kzg_batch_two_point_openings_verify() {
        let mut rng = test_rng();
        let crs = Crs::<E>::new(8, &mut rng);
        let coeffs_a = vec![Fr::from(3u64), Fr::from(7u64), Fr::from(11u64)];
        let coeffs_b = vec![Fr::from(2u64), Fr::from(5u64), Fr::from(13u64)];
        let commitment_a = crs.commit(&coeffs_a);
        let commitment_b = crs.commit(&coeffs_b);
        let opening_a = crs.open_two_points(&coeffs_a, Fr::from(4u64), Fr::from(8u64));
        let opening_b = crs.open_two_points(&coeffs_b, Fr::from(6u64), Fr::from(9u64));
        let statements = vec![
            KzgTwoPointOpeningStatement {
                commitment_terms: vec![(commitment_a, Fr::one())],
                point_0: Fr::from(4u64),
                point_1: Fr::from(8u64),
                opening: opening_a,
            },
            KzgTwoPointOpeningStatement {
                commitment_terms: vec![(commitment_b, Fr::one())],
                point_0: Fr::from(6u64),
                point_1: Fr::from(9u64),
                opening: opening_b,
            },
        ];
        assert!(crs.verify_two_points_batch(&statements, &[Fr::from(17u64), Fr::from(19u64)]));
    }
}
