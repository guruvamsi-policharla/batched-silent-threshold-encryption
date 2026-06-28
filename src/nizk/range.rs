use crate::nizk::{
    kzg::{self, KzgOpening},
    transcript::{
        append_serializable, append_usize, challenge_scalar, challenge_scalar_not_in_subgroup,
    },
};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{rand::Rng, One};
use merlin::Transcript;

#[derive(Clone, Debug)]
pub struct RangeWitness<F: PrimeField> {
    pub value: u128,
    pub blinding: F,
}

#[derive(Clone, Debug)]
pub struct RangeProof<E: Pairing> {
    pub bit_width: usize,
    pub chunks: Vec<ChunkRangeProof<E>>,
}

#[derive(Clone, Debug)]
pub struct ChunkRangeProof<E: Pairing> {
    pub com_g: E::G1,
    pub com_q: E::G1,
    pub g_at_rho: E::ScalarField,
    pub g_at_rho_omega: E::ScalarField,
    pub hat_w_at_rho: E::ScalarField,
    pub proof_g_at_rho_and_rho_omega: E::G1,
    pub proof_hat_w_at_rho: E::G1,
}

pub fn required_kzg_degree(bit_width: usize) -> usize {
    2 * bit_width + 1
}

pub fn prove<E: Pairing>(
    crs: &kzg::Crs<E>,
    commitments: &[E::G1],
    witnesses: &[RangeWitness<E::ScalarField>],
    bit_width: usize,
    rng: &mut impl Rng,
) -> RangeProof<E> {
    assert_eq!(commitments.len(), witnesses.len());
    assert!(bit_width > 0, "bit_width must be non-zero");
    assert!(bit_width < 128, "bit_width must fit in u128 checks");
    assert!(
        crs.max_degree >= required_kzg_degree(bit_width),
        "KZG CRS degree too small for BFGW range proof"
    );

    let chunks = commitments
        .iter()
        .zip(witnesses)
        .enumerate()
        .map(|(idx, (&commitment, witness))| {
            prove_chunk(crs, commitment, witness, bit_width, idx, rng)
        })
        .collect();

    RangeProof { bit_width, chunks }
}

pub fn verify<E: Pairing>(crs: &kzg::Crs<E>, commitments: &[E::G1], proof: &RangeProof<E>) -> bool {
    if commitments.len() != proof.chunks.len()
        || proof.bit_width == 0
        || proof.bit_width >= 128
        || crs.max_degree < required_kzg_degree(proof.bit_width)
    {
        return false;
    }

    commitments
        .iter()
        .zip(&proof.chunks)
        .enumerate()
        .all(|(idx, (&commitment, chunk_proof))| {
            verify_chunk(crs, commitment, chunk_proof, proof.bit_width, idx)
        })
}

fn prove_chunk<E: Pairing>(
    crs: &kzg::Crs<E>,
    commitment: E::G1,
    witness: &RangeWitness<E::ScalarField>,
    bit_width: usize,
    chunk_index: usize,
    rng: &mut impl Rng,
) -> ChunkRangeProof<E> {
    assert!(
        witness.value < (1u128 << bit_width),
        "range witness outside claimed bit width"
    );

    let f = kzg::value_commitment_polynomial(E::ScalarField::from(witness.value), witness.blinding);
    debug_assert_eq!(crs.commit(&f), commitment);

    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(bit_width)
        .expect("bit_width must have a roots-of-unity domain");
    let omega = domain.element(1);
    let omega_last = domain.element(bit_width - 1);

    let g = build_bfgw_g(witness.value, bit_width, rng);
    let com_g = crs.commit(&g);

    let mut transcript = range_transcript::<E>(bit_width, chunk_index, commitment);
    append_serializable(&mut transcript, b"com_g", &com_g);
    let alpha = challenge_scalar::<E::ScalarField>(&mut transcript, b"bfgw-alpha");

    let q = bfgw_quotient(&f, &g, bit_width, omega, omega_last, alpha);
    let com_q = crs.commit(&q);
    append_serializable(&mut transcript, b"com_q", &com_q);

    let rho =
        challenge_scalar_not_in_subgroup::<E::ScalarField>(&mut transcript, b"bfgw-rho", bit_width);
    let z_rho = rho.pow(&[bit_width as u64]) - E::ScalarField::one();
    let v1 = z_rho / (rho - E::ScalarField::one());

    let opening_g = crs.open_two_points(&g, rho, rho * omega);
    let hat_w = poly_add(&poly_scale(&f, v1), &poly_scale(&q, z_rho));
    let opening_hat_w_at_rho = crs.open(&hat_w, rho);

    ChunkRangeProof {
        com_g,
        com_q,
        g_at_rho: opening_g.value_0,
        g_at_rho_omega: opening_g.value_1,
        hat_w_at_rho: opening_hat_w_at_rho.value,
        proof_g_at_rho_and_rho_omega: opening_g.proof,
        proof_hat_w_at_rho: opening_hat_w_at_rho.proof,
    }
}

fn verify_chunk<E: Pairing>(
    crs: &kzg::Crs<E>,
    commitment: E::G1,
    proof: &ChunkRangeProof<E>,
    bit_width: usize,
    chunk_index: usize,
) -> bool {
    let domain = match Radix2EvaluationDomain::<E::ScalarField>::new(bit_width) {
        Some(domain) => domain,
        None => return false,
    };
    let omega = domain.element(1);
    let omega_last = domain.element(bit_width - 1);

    let mut transcript = range_transcript::<E>(bit_width, chunk_index, commitment);
    append_serializable(&mut transcript, b"com_g", &proof.com_g);
    let alpha = challenge_scalar::<E::ScalarField>(&mut transcript, b"bfgw-alpha");
    append_serializable(&mut transcript, b"com_q", &proof.com_q);
    let rho =
        challenge_scalar_not_in_subgroup::<E::ScalarField>(&mut transcript, b"bfgw-rho", bit_width);

    let z_rho = rho.pow(&[bit_width as u64]) - E::ScalarField::one();
    let v1 = z_rho / (rho - E::ScalarField::one());
    let v2 = z_rho / (rho - omega_last);

    let opening_g = kzg::KzgTwoPointOpening {
        value_0: proof.g_at_rho,
        value_1: proof.g_at_rho_omega,
        proof: proof.proof_g_at_rho_and_rho_omega,
    };
    if !crs.verify_two_points(proof.com_g, rho, rho * omega, &opening_g) {
        return false;
    }

    let hat_w_commitment = commitment * v1 + proof.com_q * z_rho;
    let opening_hat_w_at_rho = KzgOpening {
        value: proof.hat_w_at_rho,
        proof: proof.proof_hat_w_at_rho,
    };
    if !crs.verify(hat_w_commitment, rho, &opening_hat_w_at_rho) {
        return false;
    }

    let one = E::ScalarField::one();
    let two = E::ScalarField::from(2u64);
    let alpha_sq = alpha * alpha;
    let bit_expr = proof.g_at_rho - two * proof.g_at_rho_omega;
    let lhs = proof.g_at_rho * v1 - proof.hat_w_at_rho
        + alpha * proof.g_at_rho * (one - proof.g_at_rho) * v2
        + alpha_sq * bit_expr * (one - bit_expr) * (rho - omega_last);

    lhs.is_zero()
}

fn range_transcript<E: Pairing>(
    bit_width: usize,
    chunk_index: usize,
    commitment: E::G1,
) -> Transcript {
    let mut transcript = Transcript::new(b"sbte-bfgw-range-proof");
    append_usize(&mut transcript, b"bit_width", bit_width);
    append_usize(&mut transcript, b"chunk_index", chunk_index);
    append_serializable(&mut transcript, b"commitment", &commitment);
    transcript
}

fn build_bfgw_g<F: PrimeField>(value: u128, bit_width: usize, rng: &mut impl Rng) -> Vec<F> {
    let domain = Radix2EvaluationDomain::<F>::new(bit_width)
        .expect("bit_width must have a roots-of-unity domain");
    let mut evals = vec![F::zero(); bit_width];
    let bits = (0..bit_width)
        .map(|i| F::from(((value >> i) & 1) as u64))
        .collect::<Vec<_>>();

    evals[bit_width - 1] = bits[bit_width - 1];
    for i in (0..bit_width - 1).rev() {
        evals[i] = F::from(2u64) * evals[i + 1] + bits[i];
    }
    debug_assert_eq!(evals[0], F::from(value));

    let mut points = domain.elements().collect::<Vec<_>>();
    let mut values = evals;
    let extra_points = extra_interpolation_points::<F>(bit_width);
    points.extend(extra_points);
    values.push(F::rand(rng));
    values.push(F::rand(rng));

    interpolate(&points, &values)
}

fn extra_interpolation_points<F: PrimeField>(subgroup_size: usize) -> [F; 2] {
    let mut points = Vec::with_capacity(2);
    let mut candidate = F::from(2u64);
    while points.len() < 2 {
        if candidate.pow(&[subgroup_size as u64]) != F::one() && !points.contains(&candidate) {
            points.push(candidate);
        }
        candidate += F::one();
    }
    [points[0], points[1]]
}

fn bfgw_quotient<F: PrimeField>(
    f: &[F],
    g: &[F],
    bit_width: usize,
    omega: F,
    omega_last: F,
    alpha: F,
) -> Vec<F> {
    let z = vanishing_polynomial::<F>(bit_width);
    let z_except_one = kzg::quotient_by_linear(&z, F::one());
    let z_except_last = kzg::quotient_by_linear(&z, omega_last);
    let g_shift = poly_compose_mul_const(g, omega);
    let one_minus_g = poly_sub(&[F::one()], g);
    let two = F::from(2u64);
    let bit_diff = poly_sub(g, &poly_scale(&g_shift, two));
    let bit_diff_complement = poly_sub(&[F::one()], &bit_diff);

    let w1 = poly_mul(&poly_sub(g, f), &z_except_one);
    let w2 = poly_mul(&poly_mul(g, &one_minus_g), &z_except_last);
    let w3 = poly_mul(
        &poly_mul(&bit_diff, &bit_diff_complement),
        &[-omega_last, F::one()],
    );
    let r = poly_add(
        &poly_add(&w1, &poly_scale(&w2, alpha)),
        &poly_scale(&w3, alpha * alpha),
    );
    let (q, remainder) = divide_by_vanishing(&r, bit_width);
    debug_assert!(
        remainder.iter().all(|c| c.is_zero()),
        "BFGW quotient should divide by the vanishing polynomial"
    );
    q
}

fn vanishing_polynomial<F: PrimeField>(n: usize) -> Vec<F> {
    let mut coeffs = vec![F::zero(); n + 1];
    coeffs[0] = -F::one();
    coeffs[n] = F::one();
    coeffs
}

fn divide_by_vanishing<F: PrimeField>(poly: &[F], n: usize) -> (Vec<F>, Vec<F>) {
    let mut rem = trim(poly.to_vec());
    if rem.len() <= n {
        return (vec![F::zero()], rem);
    }

    let mut q = vec![F::zero(); rem.len() - n];
    while rem.len() > n {
        let degree = rem.len() - 1;
        let coeff = rem[degree];
        let q_degree = degree - n;
        q[q_degree] = coeff;
        rem[degree] -= coeff;
        rem[q_degree] += coeff;
        rem = trim(rem);
    }

    (trim(q), rem)
}

fn interpolate<F: PrimeField>(points: &[F], values: &[F]) -> Vec<F> {
    assert_eq!(points.len(), values.len());
    let mut result = vec![F::zero()];

    for (i, (&x_i, &y_i)) in points.iter().zip(values).enumerate() {
        let mut basis = vec![F::one()];
        let mut denom = F::one();
        for (j, &x_j) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            basis = poly_mul(&basis, &[-x_j, F::one()]);
            denom *= x_i - x_j;
        }
        result = poly_add(&result, &poly_scale(&basis, y_i / denom));
    }

    trim(result)
}

fn poly_compose_mul_const<F: PrimeField>(poly: &[F], factor: F) -> Vec<F> {
    let mut cur = F::one();
    let mut out = Vec::with_capacity(poly.len());
    for &coeff in poly {
        out.push(coeff * cur);
        cur *= factor;
    }
    trim(out)
}

fn poly_add<F: PrimeField>(a: &[F], b: &[F]) -> Vec<F> {
    let len = a.len().max(b.len());
    let mut out = vec![F::zero(); len];
    for i in 0..len {
        if i < a.len() {
            out[i] += a[i];
        }
        if i < b.len() {
            out[i] += b[i];
        }
    }
    trim(out)
}

fn poly_sub<F: PrimeField>(a: &[F], b: &[F]) -> Vec<F> {
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
    trim(out)
}

fn poly_scale<F: PrimeField>(a: &[F], scalar: F) -> Vec<F> {
    trim(a.iter().map(|c| *c * scalar).collect())
}

fn poly_mul<F: PrimeField>(a: &[F], b: &[F]) -> Vec<F> {
    if a.is_empty() || b.is_empty() {
        return vec![F::zero()];
    }
    let mut out = vec![F::zero(); a.len() + b.len() - 1];
    for (i, &a_i) in a.iter().enumerate() {
        for (j, &b_j) in b.iter().enumerate() {
            out[i + j] += a_i * b_j;
        }
    }
    trim(out)
}

fn trim<F: PrimeField>(mut coeffs: Vec<F>) -> Vec<F> {
    while coeffs.len() > 1 && coeffs.last().is_some_and(|c| c.is_zero()) {
        coeffs.pop();
    }
    if coeffs.is_empty() {
        coeffs.push(F::zero());
    }
    coeffs
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::{pairing::Pairing, AffineRepr};
    use ark_std::{test_rng, UniformRand};

    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    #[test]
    fn bfgw_range_proof_accepts_valid_chunk() {
        let mut rng = test_rng();
        let bit_width = 16;
        let crs = kzg::Crs::<E>::new(required_kzg_degree(bit_width), &mut rng);
        let witness = RangeWitness {
            value: 42_424,
            blinding: Fr::rand(&mut rng),
        };
        let commitment = crs.commit_value_with_blinding(Fr::from(witness.value), witness.blinding);

        let proof = prove(&crs, &[commitment], &[witness], bit_width, &mut rng);
        assert!(verify(&crs, &[commitment], &proof));
    }

    #[test]
    fn bfgw_range_proof_rejects_tampered_commitment() {
        let mut rng = test_rng();
        let bit_width = 16;
        let crs = kzg::Crs::<E>::new(required_kzg_degree(bit_width), &mut rng);
        let witness = RangeWitness {
            value: 10,
            blinding: Fr::rand(&mut rng),
        };
        let commitment = crs.commit_value_with_blinding(Fr::from(witness.value), witness.blinding);
        let proof = prove(&crs, &[commitment], &[witness], bit_width, &mut rng);
        let bad_commitment = commitment + crs.g1_powers[0].into_group();

        assert!(!verify(&crs, &[bad_commitment], &proof));
    }

    #[test]
    #[should_panic(expected = "range witness outside claimed bit width")]
    fn bfgw_range_proof_rejects_out_of_range_witness() {
        let mut rng = test_rng();
        let bit_width = 16;
        let crs = kzg::Crs::<E>::new(required_kzg_degree(bit_width), &mut rng);
        let witness = RangeWitness {
            value: 1u128 << bit_width,
            blinding: Fr::rand(&mut rng),
        };
        let commitment = crs.commit_value_with_blinding(Fr::from(witness.value), witness.blinding);
        let _ = prove(&crs, &[commitment], &[witness], bit_width, &mut rng);
    }
}
