// CCA ciphertext-validity proofs for the BSTE construction.
//
// This module adds the proof material needed by the CCA-secure variant:
//
// - Pedersen/KZG commitments to the decomposed PRF key chunks.
// - A polynomial-commitment range proof showing that every committed chunk is
//   in `[0, 2^CHUNK_BITS)`.
// - A compact Fiat-Shamir Schnorr proof linking the same chunks to the
//   punctured PRF key, the STE ciphertext, the Pedersen commitments, and the
//   public ciphertext mask.
//
// The convenience `prove`/`verify` methods use public-parameter digests
// internally, such that the Fiat-Shamir challenge hashes do not need to hash the large CRS every time. For repeated proofs under the same public parameters, prefer
// `CcaStatementContext` and the `*_with_context` methods so the large CRS is
// hashed once and reused. In practice, one could just attach a hash to the public parameters on-chain and verify it optimistically.

use crate::{
    bte::{self, encryption::CHUNK_BITS},
    ste::{self, aggregate::EncryptionKey},
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, PrimeGroup,
};
use ark_ff::{Field, PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::Rng, One, UniformRand};
use sha2::{Digest, Sha256};

// Public Pedersen/KZG commitments to the decomposed PRF key chunks.
//
// For chunk `i`, the commitment is a KZG commitment to a degree-1 polynomial
// `f_i(X) = chunk_i + r_i * (X - 1)`, so `f_i(1) = chunk_i`.
// Equivalently, it is a Pedersen commitment
// `G_i * chunk_i + H_i * r_i`, where `H_i = G_i^tau - G_i`.
#[derive(Clone, Debug, PartialEq)]
pub struct PedersenCommitments<E: Pairing> {
    // One commitment per PRF key chunk.
    pub commitments: Vec<E::G1>,
}

// Secret opening randomness for [`PedersenCommitments`].
#[derive(Clone, Debug, PartialEq)]
pub struct PedersenOpenings<E: Pairing> {
    // Blinding scalar for each committed chunk.
    pub randomness: Vec<E::ScalarField>,
}

// Cached Fiat-Shamir binding material for fixed public parameters.
//
// The CRS and encryption key are large, especially the STE CRS. This context
// stores collision-resistant digests of those public parameters so every proof
// transcript can bind to them without serializing the full CRS repeatedly.
#[derive(Clone, Debug, PartialEq)]
pub struct CcaStatementContext {
    // Digest used by the compact Schnorr proof transcript.
    pub validity_params_digest: [u8; 32],
    // Digest used by the range-proof transcripts.
    pub range_params_digest: [u8; 32],
}

// Full CCA validity proof for one BTE ciphertext.
//
// This combines:
//
// - a [`RangeProof`] that the committed chunks are valid `CHUNK_BITS`-bit
//   limbs, and
// - a compact [`SchnorrProof`] showing that the same chunks and randomness
//   honestly generate the PPRF key, STE encryption, ciphertext mask, and
//   Pedersen commitments.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidityProof<E: Pairing> {
    // Polynomial-commitment range proof for all committed chunks.
    pub range_proof: RangeProof<E>,
    // Fiat-Shamir challenge for the compact Schnorr proof.
    pub challenge: E::ScalarField,
    // Schnorr responses for the PRF key chunks.
    pub z_chunks: Vec<E::ScalarField>,
    // Schnorr responses for the five STE encryption randomness scalars.
    pub z_ste_randomness: [E::ScalarField; 5],
    // Schnorr responses for the Pedersen commitment blindings.
    pub z_commitment_randomness: Vec<E::ScalarField>,
}

// Compact Fiat-Shamir Schnorr proof for ciphertext/chunk consistency only.
//
// This is useful for benchmarking or for protocols that want to separate the
// range proof from the linear consistency proof. It does **not** prove that
// chunks are in range; use [`ValidityProof`] for the full validity proof.
#[derive(Clone, Debug, PartialEq)]
pub struct SchnorrProof<E: Pairing> {
    // Fiat-Shamir challenge. Commitments are reconstructed during verification.
    pub challenge: E::ScalarField,
    // Responses for PRF key chunks.
    pub z_chunks: Vec<E::ScalarField>,
    // Responses for STE encryption randomness.
    pub z_ste_randomness: [E::ScalarField; 5],
    // Responses for Pedersen commitment randomness.
    pub z_commitment_randomness: Vec<E::ScalarField>,
}

impl CcaStatementContext {
    // Hashes the public parameters once for reuse across many proofs.
    //
    // Both prover and verifier must construct the context from exactly the
    // same BTE CRS, STE CRS, and encryption key.
    pub fn new<E: Pairing>(
        bte_crs: &bte::crs::CRS<E>,
        ste_crs: &ste::crs::CRS<E>,
        ek: &EncryptionKey<E>,
    ) -> Self {
        Self {
            validity_params_digest: validity_params_digest(bte_crs, ste_crs, ek),
            range_params_digest: range_params_digest(ste_crs),
        }
    }
}

// Polynomial-commitment range proof for all PRF chunks.
//
// This follows the range-proof note:
// `A Simple Range Proof From Polynomial Commitments` https://hackmd.io/@dabo/B1U4kx8XI.
// For each committed chunk `z`, the prover commits to a polynomial `g`
// encoding the binary decomposition recurrence over the subgroup domain, then
// commits to a quotient polynomial `q`. Verification checks three KZG openings
// and a final scalar identity per chunk.
#[derive(Clone, Debug, PartialEq)]
pub struct RangeProof<E: Pairing> {
    // KZG commitments to the `g` polynomials, one per chunk.
    pub g_commitments: Vec<E::G1>,
    // KZG commitments to the quotient polynomials, one per chunk.
    pub q_commitments: Vec<E::G1>,
    // Fiat-Shamir challenge used to combine the three range constraints.
    pub tau: E::ScalarField,
    // Fiat-Shamir evaluation point outside the range-check subgroup.
    pub rho: E::ScalarField,
    // Openings/evaluations needed to verify each chunk's range proof.
    pub openings: Vec<RangeChunkProof<E>>,
}

// Per-chunk KZG openings used by [`RangeProof`].
#[derive(Clone, Debug, PartialEq)]
pub struct RangeChunkProof<E: Pairing> {
    // Claimed value `g(rho)`.
    pub g_at_rho: E::ScalarField,
    // Claimed value `g(rho * omega)`.
    pub g_at_rho_omega: E::ScalarField,
    // Claimed value of the verifier-constructed linear polynomial `w_hat(rho)`.
    pub w_hat_at_rho: E::ScalarField,
    // KZG opening for `g(rho)`.
    pub g_opening_at_rho: E::G1,
    // KZG opening for `g(rho * omega)`.
    pub g_opening_at_rho_omega: E::G1,
    // KZG opening for `w_hat(rho)`.
    pub w_hat_opening_at_rho: E::G1,
}

struct SchnorrCommitments<E: Pairing> {
    a_pprf_key: E::G1,
    a_mask: PairingOutput<E>,
    a_sa1: [E::G1; 2],
    a_sa2: [E::G2; 6],
    a_ct: Vec<PairingOutput<E>>,
    a_chunk_commitments: Vec<E::G1>,
}

impl<E: Pairing> PedersenCommitments<E> {
    // Commits to the provided PRF key chunks and returns the openings.
    //
    // The commitments are public statement elements for both the range proof
    // and the Schnorr consistency proof. The returned openings are witness
    // data and must remain secret.
    pub fn commit(
        chunks: &[E::ScalarField],
        ste_crs: &ste::crs::CRS<E>,
        rng: &mut impl Rng,
    ) -> (Self, PedersenOpenings<E>) {
        assert!(
            chunks.len() <= ste_crs.l,
            "too many chunks for the STE CRS commitment bases"
        );
        assert!(
            ste_crs.n >= 1,
            "STE CRS must contain at least two powers for Pedersen commitments"
        );

        let randomness = (0..chunks.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let commitments = chunks
            .iter()
            .zip(randomness.iter())
            .enumerate()
            .map(|(i, (chunk, blind))| {
                pedersen_value_base(ste_crs, i) * chunk + pedersen_blinding_base(ste_crs, i) * blind
            })
            .collect::<Vec<_>>();

        (Self { commitments }, PedersenOpenings { randomness })
    }
}

impl<E: Pairing> RangeProof<E> {
    // Creates a range proof and recomputes the range parameter digest.
    //
    // Prefer [`RangeProof::prove_with_context`] when many proofs are generated
    // under the same STE CRS.
    pub fn prove(
        chunk_commitments: &PedersenCommitments<E>,
        witness: &bte::encryption::EncryptionWitness<E>,
        commitment_openings: &PedersenOpenings<E>,
        ste_crs: &ste::crs::CRS<E>,
        rng: &mut impl Rng,
    ) -> Self {
        let context_digest = range_params_digest(ste_crs);
        Self::prove_with_context(
            &context_digest,
            chunk_commitments,
            witness,
            commitment_openings,
            ste_crs,
            rng,
        )
    }

    // Creates a range proof using a cached range-parameter digest.
    //
    // The witness supplies the chunk values. The Pedersen openings supply the
    // degree-1 polynomials `f_i` satisfying `f_i(1) = chunk_i`.
    pub fn prove_with_context(
        range_params_digest: &[u8; 32],
        chunk_commitments: &PedersenCommitments<E>,
        witness: &bte::encryption::EncryptionWitness<E>,
        commitment_openings: &PedersenOpenings<E>,
        ste_crs: &ste::crs::CRS<E>,
        rng: &mut impl Rng,
    ) -> Self {
        validate_range_statement_shape(chunk_commitments, ste_crs)
            .expect("invalid range-proof statement");
        assert_eq!(
            witness.chunks.len(),
            chunk_commitments.commitments.len(),
            "range witness and commitments must have the same number of chunks"
        );
        assert_eq!(
            commitment_openings.randomness.len(),
            chunk_commitments.commitments.len(),
            "range commitment openings and commitments must have the same length"
        );

        let mut f_polys = Vec::with_capacity(witness.chunks.len());
        let mut g_polys = Vec::with_capacity(witness.chunks.len());
        let mut g_commitments = Vec::with_capacity(witness.chunks.len());

        for i in 0..witness.chunks.len() {
            let f_poly = pedersen_polynomial(witness.chunks[i], commitment_openings.randomness[i]);
            let g_poly = range_g_polynomial::<E>(witness.chunks[i], rng);
            g_commitments.push(ste_crs.commit_g1(&g_poly.coeffs, i));
            f_polys.push(f_poly);
            g_polys.push(g_poly);
        }

        let tau = range_tau_challenge(range_params_digest, chunk_commitments, &g_commitments);
        let mut q_polys = Vec::with_capacity(witness.chunks.len());
        let mut q_commitments = Vec::with_capacity(witness.chunks.len());
        for i in 0..witness.chunks.len() {
            let q_poly = range_q_polynomial::<E>(&f_polys[i], &g_polys[i], tau);
            q_commitments.push(ste_crs.commit_g1(&q_poly.coeffs, i));
            q_polys.push(q_poly);
        }

        let rho = range_rho_challenge(
            range_params_digest,
            chunk_commitments,
            &g_commitments,
            tau,
            &q_commitments,
        );
        assert!(
            !is_in_range_domain::<E>(rho),
            "Fiat-Shamir rho landed in the range domain"
        );

        let rho_n_minus_one = rho.pow(&[CHUNK_BITS as u64]) - E::ScalarField::one();
        let rho_minus_one_inv = (rho - E::ScalarField::one())
            .inverse()
            .expect("rho must not be one");
        let first_quotient_at_rho = rho_n_minus_one * rho_minus_one_inv;
        let rho_omega = rho * range_omega::<E>();
        let openings = (0..witness.chunks.len())
            .map(|i| {
                let g_at_rho = g_polys[i].evaluate(&rho);
                let g_at_rho_omega = g_polys[i].evaluate(&rho_omega);
                let w_hat_poly = &scale_poly(&f_polys[i], first_quotient_at_rho)
                    + &scale_poly(&q_polys[i], rho_n_minus_one);
                let w_hat_at_rho = w_hat_poly.evaluate(&rho);
                RangeChunkProof {
                    g_at_rho,
                    g_at_rho_omega,
                    w_hat_at_rho,
                    g_opening_at_rho: ste_crs.compute_opening_proof(&g_polys[i].coeffs, &rho, i),
                    g_opening_at_rho_omega: ste_crs.compute_opening_proof(
                        &g_polys[i].coeffs,
                        &rho_omega,
                        i,
                    ),
                    w_hat_opening_at_rho: ste_crs.compute_opening_proof(
                        &w_hat_poly.coeffs,
                        &rho,
                        i,
                    ),
                }
            })
            .collect::<Vec<_>>();

        Self {
            g_commitments,
            q_commitments,
            tau,
            rho,
            openings,
        }
    }

    // Verifies a range proof and recomputes the range parameter digest.
    //
    // Prefer [`RangeProof::verify_with_context`] when verifying many proofs
    // under the same STE CRS.
    pub fn verify(
        &self,
        chunk_commitments: &PedersenCommitments<E>,
        ste_crs: &ste::crs::CRS<E>,
    ) -> bool {
        let context_digest = range_params_digest(ste_crs);
        self.verify_with_context(&context_digest, chunk_commitments, ste_crs)
    }

    // Verifies a range proof using a cached range-parameter digest.
    //
    // Returns `true` only if all committed chunks are proven to be in
    // `[0, 2^CHUNK_BITS)`.
    pub fn verify_with_context(
        &self,
        range_params_digest: &[u8; 32],
        chunk_commitments: &PedersenCommitments<E>,
        ste_crs: &ste::crs::CRS<E>,
    ) -> bool {
        if validate_range_statement_shape(chunk_commitments, ste_crs).is_err()
            || self.g_commitments.len() != chunk_commitments.commitments.len()
            || self.q_commitments.len() != chunk_commitments.commitments.len()
            || self.openings.len() != chunk_commitments.commitments.len()
        {
            return false;
        }

        let tau = range_tau_challenge(range_params_digest, chunk_commitments, &self.g_commitments);
        if tau != self.tau {
            return false;
        }
        let rho = range_rho_challenge(
            range_params_digest,
            chunk_commitments,
            &self.g_commitments,
            self.tau,
            &self.q_commitments,
        );
        if rho != self.rho || is_in_range_domain::<E>(self.rho) {
            return false;
        }

        let omega = range_omega::<E>();
        let omega_last = omega.pow(&[(CHUNK_BITS - 1) as u64]);
        let rho_omega = self.rho * omega;
        let rho_n_minus_one = self.rho.pow(&[CHUNK_BITS as u64]) - E::ScalarField::one();
        let first_quotient_at_rho = match (self.rho - E::ScalarField::one()).inverse() {
            Some(inv) => rho_n_minus_one * inv,
            None => return false,
        };
        let second_quotient_at_rho = match (self.rho - omega_last).inverse() {
            Some(inv) => rho_n_minus_one * inv,
            None => return false,
        };

        for i in 0..chunk_commitments.commitments.len() {
            let opening = &self.openings[i];
            if !verify_kzg_opening(
                ste_crs,
                i,
                self.g_commitments[i],
                self.rho,
                opening.g_at_rho,
                opening.g_opening_at_rho,
            ) || !verify_kzg_opening(
                ste_crs,
                i,
                self.g_commitments[i],
                rho_omega,
                opening.g_at_rho_omega,
                opening.g_opening_at_rho_omega,
            ) {
                return false;
            }

            let w_hat_commitment = chunk_commitments.commitments[i] * first_quotient_at_rho
                + self.q_commitments[i] * rho_n_minus_one;
            if !verify_kzg_opening(
                ste_crs,
                i,
                w_hat_commitment,
                self.rho,
                opening.w_hat_at_rho,
                opening.w_hat_opening_at_rho,
            ) {
                return false;
            }

            let w2_at_rho = opening.g_at_rho
                * (E::ScalarField::one() - opening.g_at_rho)
                * second_quotient_at_rho;
            let transition = opening.g_at_rho - E::ScalarField::from(2u64) * opening.g_at_rho_omega;
            let w3_at_rho = transition
                * (E::ScalarField::one() - opening.g_at_rho
                    + E::ScalarField::from(2u64) * opening.g_at_rho_omega)
                * (self.rho - omega_last);
            let check = opening.g_at_rho * first_quotient_at_rho
                + self.tau * w2_at_rho
                + self.tau.square() * w3_at_rho
                - opening.w_hat_at_rho;
            if !check.is_zero() {
                return false;
            }
        }

        true
    }
}

fn verify_kzg_opening<E: Pairing>(
    ste_crs: &ste::crs::CRS<E>,
    chunk: usize,
    commitment: E::G1,
    point: E::ScalarField,
    value: E::ScalarField,
    proof: E::G1,
) -> bool {
    // KZG opening check for C(X) at `point`:
    // e(C - value*G, H) = e(proof, tau*H - point*H).
    let value_base = pedersen_value_base(ste_crs, chunk);
    let lhs = E::pairing(commitment - value_base * value, ste_crs.powers_of_h[0][0]);
    let rhs = E::pairing(
        proof,
        ste_crs.powers_of_h[0][1].into_group() - ste_crs.powers_of_h[0][0].into_group() * point,
    );
    lhs == rhs
}

impl<E: Pairing> SchnorrProof<E> {
    // Proves the linear consistency relations without the range proof.
    //
    // This proves knowledge of the chunk values, STE encryption randomness,
    // and Pedersen blindings that explain the public ciphertext statement. It
    // intentionally does not prove that the chunks are small.
    pub fn prove_with_context(
        context: &CcaStatementContext,
        ciphertext: &bte::encryption::Ciphertext<E>,
        bte_crs: &bte::crs::CRS<E>,
        ste_crs: &ste::crs::CRS<E>,
        ek: &EncryptionKey<E>,
        chunk_commitments: &PedersenCommitments<E>,
        witness: &bte::encryption::EncryptionWitness<E>,
        commitment_openings: &PedersenOpenings<E>,
        rng: &mut impl Rng,
    ) -> Self {
        validate_statement_shape(ciphertext, bte_crs, ste_crs, ek, chunk_commitments)
            .expect("invalid Schnorr statement");
        assert_eq!(
            witness.chunks.len(),
            chunk_commitments.commitments.len(),
            "witness and commitments must have the same number of chunks"
        );
        assert_eq!(
            commitment_openings.randomness.len(),
            chunk_commitments.commitments.len(),
            "commitment openings and commitments must have the same length"
        );

        // First sample fresh Schnorr masks for every witness component. These
        // masks are the prover's one-time randomness for the proof, not the
        // encryption randomness from the ciphertext.
        let r_chunks = (0..witness.chunks.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let r_ste_randomness = [
            E::ScalarField::rand(rng),
            E::ScalarField::rand(rng),
            E::ScalarField::rand(rng),
            E::ScalarField::rand(rng),
            E::ScalarField::rand(rng),
        ];
        let r_commitment_randomness = (0..witness.chunks.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();

        // Build the first-round Schnorr commitments by running the public
        // linear maps on the masks. These mirror the ciphertext equations:
        // recomposed key -> PPRF key/mask, chunks/randomness -> STE ciphertext,
        // and chunks/blindings -> Pedersen commitments.
        let r_key = recompose_chunks::<E>(&r_chunks);
        let a_pprf_key = bte_crs.powers_of_g[ciphertext.pprf.point] * r_key;
        let a_mask = bte_crs.gt_powers[ciphertext.pprf.point] * r_key;
        let (a_sa1, a_sa2, a_ct) = ste_linear_commitments(
            ste_crs,
            ek,
            ciphertext.encrypted_key.t,
            &r_chunks,
            &r_ste_randomness,
        );
        let a_chunk_commitments = r_chunks
            .iter()
            .zip(r_commitment_randomness.iter())
            .enumerate()
            .map(|(i, (chunk, blind))| {
                pedersen_value_base(ste_crs, i) * chunk + pedersen_blinding_base(ste_crs, i) * blind
            })
            .collect::<Vec<_>>();

        let commitments = SchnorrCommitments {
            a_pprf_key,
            a_mask,
            a_sa1,
            a_sa2,
            a_ct,
            a_chunk_commitments,
        };
        // Fiat-Shamir binds the whole public statement and all first-round
        // commitments. The public-parameter digest is included so the proof
        // cannot be replayed under different CRS/encryption parameters.
        let challenge = challenge_scalar(
            &context.validity_params_digest,
            ciphertext,
            chunk_commitments,
            &commitments,
        );

        // Responses are z = mask + challenge * witness for each witness
        // family. Verification can reconstruct the omitted commitments from
        // these responses and the public statement.
        let z_chunks = r_chunks
            .iter()
            .zip(witness.chunks.iter())
            .map(|(r, w)| *r + challenge * w)
            .collect();
        let mut z_ste_randomness = [E::ScalarField::zero(); 5];
        for i in 0..5 {
            z_ste_randomness[i] = r_ste_randomness[i] + challenge * witness.ste_randomness.s[i];
        }
        let z_commitment_randomness = r_commitment_randomness
            .iter()
            .zip(commitment_openings.randomness.iter())
            .map(|(r, w)| *r + challenge * w)
            .collect();

        Self {
            challenge,
            z_chunks,
            z_ste_randomness,
            z_commitment_randomness,
        }
    }

    // Verifies the compact Schnorr/linkage proof without checking ranges.
    //
    // Verification reconstructs the omitted Schnorr commitments from
    // `(challenge, responses, public statement)` and re-derives the
    // Fiat-Shamir challenge.
    pub fn verify_with_context(
        &self,
        context: &CcaStatementContext,
        ciphertext: &bte::encryption::Ciphertext<E>,
        bte_crs: &bte::crs::CRS<E>,
        ste_crs: &ste::crs::CRS<E>,
        ek: &EncryptionKey<E>,
        chunk_commitments: &PedersenCommitments<E>,
    ) -> bool {
        if validate_statement_shape(ciphertext, bte_crs, ste_crs, ek, chunk_commitments).is_err() {
            return false;
        }
        if self.z_chunks.len() != chunk_commitments.commitments.len()
            || self.z_commitment_randomness.len() != chunk_commitments.commitments.len()
        {
            return false;
        }

        let commitments = reconstruct_schnorr_commitments(
            self.challenge,
            &self.z_chunks,
            &self.z_ste_randomness,
            &self.z_commitment_randomness,
            ciphertext,
            bte_crs,
            ste_crs,
            ek,
            chunk_commitments,
        );
        let challenge = challenge_scalar(
            &context.validity_params_digest,
            ciphertext,
            chunk_commitments,
            &commitments,
        );
        challenge == self.challenge
    }
}

impl<E: Pairing> ValidityProof<E> {
    // Creates a full CCA validity proof and recomputes the public-parameter
    // digests used by the Fiat-Shamir transcripts.
    pub fn prove(
        ciphertext: &bte::encryption::Ciphertext<E>,
        bte_crs: &bte::crs::CRS<E>,
        ste_crs: &ste::crs::CRS<E>,
        ek: &EncryptionKey<E>,
        chunk_commitments: &PedersenCommitments<E>,
        witness: &bte::encryption::EncryptionWitness<E>,
        commitment_openings: &PedersenOpenings<E>,
        rng: &mut impl Rng,
    ) -> Self {
        let context = CcaStatementContext::new(bte_crs, ste_crs, ek);
        Self::prove_with_context(
            &context,
            ciphertext,
            bte_crs,
            ste_crs,
            ek,
            chunk_commitments,
            witness,
            commitment_openings,
            rng,
        )
    }

    // Creates a full CCA validity proof with precomputed statement context.
    //
    // The witness must be the encryption witness for `ciphertext`, and the
    // Pedersen openings must open `chunk_commitments` to the same chunks.
    pub fn prove_with_context(
        context: &CcaStatementContext,
        ciphertext: &bte::encryption::Ciphertext<E>,
        bte_crs: &bte::crs::CRS<E>,
        ste_crs: &ste::crs::CRS<E>,
        ek: &EncryptionKey<E>,
        chunk_commitments: &PedersenCommitments<E>,
        witness: &bte::encryption::EncryptionWitness<E>,
        commitment_openings: &PedersenOpenings<E>,
        rng: &mut impl Rng,
    ) -> Self {
        validate_statement_shape(ciphertext, bte_crs, ste_crs, ek, chunk_commitments)
            .expect("invalid ciphertext-validity statement");
        assert_eq!(
            witness.chunks.len(),
            chunk_commitments.commitments.len(),
            "witness and commitments must have the same number of chunks"
        );
        assert_eq!(
            commitment_openings.randomness.len(),
            chunk_commitments.commitments.len(),
            "commitment openings and commitments must have the same length"
        );
        let range_proof = RangeProof::prove_with_context(
            &context.range_params_digest,
            chunk_commitments,
            witness,
            commitment_openings,
            ste_crs,
            rng,
        );

        // Schnorr randomizers for the three witness families: chunks, STE
        // encryption randomness, and Pedersen commitment blindings.
        let r_chunks = (0..witness.chunks.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let r_ste_randomness = [
            E::ScalarField::rand(rng),
            E::ScalarField::rand(rng),
            E::ScalarField::rand(rng),
            E::ScalarField::rand(rng),
            E::ScalarField::rand(rng),
        ];
        let r_commitment_randomness = (0..witness.chunks.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();

        let r_key = recompose_chunks::<E>(&r_chunks);
        let a_pprf_key = bte_crs.powers_of_g[ciphertext.pprf.point] * r_key;
        let a_mask = bte_crs.gt_powers[ciphertext.pprf.point] * r_key;
        let (a_sa1, a_sa2, a_ct) = ste_linear_commitments(
            ste_crs,
            ek,
            ciphertext.encrypted_key.t,
            &r_chunks,
            &r_ste_randomness,
        );
        let a_chunk_commitments = r_chunks
            .iter()
            .zip(r_commitment_randomness.iter())
            .enumerate()
            .map(|(i, (chunk, blind))| {
                pedersen_value_base(ste_crs, i) * chunk + pedersen_blinding_base(ste_crs, i) * blind
            })
            .collect::<Vec<_>>();

        let commitments = SchnorrCommitments {
            a_pprf_key,
            a_mask,
            a_sa1,
            a_sa2,
            a_ct,
            a_chunk_commitments,
        };
        let challenge = challenge_scalar(
            &context.validity_params_digest,
            ciphertext,
            chunk_commitments,
            &commitments,
        );

        let z_chunks = r_chunks
            .iter()
            .zip(witness.chunks.iter())
            .map(|(r, w)| *r + challenge * w)
            .collect();
        let mut z_ste_randomness = [E::ScalarField::zero(); 5];
        for i in 0..5 {
            z_ste_randomness[i] = r_ste_randomness[i] + challenge * witness.ste_randomness.s[i];
        }
        let z_commitment_randomness = r_commitment_randomness
            .iter()
            .zip(commitment_openings.randomness.iter())
            .map(|(r, w)| *r + challenge * w)
            .collect();

        Self {
            range_proof,
            challenge,
            z_chunks,
            z_ste_randomness,
            z_commitment_randomness,
        }
    }

    // Verifies a full CCA validity proof and recomputes the public-parameter
    // digests used by the Fiat-Shamir transcripts.
    pub fn verify(
        &self,
        ciphertext: &bte::encryption::Ciphertext<E>,
        bte_crs: &bte::crs::CRS<E>,
        ste_crs: &ste::crs::CRS<E>,
        ek: &EncryptionKey<E>,
        chunk_commitments: &PedersenCommitments<E>,
    ) -> bool {
        let context = CcaStatementContext::new(bte_crs, ste_crs, ek);
        self.verify_with_context(
            &context,
            ciphertext,
            bte_crs,
            ste_crs,
            ek,
            chunk_commitments,
        )
    }

    // Verifies both proof components with precomputed statement context:
    // the range proof for valid chunk limbs and the compact Schnorr proof
    // tying those limbs to this exact ciphertext statement.
    pub fn verify_with_context(
        &self,
        context: &CcaStatementContext,
        ciphertext: &bte::encryption::Ciphertext<E>,
        bte_crs: &bte::crs::CRS<E>,
        ste_crs: &ste::crs::CRS<E>,
        ek: &EncryptionKey<E>,
        chunk_commitments: &PedersenCommitments<E>,
    ) -> bool {
        if validate_statement_shape(ciphertext, bte_crs, ste_crs, ek, chunk_commitments).is_err() {
            return false;
        }
        if !self.range_proof.verify_with_context(
            &context.range_params_digest,
            chunk_commitments,
            ste_crs,
        ) {
            return false;
        }
        if self.z_chunks.len() != chunk_commitments.commitments.len()
            || self.z_commitment_randomness.len() != chunk_commitments.commitments.len()
        {
            return false;
        }

        let commitments = reconstruct_schnorr_commitments(
            self.challenge,
            &self.z_chunks,
            &self.z_ste_randomness,
            &self.z_commitment_randomness,
            ciphertext,
            bte_crs,
            ste_crs,
            ek,
            chunk_commitments,
        );
        let challenge = challenge_scalar(
            &context.validity_params_digest,
            ciphertext,
            chunk_commitments,
            &commitments,
        );
        challenge == self.challenge
    }
}

fn validate_statement_shape<E: Pairing>(
    ciphertext: &bte::encryption::Ciphertext<E>,
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    ek: &EncryptionKey<E>,
    chunk_commitments: &PedersenCommitments<E>,
) -> Result<(), ()> {
    if ciphertext.pprf.point >= bte_crs.batch_size {
        return Err(());
    }
    if ciphertext.encrypted_key.t >= ste_crs.powers_of_g[0].len() {
        return Err(());
    }
    if ciphertext.encrypted_key.ct.len() != chunk_commitments.commitments.len()
        || chunk_commitments.commitments.len() > ste_crs.l
        || ek.e_gh.len() < chunk_commitments.commitments.len()
        || ek.gamma_g2.is_empty()
        || ste_crs.n < 1
        || !range_crs_has_enough_degree(ste_crs)
    {
        return Err(());
    }
    Ok(())
}

fn validate_range_statement_shape<E: Pairing>(
    chunk_commitments: &PedersenCommitments<E>,
    ste_crs: &ste::crs::CRS<E>,
) -> Result<(), ()> {
    if chunk_commitments.commitments.len() > ste_crs.l || !range_crs_has_enough_degree(ste_crs) {
        return Err(());
    }
    Ok(())
}

fn range_crs_has_enough_degree<E: Pairing>(ste_crs: &ste::crs::CRS<E>) -> bool {
    let required_len = (2 * CHUNK_BITS as usize) + 3;
    ste_crs
        .powers_of_g
        .iter()
        .take(ste_crs.l)
        .all(|powers| powers.len() >= required_len)
        && ste_crs.powers_of_h[0].len() >= required_len
}

fn ste_linear_commitments<E: Pairing>(
    ste_crs: &ste::crs::CRS<E>,
    ek: &EncryptionKey<E>,
    t: usize,
    chunks: &[E::ScalarField],
    s: &[E::ScalarField; 5],
) -> ([E::G1; 2], [E::G2; 6], Vec<PairingOutput<E>>) {
    let sa1 = [
        (ek.ask * s[0]) + (ste_crs.powers_of_g[0][t] * s[3]) + (ste_crs.powers_of_g[0][0] * s[4]),
        ste_crs.powers_of_g[0][0] * s[2],
    ];
    let sa2 = [
        (ste_crs.powers_of_h[0][0] * s[0]) + (ek.gamma_g2[0] * s[2]),
        ek.z_g2 * s[0],
        ste_crs.powers_of_h[0][1] * s[0] + ste_crs.powers_of_h[0][2] * s[1],
        ste_crs.powers_of_h[0][0] * s[1],
        ste_crs.powers_of_h[0][0] * s[3],
        ste_crs.powers_of_h[0][1] * s[4],
    ];
    let gen_t = PairingOutput::<E>::generator();
    let ct = chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| ek.e_gh[i] * s[4] + gen_t * chunk)
        .collect::<Vec<_>>();

    (sa1, sa2, ct)
}

fn recompose_chunks<E: Pairing>(chunks: &[E::ScalarField]) -> E::ScalarField {
    let mut key = E::ScalarField::zero();
    let mut offset = E::ScalarField::from(1u64);
    let radix = E::ScalarField::from(1u128 << CHUNK_BITS);
    for chunk in chunks {
        key += offset * chunk;
        offset *= radix;
    }
    key
}

fn pedersen_value_base<E: Pairing>(ste_crs: &ste::crs::CRS<E>, chunk: usize) -> E::G1 {
    ste_crs.powers_of_g[chunk][0].into_group()
}

fn pedersen_blinding_base<E: Pairing>(ste_crs: &ste::crs::CRS<E>, chunk: usize) -> E::G1 {
    ste_crs.powers_of_g[chunk][1].into_group() - ste_crs.powers_of_g[chunk][0].into_group()
}

fn pedersen_polynomial<F: PrimeField>(value: F, blind: F) -> DensePolynomial<F> {
    DensePolynomial::from_coefficients_vec(vec![value - blind, blind])
}

fn range_omega<E: Pairing>() -> E::ScalarField {
    Radix2EvaluationDomain::<E::ScalarField>::new(CHUNK_BITS as usize)
        .expect("CHUNK_BITS must fit the scalar field two-adicity")
        .group_gen
}

fn is_in_range_domain<E: Pairing>(point: E::ScalarField) -> bool {
    point.pow(&[CHUNK_BITS as u64]) == E::ScalarField::one()
}

fn range_g_polynomial<E: Pairing>(
    chunk: E::ScalarField,
    rng: &mut impl Rng,
) -> DensePolynomial<E::ScalarField> {
    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(CHUNK_BITS as usize)
        .expect("CHUNK_BITS must fit the scalar field two-adicity");
    let mut value = chunk;
    let mut bits = vec![E::ScalarField::zero(); CHUNK_BITS as usize];
    for bit in bits.iter_mut() {
        let q = value.into_bigint() >> 1;
        *bit = value - E::ScalarField::from_bigint(q << 1).unwrap();
        value = E::ScalarField::from_bigint(q).unwrap();
    }
    assert!(value.is_zero(), "chunk is not in range");

    let mut g_values = vec![E::ScalarField::zero(); CHUNK_BITS as usize];
    g_values[(CHUNK_BITS - 1) as usize] = bits[(CHUNK_BITS - 1) as usize];
    for i in (0..(CHUNK_BITS as usize - 1)).rev() {
        g_values[i] = E::ScalarField::from(2u64) * g_values[i + 1] + bits[i];
    }

    let omega_prime = E::ScalarField::from(3u64);
    let omega_double_prime = E::ScalarField::from(5u64);
    assert!(!is_in_range_domain::<E>(omega_prime));
    assert!(!is_in_range_domain::<E>(omega_double_prime));

    let mut points = (0..CHUNK_BITS as usize)
        .map(|i| (domain.element(i), g_values[i]))
        .collect::<Vec<_>>();
    points.push((omega_prime, E::ScalarField::rand(rng)));
    points.push((omega_double_prime, E::ScalarField::rand(rng)));

    interpolate_polynomial(&points)
}

fn range_q_polynomial<E: Pairing>(
    f: &DensePolynomial<E::ScalarField>,
    g: &DensePolynomial<E::ScalarField>,
    tau: E::ScalarField,
) -> DensePolynomial<E::ScalarField> {
    let n = CHUNK_BITS as usize;
    let omega = range_omega::<E>();
    let omega_last = omega.pow(&[(CHUNK_BITS - 1) as u64]);
    let one = DensePolynomial::from_coefficients_vec(vec![E::ScalarField::one()]);
    let two = E::ScalarField::from(2u64);
    let g_shifted = shift_polynomial(g, omega);

    // w1 enforces g(1) = f(1), w2 enforces boolean bits on the range domain,
    // and w3 enforces the binary recurrence between adjacent domain points.
    // The quotient proves their random linear combination vanishes on X^n - 1.
    let g_minus_f = g - f;
    let w1 = &g_minus_f * &vanishing_except::<E>(E::ScalarField::one());
    let w2 = &(g * &(&one - g)) * &vanishing_except::<E>(omega_last);
    let transition = g - &scale_poly(&g_shifted, two);
    let transition_complement = &one - g + &scale_poly(&g_shifted, two);
    let w3 = &(&transition * &transition_complement)
        * &DensePolynomial::from_coefficients_vec(vec![-omega_last, E::ScalarField::one()]);

    let combined = &(&w1 + &scale_poly(&w2, tau)) + &scale_poly(&w3, tau.square());
    let vanishing = {
        let mut coeffs = vec![E::ScalarField::zero(); n + 1];
        coeffs[0] = -E::ScalarField::one();
        coeffs[n] = E::ScalarField::one();
        DensePolynomial::from_coefficients_vec(coeffs)
    };
    &combined / &vanishing
}

fn vanishing_except<E: Pairing>(excluded: E::ScalarField) -> DensePolynomial<E::ScalarField> {
    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(CHUNK_BITS as usize)
        .expect("CHUNK_BITS must fit the scalar field two-adicity");
    let divisor = DensePolynomial::from_coefficients_vec(vec![-excluded, E::ScalarField::one()]);
    &domain.vanishing_polynomial().into() / &divisor
}

fn shift_polynomial<F: PrimeField>(poly: &DensePolynomial<F>, shift: F) -> DensePolynomial<F> {
    let mut coeffs = poly.coeffs.clone();
    let mut power = F::one();
    for coeff in coeffs.iter_mut() {
        *coeff *= power;
        power *= shift;
    }
    DensePolynomial::from_coefficients_vec(coeffs)
}

fn scale_poly<F: PrimeField>(poly: &DensePolynomial<F>, scalar: F) -> DensePolynomial<F> {
    DensePolynomial::from_coefficients_vec(poly.coeffs.iter().map(|c| *c * scalar).collect())
}

fn interpolate_polynomial<F: PrimeField>(points: &[(F, F)]) -> DensePolynomial<F> {
    let mut result = DensePolynomial::zero();
    for (i, (x_i, y_i)) in points.iter().enumerate() {
        let mut basis = DensePolynomial::from_coefficients_vec(vec![F::one()]);
        let mut denominator = F::one();
        for (j, (x_j, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            basis = &basis * &DensePolynomial::from_coefficients_vec(vec![-*x_j, F::one()]);
            denominator *= *x_i - *x_j;
        }
        result = &result + &scale_poly(&basis, *y_i * denominator.inverse().unwrap());
    }
    result
}

fn range_tau_challenge<E: Pairing>(
    range_params_digest: &[u8; 32],
    chunk_commitments: &PedersenCommitments<E>,
    g_commitments: &[E::G1],
) -> E::ScalarField {
    let mut transcript = Transcript::new(b"BSTE-CCA-RANGE-PROOF-TAU-V1");
    transcript.append_bytes(b"range_params_digest", range_params_digest);
    transcript.append_serializable_slice(b"chunk_commitments", &chunk_commitments.commitments);
    transcript.append_serializable_slice(b"g_commitments", g_commitments);
    E::ScalarField::from_le_bytes_mod_order(&transcript.finalize())
}

fn range_rho_challenge<E: Pairing>(
    range_params_digest: &[u8; 32],
    chunk_commitments: &PedersenCommitments<E>,
    g_commitments: &[E::G1],
    tau: E::ScalarField,
    q_commitments: &[E::G1],
) -> E::ScalarField {
    let mut transcript = Transcript::new(b"BSTE-CCA-RANGE-PROOF-RHO-V1");
    transcript.append_bytes(b"range_params_digest", range_params_digest);
    transcript.append_serializable_slice(b"chunk_commitments", &chunk_commitments.commitments);
    transcript.append_serializable_slice(b"g_commitments", g_commitments);
    transcript.append_serializable(b"tau", &tau);
    transcript.append_serializable_slice(b"q_commitments", q_commitments);
    let mut rho = E::ScalarField::from_le_bytes_mod_order(&transcript.finalize());
    let mut counter = 0usize;
    while is_in_range_domain::<E>(rho) {
        let mut retry = Transcript::new(b"BSTE-CCA-RANGE-PROOF-RHO-RETRY-V1");
        retry.append_serializable(b"rho", &rho);
        retry.append_usize(b"counter", counter);
        rho = E::ScalarField::from_le_bytes_mod_order(&retry.finalize());
        counter += 1;
    }
    rho
}

fn reconstruct_schnorr_commitments<E: Pairing>(
    challenge: E::ScalarField,
    z_chunks: &[E::ScalarField],
    z_ste_randomness: &[E::ScalarField; 5],
    z_commitment_randomness: &[E::ScalarField],
    ciphertext: &bte::encryption::Ciphertext<E>,
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    ek: &EncryptionKey<E>,
    chunk_commitments: &PedersenCommitments<E>,
) -> SchnorrCommitments<E> {
    // Compact Schnorr proofs omit the first-round commitments. Verification
    // reconstructs each commitment as L(response) - challenge * public_value,
    // then hashes the reconstructed commitments back into the challenge.
    let z_key = recompose_chunks::<E>(z_chunks);
    let point = ciphertext.pprf.point;

    let a_pprf_key = bte_crs.powers_of_g[point] * z_key - ciphertext.pprf.key * challenge;
    let a_mask = bte_crs.gt_powers[point] * z_key - ciphertext.mask * challenge;

    let (lhs_sa1, lhs_sa2, lhs_ct) = ste_linear_commitments(
        ste_crs,
        ek,
        ciphertext.encrypted_key.t,
        z_chunks,
        z_ste_randomness,
    );
    let a_sa1 = [
        lhs_sa1[0] - ciphertext.encrypted_key.sa1[0] * challenge,
        lhs_sa1[1] - ciphertext.encrypted_key.sa1[1] * challenge,
    ];
    let a_sa2 = [
        lhs_sa2[0] - ciphertext.encrypted_key.sa2[0] * challenge,
        lhs_sa2[1] - ciphertext.encrypted_key.sa2[1] * challenge,
        lhs_sa2[2] - ciphertext.encrypted_key.sa2[2] * challenge,
        lhs_sa2[3] - ciphertext.encrypted_key.sa2[3] * challenge,
        lhs_sa2[4] - ciphertext.encrypted_key.sa2[4] * challenge,
        lhs_sa2[5] - ciphertext.encrypted_key.sa2[5] * challenge,
    ];
    let a_ct = lhs_ct
        .iter()
        .zip(ciphertext.encrypted_key.ct.iter())
        .map(|(lhs, ct)| *lhs - *ct * challenge)
        .collect::<Vec<_>>();
    let a_chunk_commitments = (0..chunk_commitments.commitments.len())
        .map(|i| {
            pedersen_value_base(ste_crs, i) * z_chunks[i]
                + pedersen_blinding_base(ste_crs, i) * z_commitment_randomness[i]
                - chunk_commitments.commitments[i] * challenge
        })
        .collect::<Vec<_>>();

    SchnorrCommitments {
        a_pprf_key,
        a_mask,
        a_sa1,
        a_sa2,
        a_ct,
        a_chunk_commitments,
    }
}

fn challenge_scalar<E: Pairing>(
    validity_params_digest: &[u8; 32],
    ciphertext: &bte::encryption::Ciphertext<E>,
    chunk_commitments: &PedersenCommitments<E>,
    commitments: &SchnorrCommitments<E>,
) -> E::ScalarField {
    let mut transcript = Transcript::new(b"BSTE-CCA-CIPHERTEXT-VALIDITY-V2-COMPACT");
    append_statement(
        &mut transcript,
        validity_params_digest,
        ciphertext,
        chunk_commitments,
    );
    transcript.append_serializable(b"a_pprf_key", &commitments.a_pprf_key);
    transcript.append_serializable(b"a_mask", &commitments.a_mask);
    transcript.append_serializable(b"a_sa1", &commitments.a_sa1);
    transcript.append_serializable(b"a_sa2", &commitments.a_sa2);
    transcript.append_serializable_slice(b"a_ct", &commitments.a_ct);
    transcript.append_serializable_slice(b"a_chunk_commitments", &commitments.a_chunk_commitments);
    E::ScalarField::from_le_bytes_mod_order(&transcript.finalize())
}

fn append_statement<E: Pairing>(
    transcript: &mut Transcript,
    validity_params_digest: &[u8; 32],
    ciphertext: &bte::encryption::Ciphertext<E>,
    chunk_commitments: &PedersenCommitments<E>,
) {
    transcript.append_bytes(b"validity_params_digest", validity_params_digest);
    transcript.append_usize(b"pprf_point", ciphertext.pprf.point);
    transcript.append_serializable(b"pprf_key", &ciphertext.pprf.key);
    transcript.append_serializable(b"encrypted_key", &ciphertext.encrypted_key);
    transcript.append_serializable(b"mask", &ciphertext.mask);
    transcript.append_serializable_slice(b"pedersen_commitments", &chunk_commitments.commitments);
}

fn validity_params_digest<E: Pairing>(
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    ek: &EncryptionKey<E>,
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"BSTE-CCA-VALIDITY-PARAMS-DIGEST-V1");
    transcript.append_usize(b"bte_batch_size", bte_crs.batch_size);
    transcript.append_usize(b"bte_fft_size", bte_crs.fft_size);
    transcript.append_serializable_slice(b"bte_powers_of_g", &bte_crs.powers_of_g);
    transcript.append_serializable_slice(b"bte_powers_of_h", &bte_crs.powers_of_h);
    transcript.append_serializable(b"bte_gt_nplus1", &bte_crs.gt_nplus1);
    transcript.append_serializable_slice(b"bte_fft_h", &bte_crs.fft_h);
    transcript.append_serializable_slice(b"bte_gt_powers", &bte_crs.gt_powers);
    transcript.append_serializable(b"ste_crs", ste_crs);
    transcript.append_serializable(b"ek", ek);
    transcript.finalize()
}

fn range_params_digest<E: Pairing>(ste_crs: &ste::crs::CRS<E>) -> [u8; 32] {
    let mut transcript = Transcript::new(b"BSTE-CCA-RANGE-PARAMS-DIGEST-V1");
    transcript.append_usize(b"chunk_bits", CHUNK_BITS as usize);
    transcript.append_serializable(b"ste_crs", ste_crs);
    transcript.finalize()
}

struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    fn new(domain: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        Self { hasher }
    }

    fn append_label(&mut self, label: &[u8]) {
        self.hasher.update((label.len() as u64).to_le_bytes());
        self.hasher.update(label);
    }

    fn append_usize(&mut self, label: &[u8], value: usize) {
        self.append_label(label);
        self.hasher.update((value as u64).to_le_bytes());
    }

    fn append_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        self.append_label(label);
        self.hasher.update((bytes.len() as u64).to_le_bytes());
        self.hasher.update(bytes);
    }

    fn append_serializable<T: CanonicalSerialize>(&mut self, label: &[u8], value: &T) {
        self.append_label(label);
        let mut bytes = Vec::new();
        value
            .serialize_compressed(&mut bytes)
            .expect("canonical serialization should succeed");
        self.hasher.update((bytes.len() as u64).to_le_bytes());
        self.hasher.update(bytes);
    }

    fn append_serializable_slice<T: CanonicalSerialize>(&mut self, label: &[u8], values: &[T]) {
        self.append_label(label);
        self.hasher.update((values.len() as u64).to_le_bytes());
        for value in values {
            let mut bytes = Vec::new();
            value
                .serialize_compressed(&mut bytes)
                .expect("canonical serialization should succeed");
            self.hasher.update((bytes.len() as u64).to_le_bytes());
            self.hasher.update(bytes);
        }
    }

    fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    type E = Bls12_381;

    fn setup() -> (
        bte::crs::CRS<E>,
        ste::crs::CRS<E>,
        EncryptionKey<E>,
        impl Rng,
    ) {
        let mut rng = test_rng();
        let n = (2 * CHUNK_BITS as usize + 3).next_power_of_two();
        let l = bte::encryption::NUM_CHUNKS;
        let batch_size = 8;
        let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
        let ste_crs = ste::crs::CRS::new(n, l, &mut rng);
        let sk = (0..n)
            .map(|i| ste::setup::SecretKey::<E>::new(&mut rng, i))
            .collect::<Vec<_>>();
        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
            .collect::<Vec<_>>();
        let (_ak, ek) = ste::aggregate::AggregateKey::<E>::new(pk, &ste_crs);
        (bte_crs, ste_crs, ek, rng)
    }

    #[test]
    fn valid_ciphertext_proof_verifies() {
        let (bte_crs, ste_crs, ek, mut rng) = setup();
        let t = 4;
        let (ciphertext, witness) =
            bte::encryption::encrypt_with_witness(3, &bte_crs, &ste_crs, &ek, t, &mut rng);
        let (commitments, openings) =
            PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);

        let proof = ValidityProof::prove(
            &ciphertext,
            &bte_crs,
            &ste_crs,
            &ek,
            &commitments,
            &witness,
            &openings,
            &mut rng,
        );

        assert!(proof.verify(&ciphertext, &bte_crs, &ste_crs, &ek, &commitments));
    }

    #[test]
    fn tampered_statement_does_not_verify() {
        let (bte_crs, ste_crs, ek, mut rng) = setup();
        let t = 4;
        let (mut ciphertext, witness) =
            bte::encryption::encrypt_with_witness(3, &bte_crs, &ste_crs, &ek, t, &mut rng);
        let (commitments, openings) =
            PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);
        let proof = ValidityProof::prove(
            &ciphertext,
            &bte_crs,
            &ste_crs,
            &ek,
            &commitments,
            &witness,
            &openings,
            &mut rng,
        );

        ciphertext.mask += PairingOutput::<E>::generator();

        assert!(!proof.verify(&ciphertext, &bte_crs, &ste_crs, &ek, &commitments));
    }

    #[test]
    fn tampered_commitment_does_not_verify() {
        let (bte_crs, ste_crs, ek, mut rng) = setup();
        let t = 4;
        let (ciphertext, witness) =
            bte::encryption::encrypt_with_witness(3, &bte_crs, &ste_crs, &ek, t, &mut rng);
        let (mut commitments, openings) =
            PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);
        let proof = ValidityProof::prove(
            &ciphertext,
            &bte_crs,
            &ste_crs,
            &ek,
            &commitments,
            &witness,
            &openings,
            &mut rng,
        );

        commitments.commitments[0] += ste_crs.gen_g[0];

        assert!(!proof.verify(&ciphertext, &bte_crs, &ste_crs, &ek, &commitments));
    }

    #[test]
    fn tampered_challenge_does_not_verify() {
        let (bte_crs, ste_crs, ek, mut rng) = setup();
        let t = 4;
        let (ciphertext, witness) =
            bte::encryption::encrypt_with_witness(3, &bte_crs, &ste_crs, &ek, t, &mut rng);
        let (commitments, openings) =
            PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);
        let mut proof = ValidityProof::prove(
            &ciphertext,
            &bte_crs,
            &ste_crs,
            &ek,
            &commitments,
            &witness,
            &openings,
            &mut rng,
        );

        proof.challenge += <E as Pairing>::ScalarField::from(1u64);

        assert!(!proof.verify(&ciphertext, &bte_crs, &ste_crs, &ek, &commitments));
    }

    #[test]
    fn tampered_range_proof_does_not_verify() {
        let (bte_crs, ste_crs, ek, mut rng) = setup();
        let t = 4;
        let (ciphertext, witness) =
            bte::encryption::encrypt_with_witness(3, &bte_crs, &ste_crs, &ek, t, &mut rng);
        let (commitments, openings) =
            PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);
        let mut proof = ValidityProof::prove(
            &ciphertext,
            &bte_crs,
            &ste_crs,
            &ek,
            &commitments,
            &witness,
            &openings,
            &mut rng,
        );

        proof.range_proof.openings[0].g_at_rho += <E as Pairing>::ScalarField::from(1u64);

        assert!(!proof.verify(&ciphertext, &bte_crs, &ste_crs, &ek, &commitments));
    }
}
