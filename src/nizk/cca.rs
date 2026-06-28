use crate::{
    bte::{self, PPRF},
    nizk::{
        kzg,
        range::RangeProof,
        transcript::{append_serializable, append_usize, challenge_scalar},
    },
    ste::{self, aggregate::EncryptionKey, encryption::EncryptionWitness},
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM,
};
use ark_ff::PrimeField;
use ark_std::{rand::Rng, One, UniformRand, Zero};
use merlin::Transcript;

#[derive(Clone, Debug, PartialEq)]
pub struct CcaProof<E: Pairing> {
    pub first_round: CcaFirstRound<E>,
    pub chunk_responses: Vec<E::ScalarField>,
    pub blinding_responses: Vec<E::ScalarField>,
    pub randomness_responses: [E::ScalarField; 5],
}

#[derive(Clone, Debug, PartialEq)]
pub struct CcaFirstRound<E: Pairing> {
    pub pprf: E::G1,
    pub commitments: Vec<E::G1>,
    pub sa1: [E::G1; 2],
    pub sa2: [E::G2; 6],
    pub ct: Vec<PairingOutput<E>>,
}

#[derive(Clone, Debug)]
pub struct CcaWitness<E: Pairing> {
    pub chunks: Vec<u128>,
    pub blindings: Vec<E::ScalarField>,
    pub encryption_witness: EncryptionWitness<E>,
}

pub fn prove<E: Pairing>(
    statement: &CcaStatement<'_, E>,
    witness: &CcaWitness<E>,
    rng: &mut impl Rng,
) -> CcaProof<E> {
    assert_well_formed(statement, witness.chunks.len());
    assert_eq!(witness.chunks.len(), witness.blindings.len());
    assert_eq!(witness.chunks.len(), statement.commitments.len());

    let chunk_nonces = (0..witness.chunks.len())
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let blinding_nonces = (0..witness.blindings.len())
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let randomness_nonces: [E::ScalarField; 5] = std::array::from_fn(|_| E::ScalarField::rand(rng));

    let first_round = first_round_commitments(
        statement,
        &chunk_nonces,
        &blinding_nonces,
        &randomness_nonces,
    );
    let challenge = challenge_for_first_round(statement, &first_round);

    let chunk_responses = chunk_nonces
        .iter()
        .zip(&witness.chunks)
        .map(|(&nonce, &chunk)| nonce + challenge * E::ScalarField::from(chunk))
        .collect::<Vec<_>>();
    let blinding_responses = blinding_nonces
        .iter()
        .zip(&witness.blindings)
        .map(|(&nonce, &blinding)| nonce + challenge * blinding)
        .collect::<Vec<_>>();
    let randomness_responses =
        std::array::from_fn(|i| randomness_nonces[i] + challenge * witness.encryption_witness.s[i]);

    CcaProof {
        first_round,
        chunk_responses,
        blinding_responses,
        randomness_responses,
    }
}

pub fn verify<E: Pairing>(statement: &CcaStatement<'_, E>, proof: &CcaProof<E>) -> bool {
    if !proof_shape_matches(statement, proof) {
        return false;
    }

    let challenge = challenge_for_first_round(statement, &proof.first_round);
    verify_linear_relations(statement, proof, challenge)
}

pub fn verify_batch<E: Pairing>(
    statements: &[CcaStatement<'_, E>],
    proofs: &[CcaProof<E>],
) -> bool {
    if statements.len() != proofs.len() {
        return false;
    }
    if statements.is_empty() {
        return true;
    }

    let mut batch_transcript = Transcript::new(b"sbte-cca-proof-batch");
    append_usize(&mut batch_transcript, b"proof_count", proofs.len());
    let mut challenges = Vec::with_capacity(proofs.len());
    for (statement, proof) in statements.iter().zip(proofs) {
        if !proof_shape_matches(statement, proof) {
            return false;
        }
        append_cca_statement(&mut batch_transcript, statement);
        append_proof(&mut batch_transcript, proof);
        challenges.push(challenge_for_first_round(statement, &proof.first_round));
    }

    let mut g1_bases = Vec::new();
    let mut g1_scalars = Vec::new();
    let mut g2_bases = Vec::new();
    let mut g2_scalars = Vec::new();
    let mut gt_bases = Vec::new();
    let mut gt_scalars = Vec::new();
    for ((statement, proof), &challenge) in statements.iter().zip(proofs).zip(&challenges) {
        accumulate_batch_equations(
            statement,
            proof,
            challenge,
            &mut batch_transcript,
            &mut g1_bases,
            &mut g1_scalars,
            &mut g2_bases,
            &mut g2_scalars,
            &mut gt_bases,
            &mut gt_scalars,
        );
    }

    g1_msm::<E>(&g1_bases, &g1_scalars).is_zero()
        && g2_msm::<E>(&g2_bases, &g2_scalars).is_zero()
        && gt_msm::<E>(&gt_bases, &gt_scalars).is_zero()
}

fn challenge_for_first_round<E: Pairing>(
    statement: &CcaStatement<'_, E>,
    first_round: &CcaFirstRound<E>,
) -> E::ScalarField {
    let mut transcript = cca_transcript(statement);
    append_first_round(&mut transcript, first_round);
    challenge_scalar::<E::ScalarField>(&mut transcript, b"cca-challenge")
}

fn proof_shape_matches<E: Pairing>(statement: &CcaStatement<'_, E>, proof: &CcaProof<E>) -> bool {
    statement.pprf.point == statement.position
        && statement.position < statement.bte_crs.batch_size
        && proof.chunk_responses.len() == statement.commitments.len()
        && proof.blinding_responses.len() == statement.commitments.len()
        && proof.first_round.commitments.len() == statement.commitments.len()
        && proof.first_round.ct.len() == statement.commitments.len()
        && statement.encrypted_key.ct.len() == statement.commitments.len()
        && statement.range_proof.chunks.len() == statement.commitments.len()
        && statement.ek.e_gh.len() >= statement.commitments.len()
        && !statement.ek.gamma_g2.is_empty()
        && !statement.ste_crs.powers_of_g.is_empty()
        && !statement.ste_crs.powers_of_h.is_empty()
}

fn verify_linear_relations<E: Pairing>(
    statement: &CcaStatement<'_, E>,
    proof: &CcaProof<E>,
    challenge: E::ScalarField,
) -> bool {
    let lhs = first_round_commitments(
        statement,
        &proof.chunk_responses,
        &proof.blinding_responses,
        &proof.randomness_responses,
    );

    if lhs.pprf != proof.first_round.pprf + statement.pprf.key * challenge {
        return false;
    }
    for ((&lhs_commitment, &first_round), &commitment) in lhs
        .commitments
        .iter()
        .zip(&proof.first_round.commitments)
        .zip(statement.commitments)
    {
        if lhs_commitment != first_round + commitment * challenge {
            return false;
        }
    }
    for i in 0..2 {
        if lhs.sa1[i] != proof.first_round.sa1[i] + statement.encrypted_key.sa1[i] * challenge {
            return false;
        }
    }
    for i in 0..6 {
        if lhs.sa2[i] != proof.first_round.sa2[i] + statement.encrypted_key.sa2[i] * challenge {
            return false;
        }
    }
    for ((&lhs_ct, &first_round), &ct) in lhs
        .ct
        .iter()
        .zip(&proof.first_round.ct)
        .zip(&statement.encrypted_key.ct)
    {
        if lhs_ct != first_round + ct * challenge {
            return false;
        }
    }

    true
}

pub struct CcaStatement<'a, E: Pairing> {
    pub bte_crs: &'a bte::crs::CRS<E>,
    pub ste_crs: &'a ste::crs::CRS<E>,
    pub kzg_crs: &'a kzg::Crs<E>,
    pub ek: &'a EncryptionKey<E>,
    pub position: usize,
    pub pprf: &'a PPRF<E>,
    pub beta: &'a PairingOutput<E>,
    pub encrypted_key: &'a ste::encryption::Ciphertext<E>,
    pub commitments: &'a [E::G1],
    pub range_proof: &'a RangeProof<E>,
}

fn assert_well_formed<E: Pairing>(statement: &CcaStatement<'_, E>, chunks_len: usize) {
    assert_eq!(statement.pprf.point, statement.position);
    assert_eq!(statement.commitments.len(), chunks_len);
    assert_eq!(statement.encrypted_key.ct.len(), chunks_len);
    assert_eq!(statement.range_proof.chunks.len(), chunks_len);
    assert!(statement.position < statement.bte_crs.batch_size);
}

fn first_round_commitments<E: Pairing>(
    statement: &CcaStatement<'_, E>,
    chunk_nonces: &[E::ScalarField],
    blinding_nonces: &[E::ScalarField],
    randomness_nonces: &[E::ScalarField; 5],
) -> CcaFirstRound<E> {
    let pprf_bases = pprf_bases(statement, chunk_nonces.len());
    let pprf = g1_msm::<E>(&pprf_bases, chunk_nonces);

    let h =
        statement.kzg_crs.g1_powers[1].into_group() - statement.kzg_crs.g1_powers[0].into_group();
    let commitments = chunk_nonces
        .iter()
        .zip(blinding_nonces)
        .map(|(&k_nonce, &rho_nonce)| {
            statement.kzg_crs.g1_powers[0].into_group() * k_nonce + h * rho_nonce
        })
        .collect::<Vec<_>>();

    let sa1 = [
        g1_msm::<E>(
            &[
                statement.ek.ask,
                statement.ste_crs.powers_of_g[0][statement.encrypted_key.t].into_group(),
                statement.ste_crs.powers_of_g[0][0].into_group(),
            ],
            &[
                randomness_nonces[0],
                randomness_nonces[3],
                randomness_nonces[4],
            ],
        ),
        statement.ste_crs.powers_of_g[0][0].into_group() * randomness_nonces[2],
    ];

    let sa2 = [
        g2_msm::<E>(
            &[
                statement.ste_crs.powers_of_h[0][0].into_group(),
                statement.ek.gamma_g2[0],
            ],
            &[randomness_nonces[0], randomness_nonces[2]],
        ),
        statement.ek.z_g2 * randomness_nonces[0],
        g2_msm::<E>(
            &[
                statement.ste_crs.powers_of_h[0][1].into_group(),
                statement.ste_crs.powers_of_h[0][2].into_group(),
            ],
            &[randomness_nonces[0], randomness_nonces[1]],
        ),
        statement.ste_crs.powers_of_h[0][0].into_group() * randomness_nonces[1],
        statement.ste_crs.powers_of_h[0][0].into_group() * randomness_nonces[3],
        statement.ste_crs.powers_of_h[0][1].into_group() * randomness_nonces[4],
    ];

    let gen_t = PairingOutput::<E>::generator();
    let ct = statement
        .ek
        .e_gh
        .iter()
        .zip(chunk_nonces)
        .map(|(&e_gh, &k_nonce)| e_gh * randomness_nonces[4] + gen_t * k_nonce)
        .collect::<Vec<_>>();

    CcaFirstRound {
        pprf,
        commitments,
        sa1,
        sa2,
        ct,
    }
}

fn pprf_bases<E: Pairing>(statement: &CcaStatement<'_, E>, len: usize) -> Vec<E::G1> {
    let base = statement.bte_crs.powers_of_g[statement.position];
    let radix = E::ScalarField::from(1u128 << bte::encryption::CHUNK_BITS);
    let mut offset = E::ScalarField::one();
    let mut bases = Vec::with_capacity(len);
    for _ in 0..len {
        bases.push(base * offset);
        offset *= radix;
    }
    bases
}

fn cca_transcript<E: Pairing>(statement: &CcaStatement<'_, E>) -> Transcript {
    let mut transcript = Transcript::new(b"sbte-cca-proof");
    append_cca_statement(&mut transcript, statement);
    transcript
}

fn append_cca_statement<E: Pairing>(transcript: &mut Transcript, statement: &CcaStatement<'_, E>) {
    append_usize(transcript, b"position", statement.position);
    append_usize(transcript, b"threshold", statement.encrypted_key.t);
    append_usize(transcript, b"bte_batch_size", statement.bte_crs.batch_size);
    append_usize(transcript, b"ste_n", statement.ste_crs.n);
    append_usize(transcript, b"ste_l", statement.ste_crs.l);
    append_usize(transcript, b"kzg_max_degree", statement.kzg_crs.max_degree);
    append_serializable(transcript, b"pprf_key", &statement.pprf.key);
    append_serializable(transcript, b"beta", statement.beta);
    append_serializable(transcript, b"ek_ask", &statement.ek.ask);
    append_serializable(transcript, b"ek_z_g2", &statement.ek.z_g2);
    for e_gh in &statement.ek.e_gh {
        append_serializable(transcript, b"ek_e_gh", e_gh);
    }
    for gamma in &statement.ek.gamma_g2 {
        append_serializable(transcript, b"ek_gamma_g2", gamma);
    }
    append_serializable(transcript, b"sa1_0", &statement.encrypted_key.sa1[0]);
    append_serializable(transcript, b"sa1_1", &statement.encrypted_key.sa1[1]);
    for sa2 in &statement.encrypted_key.sa2 {
        append_serializable(transcript, b"sa2", sa2);
    }
    for ct in &statement.encrypted_key.ct {
        append_serializable(transcript, b"ste_ct", ct);
    }
    for commitment in statement.commitments {
        append_serializable(transcript, b"chunk_commitment", commitment);
    }
    append_range_proof(transcript, statement.range_proof);
}

fn append_range_proof<E: Pairing>(transcript: &mut Transcript, proof: &RangeProof<E>) {
    append_usize(transcript, b"range_bit_width", proof.bit_width);
    append_usize(transcript, b"range_chunks", proof.chunks.len());
    for chunk in &proof.chunks {
        append_serializable(transcript, b"range_com_g", &chunk.com_g);
        append_serializable(transcript, b"range_com_q", &chunk.com_q);
        append_serializable(transcript, b"range_g_rho", &chunk.g_at_rho);
        append_serializable(transcript, b"range_g_rho_omega", &chunk.g_at_rho_omega);
        append_serializable(transcript, b"range_hat_w_rho", &chunk.hat_w_at_rho);
        append_serializable(
            transcript,
            b"range_pi_g_rho_and_rho_omega",
            &chunk.proof_g_at_rho_and_rho_omega,
        );
        append_serializable(transcript, b"range_pi_hat_w_rho", &chunk.proof_hat_w_at_rho);
    }
}

fn append_first_round<E: Pairing>(transcript: &mut Transcript, first_round: &CcaFirstRound<E>) {
    append_serializable(transcript, b"a_pprf", &first_round.pprf);
    for commitment in &first_round.commitments {
        append_serializable(transcript, b"a_chunk_commitment", commitment);
    }
    append_serializable(transcript, b"a_sa1_0", &first_round.sa1[0]);
    append_serializable(transcript, b"a_sa1_1", &first_round.sa1[1]);
    for sa2 in &first_round.sa2 {
        append_serializable(transcript, b"a_sa2", sa2);
    }
    for ct in &first_round.ct {
        append_serializable(transcript, b"a_ct", ct);
    }
}

fn append_proof<E: Pairing>(transcript: &mut Transcript, proof: &CcaProof<E>) {
    append_first_round(transcript, &proof.first_round);
    append_usize(transcript, b"chunk_responses", proof.chunk_responses.len());
    for response in &proof.chunk_responses {
        append_serializable(transcript, b"chunk_response", response);
    }
    append_usize(
        transcript,
        b"blinding_responses",
        proof.blinding_responses.len(),
    );
    for response in &proof.blinding_responses {
        append_serializable(transcript, b"blinding_response", response);
    }
    for response in &proof.randomness_responses {
        append_serializable(transcript, b"randomness_response", response);
    }
}

fn accumulate_batch_equations<E: Pairing>(
    statement: &CcaStatement<'_, E>,
    proof: &CcaProof<E>,
    challenge: E::ScalarField,
    batch_transcript: &mut Transcript,
    g1_bases: &mut Vec<E::G1>,
    g1_scalars: &mut Vec<E::ScalarField>,
    g2_bases: &mut Vec<E::G2>,
    g2_scalars: &mut Vec<E::ScalarField>,
    gt_bases: &mut Vec<PairingOutput<E>>,
    gt_scalars: &mut Vec<E::ScalarField>,
) {
    let mut weight = || challenge_scalar::<E::ScalarField>(batch_transcript, b"cca-batch-weight");
    let g0 = statement.kzg_crs.g1_powers[0].into_group();
    let h = statement.kzg_crs.g1_powers[1].into_group() - g0;
    let ste_g0 = statement.ste_crs.powers_of_g[0][0].into_group();
    let ste_gt = statement.ste_crs.powers_of_g[0][statement.encrypted_key.t].into_group();
    let ste_h0 = statement.ste_crs.powers_of_h[0][0].into_group();
    let ste_h1 = statement.ste_crs.powers_of_h[0][1].into_group();
    let ste_h2 = statement.ste_crs.powers_of_h[0][2].into_group();
    let z = &proof.chunk_responses;
    let z_blind = &proof.blinding_responses;
    let s = &proof.randomness_responses;

    let w = weight();
    let mut z_key = E::ScalarField::zero();
    let radix = E::ScalarField::from(1u128 << bte::encryption::CHUNK_BITS);
    let mut offset = E::ScalarField::one();
    for &response in z {
        z_key += response * offset;
        offset *= radix;
    }
    push_g1::<E>(
        g1_bases,
        g1_scalars,
        statement.bte_crs.powers_of_g[statement.position],
        w * z_key,
    );
    push_g1::<E>(g1_bases, g1_scalars, statement.pprf.key, -(w * challenge));
    push_g1::<E>(g1_bases, g1_scalars, proof.first_round.pprf, -w);

    for j in 0..statement.commitments.len() {
        let w = weight();
        push_g1::<E>(g1_bases, g1_scalars, g0, w * z[j]);
        push_g1::<E>(g1_bases, g1_scalars, h, w * z_blind[j]);
        push_g1::<E>(
            g1_bases,
            g1_scalars,
            statement.commitments[j],
            -(w * challenge),
        );
        push_g1::<E>(g1_bases, g1_scalars, proof.first_round.commitments[j], -w);
    }

    let w = weight();
    push_g1::<E>(g1_bases, g1_scalars, statement.ek.ask, w * s[0]);
    push_g1::<E>(g1_bases, g1_scalars, ste_gt, w * s[3]);
    push_g1::<E>(g1_bases, g1_scalars, ste_g0, w * s[4]);
    push_g1::<E>(
        g1_bases,
        g1_scalars,
        statement.encrypted_key.sa1[0],
        -(w * challenge),
    );
    push_g1::<E>(g1_bases, g1_scalars, proof.first_round.sa1[0], -w);

    let w = weight();
    push_g1::<E>(g1_bases, g1_scalars, ste_g0, w * s[2]);
    push_g1::<E>(
        g1_bases,
        g1_scalars,
        statement.encrypted_key.sa1[1],
        -(w * challenge),
    );
    push_g1::<E>(g1_bases, g1_scalars, proof.first_round.sa1[1], -w);

    let w = weight();
    push_g2::<E>(g2_bases, g2_scalars, ste_h0, w * s[0]);
    push_g2::<E>(g2_bases, g2_scalars, statement.ek.gamma_g2[0], w * s[2]);
    push_g2::<E>(
        g2_bases,
        g2_scalars,
        statement.encrypted_key.sa2[0],
        -(w * challenge),
    );
    push_g2::<E>(g2_bases, g2_scalars, proof.first_round.sa2[0], -w);

    let w = weight();
    push_g2::<E>(g2_bases, g2_scalars, statement.ek.z_g2, w * s[0]);
    push_g2::<E>(
        g2_bases,
        g2_scalars,
        statement.encrypted_key.sa2[1],
        -(w * challenge),
    );
    push_g2::<E>(g2_bases, g2_scalars, proof.first_round.sa2[1], -w);

    let w = weight();
    push_g2::<E>(g2_bases, g2_scalars, ste_h1, w * s[0]);
    push_g2::<E>(g2_bases, g2_scalars, ste_h2, w * s[1]);
    push_g2::<E>(
        g2_bases,
        g2_scalars,
        statement.encrypted_key.sa2[2],
        -(w * challenge),
    );
    push_g2::<E>(g2_bases, g2_scalars, proof.first_round.sa2[2], -w);

    for (idx, response) in [(3, s[1]), (4, s[3]), (5, s[4])] {
        let w = weight();
        let base = if idx == 5 { ste_h1 } else { ste_h0 };
        push_g2::<E>(g2_bases, g2_scalars, base, w * response);
        push_g2::<E>(
            g2_bases,
            g2_scalars,
            statement.encrypted_key.sa2[idx],
            -(w * challenge),
        );
        push_g2::<E>(g2_bases, g2_scalars, proof.first_round.sa2[idx], -w);
    }

    let gen_t = PairingOutput::<E>::generator();
    for j in 0..statement.commitments.len() {
        let w = weight();
        push_gt::<E>(gt_bases, gt_scalars, statement.ek.e_gh[j], w * s[4]);
        push_gt::<E>(gt_bases, gt_scalars, gen_t, w * z[j]);
        push_gt::<E>(
            gt_bases,
            gt_scalars,
            statement.encrypted_key.ct[j],
            -(w * challenge),
        );
        push_gt::<E>(gt_bases, gt_scalars, proof.first_round.ct[j], -w);
    }
}

fn push_g1<E: Pairing>(
    bases: &mut Vec<E::G1>,
    scalars: &mut Vec<E::ScalarField>,
    base: E::G1,
    scalar: E::ScalarField,
) {
    bases.push(base);
    scalars.push(scalar);
}

fn push_g2<E: Pairing>(
    bases: &mut Vec<E::G2>,
    scalars: &mut Vec<E::ScalarField>,
    base: E::G2,
    scalar: E::ScalarField,
) {
    bases.push(base);
    scalars.push(scalar);
}

fn push_gt<E: Pairing>(
    bases: &mut Vec<PairingOutput<E>>,
    scalars: &mut Vec<E::ScalarField>,
    base: PairingOutput<E>,
    scalar: E::ScalarField,
) {
    bases.push(base);
    scalars.push(scalar);
}

fn g1_msm<E: Pairing>(bases: &[E::G1], scalars: &[E::ScalarField]) -> E::G1 {
    debug_assert_eq!(bases.len(), scalars.len());
    if bases.is_empty() {
        return E::G1::zero();
    }
    let bases = E::G1::normalize_batch(bases);
    let scalars = scalars.iter().map(|s| s.into_bigint()).collect::<Vec<_>>();
    E::G1::msm_bigint(&bases, &scalars)
}

fn g2_msm<E: Pairing>(bases: &[E::G2], scalars: &[E::ScalarField]) -> E::G2 {
    debug_assert_eq!(bases.len(), scalars.len());
    if bases.is_empty() {
        return E::G2::zero();
    }
    let bases = E::G2::normalize_batch(bases);
    let scalars = scalars.iter().map(|s| s.into_bigint()).collect::<Vec<_>>();
    E::G2::msm_bigint(&bases, &scalars)
}

fn gt_msm<E: Pairing>(
    bases: &[PairingOutput<E>],
    scalars: &[E::ScalarField],
) -> PairingOutput<E> {
    debug_assert_eq!(bases.len(), scalars.len());
    if bases.is_empty() {
        return PairingOutput::<E>::zero();
    }
    let scalars = scalars.iter().map(|s| s.into_bigint()).collect::<Vec<_>>();
    PairingOutput::<E>::msm_bigint(bases, &scalars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bte::{self, PRF},
        nizk::range::{self, RangeWitness},
        ste::{self, aggregate::AggregateKey},
    };
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::test_rng;

    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    #[test]
    fn cca_proof_accepts_valid_ciphertext() {
        let (owned, witness) = sample_statement();
        let statement = owned.statement();
        let mut rng = test_rng();
        let proof = prove(&statement, &witness, &mut rng);
        assert!(verify(&statement, &proof));
    }

    #[test]
    fn cca_proof_rejects_tampered_pprf() {
        let (mut owned, witness) = sample_statement();
        let mut rng = test_rng();
        let proof = {
            let statement = owned.statement();
            prove(&statement, &witness, &mut rng)
        };
        owned.pprf.key += owned.bte_crs.powers_of_g[0];
        let tampered_statement = owned.statement();
        assert!(!verify(&tampered_statement, &proof));
    }

    struct OwnedStatement {
        position: usize,
        bte_crs: bte::crs::CRS<E>,
        ste_crs: ste::crs::CRS<E>,
        kzg_crs: kzg::Crs<E>,
        ek: EncryptionKey<E>,
        pprf: PPRF<E>,
        beta: PairingOutput<E>,
        encrypted_key: ste::encryption::Ciphertext<E>,
        commitments: Vec<<E as Pairing>::G1>,
        range_proof: RangeProof<E>,
    }

    impl OwnedStatement {
        fn statement(&self) -> CcaStatement<'_, E> {
            CcaStatement {
                bte_crs: &self.bte_crs,
                ste_crs: &self.ste_crs,
                kzg_crs: &self.kzg_crs,
                ek: &self.ek,
                position: self.position,
                pprf: &self.pprf,
                beta: &self.beta,
                encrypted_key: &self.encrypted_key,
                commitments: &self.commitments,
                range_proof: &self.range_proof,
            }
        }
    }

    fn sample_statement() -> (OwnedStatement, CcaWitness<E>) {
        let mut rng = test_rng();
        let n = 8;
        let l = bte::encryption::NUM_CHUNKS;
        let batch_size = 8;
        let t = n / 2;
        let position = 3;
        let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
        let ste_crs = ste::crs::CRS::<E>::new(n, l, &mut rng);
        let kzg_crs = kzg::Crs::<E>::new(range::required_kzg_degree(16), &mut rng);
        let sk = (0..n)
            .map(|i| ste::setup::SecretKey::<E>::new(&mut rng, i))
            .collect::<Vec<_>>();
        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
            .collect::<Vec<_>>();
        let (_ak, ek) = AggregateKey::<E>::new(pk, &ste_crs);

        let prf = PRF::<E>::new(&mut rng);
        let pprf = prf.puncture(position, &bte_crs);
        let beta = PairingOutput::<E>::generator() + prf.eval(position, &bte_crs);
        let chunks = decompose_key(prf.key);
        let chunk_scalars = chunks.iter().map(|&c| Fr::from(c)).collect::<Vec<_>>();
        let gen_t = PairingOutput::<E>::generator();
        let chunk_messages = chunk_scalars.iter().map(|&c| gen_t * c).collect::<Vec<_>>();
        let encryption_witness = EncryptionWitness::<E>::sample(&mut rng);
        let encrypted_key = ste::encryption::encrypt_with_witness(
            &ek,
            t,
            &ste_crs,
            &chunk_messages,
            &encryption_witness,
        );
        let blindings = (0..l).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let commitments = chunks
            .iter()
            .zip(&blindings)
            .map(|(&chunk, &blinding)| {
                kzg_crs.commit_value_with_blinding(Fr::from(chunk), blinding)
            })
            .collect::<Vec<_>>();
        let range_witnesses = chunks
            .iter()
            .zip(&blindings)
            .map(|(&value, &blinding)| RangeWitness { value, blinding })
            .collect::<Vec<_>>();
        let range_proof = range::prove(&kzg_crs, &commitments, &range_witnesses, 16, &mut rng);

        let witness = CcaWitness {
            chunks,
            blindings,
            encryption_witness,
        };
        let owned = OwnedStatement {
            position,
            bte_crs,
            ste_crs,
            kzg_crs,
            ek,
            pprf,
            beta,
            encrypted_key,
            commitments,
            range_proof,
        };

        (owned, witness)
    }

    fn decompose_key(key: Fr) -> Vec<u128> {
        let mut key = key;
        let mut chunks = vec![0u128; bte::encryption::NUM_CHUNKS];
        for chunk in &mut chunks {
            let q = key.into_bigint() >> bte::encryption::CHUNK_BITS;
            let low = key - Fr::from_bigint(q << bte::encryption::CHUNK_BITS).unwrap();
            let limbs = low.into_bigint().0;
            *chunk = limbs[0] as u128;
            key = Fr::from_bigint(q).unwrap();
        }
        chunks
    }
}
