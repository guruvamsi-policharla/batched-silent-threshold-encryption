use crate::{
    bte,
    nizk::transcript::{append_serializable, append_usize, challenge_scalar},
    ste::{crs::CRS, setup::LagPublicKey},
};
use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, UniformRand};
use merlin::Transcript;

#[derive(Clone, Debug, PartialEq)]
pub struct PartialDecryptionProof<E: Pairing> {
    pub challenge: E::ScalarField,
    pub response: E::ScalarField,
}

pub fn prove<E: Pairing>(
    crs: &CRS<E>,
    pk: &LagPublicKey<E>,
    ciphertexts: &[bte::encryption::Ciphertext<E>],
    pd: E::G1,
    sk: E::ScalarField,
    rng: &mut impl Rng,
) -> PartialDecryptionProof<E> {
    let bases = ciphertexts
        .iter()
        .map(|ct| ct.encrypted_key.sa1[1])
        .collect::<Vec<_>>();
    prove_for_bases(crs, pk, &bases, pd, sk, rng)
}

pub fn prove_for_bases<E: Pairing>(
    crs: &CRS<E>,
    pk: &LagPublicKey<E>,
    bases: &[E::G1],
    pd: E::G1,
    sk: E::ScalarField,
    rng: &mut impl Rng,
) -> PartialDecryptionProof<E> {
    let sum_sa1 = bases.iter().copied().sum::<E::G1>();
    let nonce = E::ScalarField::rand(rng);
    let a_pk = crs.gen_g[0] * nonce;
    let a_pd = sum_sa1 * nonce;

    let mut transcript = pd_transcript(crs, pk, bases, pd, sum_sa1);
    append_serializable(&mut transcript, b"a_pk", &a_pk);
    append_serializable(&mut transcript, b"a_pd", &a_pd);
    let challenge = challenge_scalar::<E::ScalarField>(&mut transcript, b"pd-challenge");
    let response = nonce + challenge * sk;

    PartialDecryptionProof {
        challenge,
        response,
    }
}

pub fn verify<E: Pairing>(
    crs: &CRS<E>,
    pk: &LagPublicKey<E>,
    ciphertexts: &[bte::encryption::Ciphertext<E>],
    pd: E::G1,
    proof: &PartialDecryptionProof<E>,
) -> bool {
    let bases = ciphertexts
        .iter()
        .map(|ct| ct.encrypted_key.sa1[1])
        .collect::<Vec<_>>();
    verify_for_bases(crs, pk, &bases, pd, proof)
}

pub fn verify_for_bases<E: Pairing>(
    crs: &CRS<E>,
    pk: &LagPublicKey<E>,
    bases: &[E::G1],
    pd: E::G1,
    proof: &PartialDecryptionProof<E>,
) -> bool {
    let Some(pk0) = pk.bls_pk.first() else {
        return false;
    };
    let sum_sa1 = bases.iter().copied().sum::<E::G1>();
    let a_pk = crs.gen_g[0] * proof.response - *pk0 * proof.challenge;
    let a_pd = sum_sa1 * proof.response - pd * proof.challenge;

    let mut transcript = pd_transcript(crs, pk, bases, pd, sum_sa1);
    append_serializable(&mut transcript, b"a_pk", &a_pk);
    append_serializable(&mut transcript, b"a_pd", &a_pd);
    let expected = challenge_scalar::<E::ScalarField>(&mut transcript, b"pd-challenge");
    expected == proof.challenge
}

pub fn batch_decryption_base<E: Pairing>(ciphertexts: &[bte::encryption::Ciphertext<E>]) -> E::G1 {
    ciphertexts
        .iter()
        .map(|ct| ct.encrypted_key.sa1[1])
        .sum::<E::G1>()
}

fn pd_transcript<E: Pairing>(
    crs: &CRS<E>,
    pk: &LagPublicKey<E>,
    bases: &[E::G1],
    pd: E::G1,
    sum_sa1: E::G1,
) -> Transcript {
    let mut transcript = Transcript::new(b"sbte-partial-decryption-proof");
    append_usize(&mut transcript, b"party_id", pk.id);
    append_serializable(&mut transcript, b"gen_g0", &crs.gen_g[0]);
    if let Some(pk0) = pk.bls_pk.first() {
        append_serializable(&mut transcript, b"pk0", pk0);
    }
    append_usize(&mut transcript, b"batch_len", bases.len());
    for base in bases {
        append_serializable(&mut transcript, b"ct_sa1_1", base);
    }
    append_serializable(&mut transcript, b"sum_sa1", &sum_sa1);
    append_serializable(&mut transcript, b"pd", &pd);
    transcript
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bte,
        ste::{self, aggregate::AggregateKey},
    };
    use ark_bls12_381::Bls12_381;
    use ark_ec::{pairing::Pairing, PrimeGroup};
    use ark_std::test_rng;

    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    #[test]
    fn partial_decryption_proof_accepts_valid_share() {
        let mut rng = test_rng();
        let n = 8;
        let l = bte::encryption::NUM_CHUNKS;
        let batch_size = 4;
        let t = n / 2;
        let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
        let ste_crs = ste::crs::CRS::<E>::new(n, l, &mut rng);

        let sk0_scalar = Fr::from(123u64);
        let sk = (0..n)
            .map(|i| {
                if i == 0 {
                    ste::setup::SecretKey::<E>::from_scalar(sk0_scalar, i)
                } else {
                    ste::setup::SecretKey::<E>::new(&mut rng, i)
                }
            })
            .collect::<Vec<_>>();
        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
            .collect::<Vec<_>>();
        let (_ak, ek) = AggregateKey::<E>::new(pk.clone(), &ste_crs);
        let ciphertexts = (0..batch_size)
            .map(|i| bte::encryption::encrypt(i, &bte_crs, &ste_crs, &ek, t, &mut rng))
            .collect::<Vec<_>>();
        let pd = sk[0].batch_partial_decryption(&ciphertexts).pd;

        let proof = prove(&ste_crs, &pk[0], &ciphertexts, pd, sk0_scalar, &mut rng);
        assert!(verify(&ste_crs, &pk[0], &ciphertexts, pd, &proof));
    }

    #[test]
    fn partial_decryption_proof_rejects_tampered_share() {
        let mut rng = test_rng();
        let n = 8;
        let l = bte::encryption::NUM_CHUNKS;
        let batch_size = 4;
        let t = n / 2;
        let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
        let ste_crs = ste::crs::CRS::<E>::new(n, l, &mut rng);

        let sk0_scalar = Fr::from(123u64);
        let sk = (0..n)
            .map(|i| {
                if i == 0 {
                    ste::setup::SecretKey::<E>::from_scalar(sk0_scalar, i)
                } else {
                    ste::setup::SecretKey::<E>::new(&mut rng, i)
                }
            })
            .collect::<Vec<_>>();
        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
            .collect::<Vec<_>>();
        let (_ak, ek) = AggregateKey::<E>::new(pk.clone(), &ste_crs);
        let ciphertexts = (0..batch_size)
            .map(|i| bte::encryption::encrypt(i, &bte_crs, &ste_crs, &ek, t, &mut rng))
            .collect::<Vec<_>>();
        let pd = sk[0].batch_partial_decryption(&ciphertexts).pd;
        let proof = prove(&ste_crs, &pk[0], &ciphertexts, pd, sk0_scalar, &mut rng);
        let bad_pd = pd + <E as Pairing>::G1::generator();

        assert!(!verify(&ste_crs, &pk[0], &ciphertexts, bad_pd, &proof));
    }
}
