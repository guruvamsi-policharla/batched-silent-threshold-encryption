use crate::{
    bte::{self, PPRF, PRF},
    nizk::{
        cca::{self, CcaProof, CcaStatement, CcaWitness},
        kzg,
        range::{self, RangeProof, RangeWitness},
    },
    ste::{self, aggregate::EncryptionKey},
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_std::{rand::Rng, UniformRand, Zero};

/// Bits per STE / GT chunk when decomposing the PRF scalar (must match `ste_crs.l`).
/// Each chunk limb is in `[0, 2^CHUNK_BITS − 1]`. After homomorphically summing `B` ciphertexts,
/// a slot sum is at most `B · (2^CHUNK_BITS − 1)`; see [`crate::dlog::max_homomorphic_batch_size`].
pub const CHUNK_BITS: u32 = 16;
/// Number of chunks; `CHUNK_BITS * NUM_CHUNKS` must cover the scalar field (~255 bits for BLS12-381).
pub const NUM_CHUNKS: usize = 16;

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    pub pprf: PPRF<E>,
    // encrypt key under the threshold scheme
    pub encrypted_key: crate::ste::encryption::Ciphertext<E>,
    pub mask: PairingOutput<E>, // todo: message masked with bytes
}

#[derive(Clone, Debug)]
pub struct CcaCiphertext<E: Pairing> {
    pub position: usize,
    pub pprf: PPRF<E>,
    pub encrypted_key: crate::ste::encryption::Ciphertext<E>,
    pub beta: PairingOutput<E>,
    pub commitments: Vec<E::G1>,
    pub proof: CcaCiphertextProof<E>,
}

#[derive(Clone, Debug)]
pub struct CcaCiphertextProof<E: Pairing> {
    pub range: RangeProof<E>,
    pub cca: CcaProof<E>,
}

/// Sample a key, puncture it at position, and mask message at that evaluation point.
pub fn encrypt<E: Pairing>(
    position: usize,
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    ek: &EncryptionKey<E>,
    t: usize,
    rng: &mut impl Rng,
) -> Ciphertext<E> {
    let prf = PRF::<E>::new(rng);
    let pprf = prf.puncture(position, &bte_crs);

    // Split prf.key into `NUM_CHUNKS` chunks of `CHUNK_BITS` bits (little-endian).
    let (chunks, _) = decompose_scalar_key::<E>(prf.key);

    let gen_t = PairingOutput::<E>::generator();
    let chunks_t = chunks.iter().map(|c| gen_t * c).collect::<Vec<_>>();

    // encrypt the key using the STE encryption scheme
    let encrypted_key = ste::encryption::encrypt(&ek, t, &ste_crs, &chunks_t, rng);

    Ciphertext {
        pprf,
        encrypted_key,
        mask: prf.eval(position, &bte_crs),
    }
}

pub fn encrypt_cca<E: Pairing>(
    position: usize,
    message: PairingOutput<E>,
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    kzg_crs: &kzg::Crs<E>,
    ek: &EncryptionKey<E>,
    t: usize,
    rng: &mut impl Rng,
) -> CcaCiphertext<E> {
    let prf = PRF::<E>::new(rng);
    let pprf = prf.puncture(position, bte_crs);
    let (chunks, chunk_values) = decompose_scalar_key::<E>(prf.key);
    let gen_t = PairingOutput::<E>::generator();
    let chunks_t = chunks.iter().map(|c| gen_t * c).collect::<Vec<_>>();
    let encryption_witness = ste::encryption::EncryptionWitness::<E>::sample(rng);
    let encrypted_key =
        ste::encryption::encrypt_with_witness(ek, t, ste_crs, &chunks_t, &encryption_witness);

    let blindings = (0..NUM_CHUNKS)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let commitments = chunk_values
        .iter()
        .zip(&blindings)
        .map(|(&chunk, &blinding)| {
            kzg_crs.commit_value_with_blinding(E::ScalarField::from(chunk), blinding)
        })
        .collect::<Vec<_>>();
    let range_witnesses = chunk_values
        .iter()
        .zip(&blindings)
        .map(|(&value, &blinding)| RangeWitness { value, blinding })
        .collect::<Vec<_>>();
    let range_proof = range::prove(
        kzg_crs,
        &commitments,
        &range_witnesses,
        CHUNK_BITS as usize,
        rng,
    );

    let beta = message + prf.eval(position, bte_crs);
    let cca_witness = CcaWitness {
        chunks: chunk_values,
        blindings,
        encryption_witness,
    };
    let statement = CcaStatement {
        bte_crs,
        ste_crs,
        kzg_crs,
        ek,
        position,
        pprf: &pprf,
        beta: &beta,
        encrypted_key: &encrypted_key,
        commitments: &commitments,
        range_proof: &range_proof,
    };
    let cca_proof = cca::prove(&statement, &cca_witness, rng);

    CcaCiphertext {
        position,
        pprf,
        encrypted_key,
        beta,
        commitments,
        proof: CcaCiphertextProof {
            range: range_proof,
            cca: cca_proof,
        },
    }
}

pub fn verify_cca<E: Pairing>(
    ct: &CcaCiphertext<E>,
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    kzg_crs: &kzg::Crs<E>,
    ek: &EncryptionKey<E>,
) -> bool {
    if !range::verify(kzg_crs, &ct.commitments, &ct.proof.range) {
        return false;
    }
    let statement = CcaStatement {
        bte_crs,
        ste_crs,
        kzg_crs,
        ek,
        position: ct.position,
        pprf: &ct.pprf,
        beta: &ct.beta,
        encrypted_key: &ct.encrypted_key,
        commitments: &ct.commitments,
        range_proof: &ct.proof.range,
    };
    cca::verify(&statement, &ct.proof.cca)
}

pub fn verify_cca_batch<E: Pairing>(
    cts: &[CcaCiphertext<E>],
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    kzg_crs: &kzg::Crs<E>,
    ek: &EncryptionKey<E>,
) -> bool {
    let range_statements = cts
        .iter()
        .map(|ct| (ct.commitments.as_slice(), &ct.proof.range))
        .collect::<Vec<_>>();
    if !range::verify_batch(kzg_crs, &range_statements) {
        return false;
    }

    let statements = cts
        .iter()
        .map(|ct| CcaStatement {
            bte_crs,
            ste_crs,
            kzg_crs,
            ek,
            position: ct.position,
            pprf: &ct.pprf,
            beta: &ct.beta,
            encrypted_key: &ct.encrypted_key,
            commitments: &ct.commitments,
            range_proof: &ct.proof.range,
        })
        .collect::<Vec<_>>();
    let proofs = cts
        .iter()
        .map(|ct| ct.proof.cca.clone())
        .collect::<Vec<_>>();
    cca::verify_batch(&statements, &proofs)
}

pub fn decompose_scalar_key<E: Pairing>(
    mut key: E::ScalarField,
) -> (Vec<E::ScalarField>, Vec<u128>) {
    let mut chunks = vec![E::ScalarField::zero(); NUM_CHUNKS];
    let mut chunk_values = vec![0u128; NUM_CHUNKS];

    for i in 0..NUM_CHUNKS {
        let q = key.into_bigint() >> CHUNK_BITS;
        chunks[i] = key - E::ScalarField::from_bigint(q << CHUNK_BITS).unwrap();
        chunk_values[i] = chunks[i].into_bigint().as_ref()[0] as u128;
        key = E::ScalarField::from_bigint(q).unwrap();
    }

    (chunks, chunk_values)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    type E = Bls12_381;

    #[test]
    fn test_encrypt() {
        let mut rng = test_rng();
        let n = 1 << 3;
        let l = NUM_CHUNKS;
        let batch_size = 8;
        let t: usize = n / 2;

        let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
        let ste_crs = ste::crs::CRS::new(n, l, &mut rng);
        let position = 5;

        let sk = (0..n)
            .map(|i| ste::setup::SecretKey::<E>::new(&mut rng, i))
            .collect::<Vec<_>>();

        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
            .collect::<Vec<_>>();

        let (_ak, ek) = ste::aggregate::AggregateKey::<E>::new(pk, &ste_crs);

        let ciphertext = encrypt(position, &bte_crs, &ste_crs, &ek, t, &mut rng);
        assert_eq!(ciphertext.pprf.point, position);
    }

    #[test]
    fn test_encrypt_cca_verifies() {
        let mut rng = test_rng();
        let n = 1 << 3;
        let l = NUM_CHUNKS;
        let batch_size = 8;
        let t: usize = n / 2;

        let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
        let ste_crs = ste::crs::CRS::new(n, l, &mut rng);
        let kzg_crs = crate::nizk::kzg::Crs::<E>::new(
            crate::nizk::range::required_kzg_degree(CHUNK_BITS as usize),
            &mut rng,
        );
        let position = 5;

        let sk = (0..n)
            .map(|i| ste::setup::SecretKey::<E>::new(&mut rng, i))
            .collect::<Vec<_>>();
        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
            .collect::<Vec<_>>();
        let (_ak, ek) = ste::aggregate::AggregateKey::<E>::new(pk, &ste_crs);
        let message = PairingOutput::<E>::generator();

        let ciphertext = encrypt_cca(
            position, message, &bte_crs, &ste_crs, &kzg_crs, &ek, t, &mut rng,
        );
        assert!(verify_cca(&ciphertext, &bte_crs, &ste_crs, &kzg_crs, &ek));
    }

    #[test]
    fn test_encrypt_cca_rejects_tampered_beta() {
        let mut rng = test_rng();
        let n = 1 << 3;
        let l = NUM_CHUNKS;
        let batch_size = 8;
        let t: usize = n / 2;

        let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
        let ste_crs = ste::crs::CRS::new(n, l, &mut rng);
        let kzg_crs = crate::nizk::kzg::Crs::<E>::new(
            crate::nizk::range::required_kzg_degree(CHUNK_BITS as usize),
            &mut rng,
        );
        let position = 5;

        let sk = (0..n)
            .map(|i| ste::setup::SecretKey::<E>::new(&mut rng, i))
            .collect::<Vec<_>>();
        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
            .collect::<Vec<_>>();
        let (_ak, ek) = ste::aggregate::AggregateKey::<E>::new(pk, &ste_crs);
        let message = PairingOutput::<E>::generator();

        let mut ciphertext = encrypt_cca(
            position, message, &bte_crs, &ste_crs, &kzg_crs, &ek, t, &mut rng,
        );
        ciphertext.beta += PairingOutput::<E>::generator();
        assert!(!verify_cca(&ciphertext, &bte_crs, &ste_crs, &kzg_crs, &ek));
    }

    #[test]
    fn test_verify_cca_batch_rejects_tampered_ciphertext() {
        let mut rng = test_rng();
        let n = 1 << 3;
        let l = NUM_CHUNKS;
        let batch_size = 4;
        let t: usize = n / 2;

        let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
        let ste_crs = ste::crs::CRS::new(n, l, &mut rng);
        let kzg_crs = crate::nizk::kzg::Crs::<E>::new(
            crate::nizk::range::required_kzg_degree(CHUNK_BITS as usize),
            &mut rng,
        );

        let sk = (0..n)
            .map(|i| ste::setup::SecretKey::<E>::new(&mut rng, i))
            .collect::<Vec<_>>();
        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
            .collect::<Vec<_>>();
        let (_ak, ek) = ste::aggregate::AggregateKey::<E>::new(pk, &ste_crs);
        let message = PairingOutput::<E>::generator();

        let mut ciphertexts = (0..batch_size)
            .map(|position| {
                encrypt_cca(
                    position, message, &bte_crs, &ste_crs, &kzg_crs, &ek, t, &mut rng,
                )
            })
            .collect::<Vec<_>>();
        assert!(verify_cca_batch(
            &ciphertexts,
            &bte_crs,
            &ste_crs,
            &kzg_crs,
            &ek
        ));

        ciphertexts[2].proof.cca.chunk_responses[0] += <E as Pairing>::ScalarField::from(1u64);
        assert!(!verify_cca_batch(
            &ciphertexts,
            &bte_crs,
            &ste_crs,
            &kzg_crs,
            &ek
        ));
    }
}
