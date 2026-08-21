use crate::{
    bte::{self, PPRF, PRF},
    ste::{self, aggregate::EncryptionKey},
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_std::{rand::Rng, Zero};

#[cfg(all(feature = "chunks-8", feature = "chunks-16"))]
compile_error!("features `chunks-8` and `chunks-16` are mutually exclusive");

#[cfg(not(any(feature = "chunks-8", feature = "chunks-16")))]
compile_error!("enable exactly one chunk parameter feature: `chunks-8` or `chunks-16`");

/// Bits per STE / GT chunk when decomposing the PRF scalar (must match `ste_crs.l`).
/// Each chunk limb is in `[0, 2^CHUNK_BITS − 1]`. After homomorphically summing `B` ciphertexts,
/// a slot sum is at most `B · (2^CHUNK_BITS − 1)`; see [`crate::dlog::max_homomorphic_batch_size`].
#[cfg(feature = "chunks-16")]
pub const CHUNK_BITS: u32 = 16;
#[cfg(feature = "chunks-8")]
pub const CHUNK_BITS: u32 = 32;
/// Number of chunks; `CHUNK_BITS * NUM_CHUNKS` must cover the scalar field (~255 bits for BLS12-381).
#[cfg(feature = "chunks-16")]
pub const NUM_CHUNKS: usize = 16;
#[cfg(feature = "chunks-8")]
pub const NUM_CHUNKS: usize = 8;

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    pub pprf: PPRF<E>,
    // encrypt key under the threshold scheme
    pub encrypted_key: crate::ste::encryption::Ciphertext<E>,
    pub mask: PairingOutput<E>, // todo: message masked with bytes
}

#[derive(Clone, Debug)]
pub struct EncryptionWitness<E: Pairing> {
    pub chunks: Vec<E::ScalarField>,
    pub ste_randomness: ste::encryption::EncryptionRandomness<E>,
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
    encrypt_with_witness(position, bte_crs, ste_crs, ek, t, rng).0
}

/// Same as [`encrypt`], but also returns the witness needed by the CCA validity proof.
pub fn encrypt_with_witness<E: Pairing>(
    position: usize,
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    ek: &EncryptionKey<E>,
    t: usize,
    rng: &mut impl Rng,
) -> (Ciphertext<E>, EncryptionWitness<E>) {
    let prf = PRF::<E>::new(rng);
    let pprf = prf.puncture(position, &bte_crs);

    // Split prf.key into `NUM_CHUNKS` chunks of `CHUNK_BITS` bits (little-endian).
    let mut key = prf.key;
    let mut chunks = vec![E::ScalarField::zero(); NUM_CHUNKS];

    for i in 0..NUM_CHUNKS {
        let q = key.into_bigint() >> CHUNK_BITS;
        chunks[i] = key - E::ScalarField::from_bigint(q << CHUNK_BITS).unwrap();
        key = E::ScalarField::from_bigint(q).unwrap();
    }

    let gen_t = PairingOutput::<E>::generator();
    let chunks_t = chunks.iter().map(|c| gen_t * c).collect::<Vec<_>>();

    // encrypt the key using the STE encryption scheme
    let (encrypted_key, ste_randomness) =
        ste::encryption::encrypt_with_witness(&ek, t, &ste_crs, &chunks_t, rng);

    let ciphertext = Ciphertext {
        pprf,
        encrypted_key,
        mask: prf.eval(position, &bte_crs),
    };
    (
        ciphertext,
        EncryptionWitness {
            chunks,
            ste_randomness,
        },
    )
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
}
