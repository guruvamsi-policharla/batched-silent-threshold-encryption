use crate::{bte, ste};
use crate::{
    bte::{PPRF, PRF},
    ste::aggregate::EncryptionKey,
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_std::{rand::Rng, Zero};

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    pub pprf: PPRF<E>,
    // encrypt key under the threshold scheme
    pub encrypted_key: crate::ste::encryption::Ciphertext<E>,
    // pub encrypted_key: E::ScalarField, // todo: this should be replaced with the STE ciphertext
    pub mask: PairingOutput<E>, // todo: message masked with bytes
}

/// Sample a key, puncture it at position, and mask message at that evalaution point.
pub fn encrypt<E: Pairing>(
    position: usize,
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    ek: &EncryptionKey<E>,
    t: usize,
    rng: &mut impl Rng,
) -> Ciphertext<E> {
    // sample a PRF key

    let prf = PRF::<E>::new(rng); //todo: replace
                                  // let prf = PRF::<E>::from_key(E::ScalarField::from(1u32));

    // puncture the PRF at the given position
    let pprf = prf.puncture(position, &bte_crs);

    // split prf.key into 8 chunks of 32 bits each
    let mut key = prf.key.clone();
    let mut chunks = vec![E::ScalarField::zero(); 8];

    for i in 0..8 {
        let q = key.into_bigint() >> 32;
        chunks[i] = key - E::ScalarField::from_bigint(q << 32).unwrap();

        key = E::ScalarField::from_bigint(q).unwrap();
    }

    /*
    #[cfg(debug_assertions)]
    {
        // assert that the all chunks are at most 32 bits
        for chunk in &chunks {
            assert!(chunk.into_bigint() <= E::ScalarField::from(1u128 << 32).into_bigint());
        }
        // assert that the sum of all chunks is equal to the original key
        let mut sum = E::ScalarField::zero();
        let mut offset = E::ScalarField::one();
        for chunk in &chunks {
            sum += offset * chunk;
            offset *= E::ScalarField::from(1u128 << 32);
        }

        assert_eq!(sum, prf.key);
    }

    let chunks_t = ek
        .e_gh
        .iter()
        .zip(chunks.iter())
        .map(|(&e, c)| e * c)
        .collect::<Vec<_>>();
    */

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
        let l = 8;
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
