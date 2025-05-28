use crate::bte::encryption::Ciphertext;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_std::Zero;

use super::{batch_eval, crs::CRS, PRF};

/// Given B ciphertexts and the aggregate key k_agg, decrypt them
pub fn decrypt<E: Pairing>(ct: &Vec<Ciphertext<E>>, k_agg: &PRF<E>, crs: &CRS<E>) {
    let pprfs = ct.iter().map(|c| c.pprf.clone()).collect::<Vec<_>>();

    let mut recovered_masks = vec![PairingOutput::<E>::zero(); ct.len()];

    for i in 0..ct.len() {
        let mask1 = batch_eval(&pprfs, i, &crs);
        let mask2 = k_agg.eval(i, &crs);

        recovered_masks[i] = mask2 - mask1;
        assert_eq!(
            recovered_masks[i], ct[i].mask,
            "Decryption failed at index {}",
            i
        );
    }
}

#[cfg(test)]
pub mod tests {
    use crate::bte::encryption::encrypt;

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    type E = Bls12_381;
    type F = <E as Pairing>::ScalarField;

    #[test]
    fn test_decrypt() {
        let mut rng = test_rng();
        let batch_size = 10;
        let crs = CRS::<E>::new(batch_size, &mut rng);

        let cts = (0..batch_size)
            .map(|i| encrypt(i, &crs, &mut rng))
            .collect::<Vec<_>>();

        let mut k_agg = F::zero();

        // todo: do STE decryption first here
        for ct in cts.iter() {
            k_agg += ct.encrypted_key;
        }

        decrypt(&cts, &PRF::from_key(k_agg), &crs);
    }
}
