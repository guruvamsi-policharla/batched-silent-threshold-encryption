use crate::{
    bte::{self, batch_eval},
    dlog::Markers,
    ste,
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_std::{end_timer, start_timer, One, Zero};

/// Given B ciphertexts and the aggregate key k_agg, decrypt them
pub fn decrypt<E: Pairing>(
    ct: &Vec<bte::encryption::Ciphertext<E>>,
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    t: usize,
    partial_decryptions: &Vec<ste::setup::PartialDecryption<E>>, //insert 0 if a party did not respond or verification failed
    selector: &[bool],
    agg_key: &ste::aggregate::AggregateKey<E>,
    markers: Markers<PairingOutput<E>>,
) {
    let pprfs = ct.iter().map(|c| c.pprf.clone()).collect::<Vec<_>>();

    let timer = start_timer!(|| "STE Decryption");
    // add up STE ciphertexts and compute k_agg
    let k_agg_ct = ct.iter().fold(
        ste::encryption::Ciphertext::<E>::zero(ste_crs.l, t),
        |acc, c| acc.add(&c.encrypted_key),
    );

    let k_agg_t =
        ste::decryption::agg_dec(partial_decryptions, &k_agg_ct, selector, agg_key, ste_crs);
    end_timer!(timer);

    let timer = start_timer!(|| "Computing DLog");
    let k_agg_chunks = k_agg_t
        .iter()
        .map(|y| markers.compute_dlog(y).expect("Failed to compute DLog"))
        .collect::<Vec<_>>();

    let mut k_agg = E::ScalarField::zero();
    let mut offset = E::ScalarField::one();
    for chunk in &k_agg_chunks {
        k_agg += offset * chunk;
        offset *= E::ScalarField::from(1u128 << 32);
    }
    end_timer!(timer);

    let k_agg = bte::PRF::from_key(k_agg);

    let mut recovered_masks = vec![PairingOutput::<E>::zero(); ct.len()];

    let timer = start_timer!(|| "Batch Decrypting");
    for i in 0..ct.len() {
        let mask1 = batch_eval(&pprfs, i, &bte_crs);
        let mask2 = k_agg.eval(i, &bte_crs);

        recovered_masks[i] = mask2 - mask1;
        assert_eq!(
            recovered_masks[i], ct[i].mask,
            "Decryption failed at index {}",
            i
        );
    }
    end_timer!(timer);
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::bte::encryption::encrypt;
    use crate::dlog;
    use ark_bls12_381::Bls12_381;
    use ark_std::{end_timer, start_timer, test_rng};

    type E = Bls12_381;

    #[test]
    fn test_decrypt() {
        let mut rng = test_rng();
        let n = 1 << 3;
        let l = 8;
        let batch_size = 8;
        let t: usize = n / 2;

        let timer = start_timer!(|| "Sampling CRS");
        let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
        let ste_crs = ste::crs::CRS::new(n, l, &mut rng);
        end_timer!(timer);

        let timer = start_timer!(|| "Sampling Keys");
        let sk = (0..n)
            .map(|i| ste::setup::SecretKey::<E>::new(&mut rng, i))
            .collect::<Vec<_>>();

        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
            .collect::<Vec<_>>();
        end_timer!(timer);

        let timer = start_timer!(|| "Aggregating Keys");
        let (_ak, ek) = ste::aggregate::AggregateKey::<E>::new(pk, &ste_crs);
        end_timer!(timer);

        let timer = start_timer!(|| "Encrypting Messages");
        let cts = (0..batch_size)
            .map(|i| encrypt(i, &bte_crs, &ste_crs, &ek, t, &mut rng))
            .collect::<Vec<_>>();
        end_timer!(timer);

        // aggregate the ciphertexts
        let timer = start_timer!(|| "Aggregating Ciphertexts");
        let agg_ct = cts.iter().fold(
            ste::encryption::Ciphertext::<E>::zero(batch_size, t),
            |acc, c| acc.add(&c.encrypted_key),
        );
        end_timer!(timer);

        // compute partial decryptions
        let timer = start_timer!(|| "Computing Partial Decryptions");
        let mut partial_decryptions: Vec<ste::setup::PartialDecryption<E>> = Vec::new();
        for i in 0..t {
            partial_decryptions.push(sk[i].partial_decryption(&agg_ct));
        }
        for _ in t..n {
            partial_decryptions.push(ste::setup::PartialDecryption::<E>::zero());
        }

        // compute the selector
        let mut selector: Vec<bool> = Vec::new();
        for _ in 0..t {
            selector.push(true);
        }
        for _ in t..n {
            selector.push(false);
        }
        end_timer!(timer);

        // read the markers
        let timer = start_timer!(|| "Reading Markers");
        let markers = dlog::Markers::<PairingOutput<E>>::read_from_file("markers_20.bin");
        end_timer!(timer);

        // decrypt the ciphertexts
        decrypt(
            &cts,
            &bte_crs,
            &ste_crs,
            t,
            &partial_decryptions,
            &selector,
            &_ak,
            markers,
        );
    }
}
