use crate::{
    bte::{self, batch_eval, encryption},
    dlog::{self, Markers},
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
    dlog::assert_homomorphic_batch_safe(ct.len(), encryption::CHUNK_BITS, dlog::DLOG_RANGE_BITS);

    let timer = start_timer!(|| "STE Decryption");
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
        .map(|y| {
            markers
                .compute_dlog(y)
                .expect("DLog lookup failed — exponent out of BSGS range")
        })
        .collect::<Vec<_>>();

    let mut k_agg = E::ScalarField::zero();
    let mut offset = E::ScalarField::one();
    let chunk_radix = E::ScalarField::from(1u128 << encryption::CHUNK_BITS);
    for chunk in &k_agg_chunks {
        k_agg += offset * chunk;
        offset *= chunk_radix;
    }
    end_timer!(timer);

    let k_agg = bte::PRF::from_key(k_agg);
    let pprfs: Vec<_> = ct.iter().map(|c| c.pprf.clone()).collect();

    let mut recovered_masks = vec![PairingOutput::<E>::zero(); ct.len()];

    let timer = start_timer!(|| "PPRF Evals");
    for i in 0..ct.len() {
        let mask1 = batch_eval(&pprfs, i, bte_crs);
        let mask2 = k_agg.eval(i, bte_crs);

        recovered_masks[i] = mask2 - mask1;
        assert_eq!(
            recovered_masks[i], ct[i].mask,
            "Decryption failed at index {}",
            i
        );
    }
    end_timer!(timer);
}

/// FFT-based decryption: same as `decrypt` but replaces the O(B²) PPRF eval loop
/// with a single O(B log B) `fft_batch_eval` call.
pub fn decrypt_fft<E: Pairing>(
    ct: &Vec<bte::encryption::Ciphertext<E>>,
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    t: usize,
    partial_decryptions: &Vec<ste::setup::PartialDecryption<E>>,
    selector: &[bool],
    agg_key: &ste::aggregate::AggregateKey<E>,
    markers: Markers<PairingOutput<E>>,
) {
    dlog::assert_homomorphic_batch_safe(ct.len(), encryption::CHUNK_BITS, dlog::DLOG_RANGE_BITS);

    let timer = start_timer!(|| "STE Decryption");
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
        .map(|y| {
            markers
                .compute_dlog(y)
                .expect("DLog lookup failed — exponent out of BSGS range")
        })
        .collect::<Vec<_>>();
    let mut k_agg_scalar = E::ScalarField::zero();
    let mut offset = E::ScalarField::one();
    let chunk_radix = E::ScalarField::from(1u128 << encryption::CHUNK_BITS);
    for chunk in &k_agg_chunks {
        k_agg_scalar += offset * chunk;
        offset *= chunk_radix;
    }
    end_timer!(timer);

    let k_agg = bte::PRF::from_key(k_agg_scalar);
    let pprfs: Vec<_> = ct.iter().map(|c| c.pprf.clone()).collect();

    let timer = start_timer!(|| "FFT PPRF Evals");
    let recovered_masks = bte::fft_batch_eval(&k_agg, &pprfs, bte_crs);
    end_timer!(timer);

    for i in 0..ct.len() {
        assert_eq!(
            recovered_masks[i], ct[i].mask,
            "FFT Decryption failed at index {}",
            i
        );
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::bte::encryption::encrypt;
    use ark_bls12_381::Bls12_381;
    use ark_std::{end_timer, start_timer, test_rng};

    type E = Bls12_381;

    #[test]
    fn test_decrypt() {
        let mut rng = test_rng();
        let n = 1 << 3;
        let l = encryption::NUM_CHUNKS;
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
        let (ak, ek) = ste::aggregate::AggregateKey::<E>::new(pk, &ste_crs);
        end_timer!(timer);

        let timer = start_timer!(|| "Encrypting Messages");
        let cts = (0..batch_size)
            .map(|i| encrypt(i, &bte_crs, &ste_crs, &ek, t, &mut rng))
            .collect::<Vec<_>>();
        end_timer!(timer);

        // compute partial decryptions
        let timer = start_timer!(|| "Computing Partial Decryptions");
        let mut partial_decryptions: Vec<ste::setup::PartialDecryption<E>> = Vec::new();
        for i in 0..t {
            partial_decryptions.push(sk[i].batch_partial_decryption(&cts));
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

        let path = format!(
            "markers_bsgs_decrypt_test_{}_{}.bin",
            dlog::DLOG_RANGE_BITS,
            dlog::DLOG_MARKER_BITS
        );
        let timer = start_timer!(|| "loading markers");
        let markers = if std::path::Path::new(&path).exists() {
            Markers::<PairingOutput<E>>::read_from_file(&path)
        } else {
            let m = Markers::<PairingOutput<E>>::new();
            m.save_to_file(&path);
            m
        };
        end_timer!(timer);

        // decrypt the ciphertexts
        decrypt(
            &cts,
            &bte_crs,
            &ste_crs,
            t,
            &partial_decryptions,
            &selector,
            &ak,
            markers,
        );
    }
}
