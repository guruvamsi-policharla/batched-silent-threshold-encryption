use crate::{
    bte::{self, batch_eval, encryption, encryption::CcaCiphertext},
    dlog::{self, Markers},
    nizk::{kzg, pd},
    ste,
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_std::{end_timer, start_timer, One, Zero};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CcaDecryptionError {
    InvalidCiphertext(usize),
    InvalidPartialDecryption(usize),
    DuplicatePartialDecryption(usize),
    InsufficientPartialDecryptions { got: usize, need: usize },
    DLogOutOfRange,
    PositionMismatch { index: usize, position: usize },
}

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

pub fn decrypt_cca_fft<E: Pairing>(
    ct: &[CcaCiphertext<E>],
    bte_crs: &bte::crs::CRS<E>,
    ste_crs: &ste::crs::CRS<E>,
    kzg_crs: &kzg::Crs<E>,
    t: usize,
    partial_decryptions: &[ste::setup::VerifiedPartialDecryption<E>],
    agg_key: &ste::aggregate::AggregateKey<E>,
    ek: &ste::aggregate::EncryptionKey<E>,
    markers: Markers<PairingOutput<E>>,
) -> Result<Vec<PairingOutput<E>>, CcaDecryptionError> {
    dlog::assert_homomorphic_batch_safe(ct.len(), encryption::CHUNK_BITS, dlog::DLOG_RANGE_BITS);

    for (i, ciphertext) in ct.iter().enumerate() {
        if ciphertext.position != i || ciphertext.pprf.point != i {
            return Err(CcaDecryptionError::PositionMismatch {
                index: i,
                position: ciphertext.position,
            });
        }
    }
    if !encryption::verify_cca_batch(ct, bte_crs, ste_crs, kzg_crs, ek) {
        let invalid = ct
            .iter()
            .position(|ciphertext| {
                !encryption::verify_cca(ciphertext, bte_crs, ste_crs, kzg_crs, ek)
            })
            .unwrap_or(0);
        return Err(CcaDecryptionError::InvalidCiphertext(invalid));
    }

    let bases = ct
        .iter()
        .map(|c| c.encrypted_key.sa1[1])
        .collect::<Vec<_>>();
    let n = agg_key.lag_pks.len();
    let mut partials = vec![ste::setup::PartialDecryption::<E>::zero(); n];
    let mut selector = vec![false; n];
    let mut valid = 0usize;
    for verified in partial_decryptions {
        let id = verified.partial.id;
        if id >= n {
            return Err(CcaDecryptionError::InvalidPartialDecryption(id));
        }
        if selector[id] {
            return Err(CcaDecryptionError::DuplicatePartialDecryption(id));
        }
        if !pd::verify_for_bases(
            ste_crs,
            &agg_key.lag_pks[id],
            &bases,
            verified.partial.pd,
            &verified.proof,
        ) {
            return Err(CcaDecryptionError::InvalidPartialDecryption(id));
        }
        selector[id] = true;
        partials[id] = verified.partial.clone();
        valid += 1;
    }

    if valid < t {
        return Err(CcaDecryptionError::InsufficientPartialDecryptions {
            got: valid,
            need: t,
        });
    }

    let k_agg_ct = ct.iter().fold(
        ste::encryption::Ciphertext::<E>::zero(ste_crs.l, t),
        |acc, c| acc.add(&c.encrypted_key),
    );
    let k_agg_t = ste::decryption::agg_dec(&partials, &k_agg_ct, &selector, agg_key, ste_crs);

    let k_agg_chunks = k_agg_t
        .iter()
        .map(|y| {
            markers
                .compute_dlog(y)
                .ok_or(CcaDecryptionError::DLogOutOfRange)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut k_agg_scalar = E::ScalarField::zero();
    let mut offset = E::ScalarField::one();
    let chunk_radix = E::ScalarField::from(1u128 << encryption::CHUNK_BITS);
    for chunk in &k_agg_chunks {
        k_agg_scalar += offset * chunk;
        offset *= chunk_radix;
    }

    let k_agg = bte::PRF::from_key(k_agg_scalar);
    let pprfs = ct.iter().map(|c| c.pprf.clone()).collect::<Vec<_>>();
    let recovered_masks = bte::fft_batch_eval(&k_agg, &pprfs, bte_crs);
    Ok(ct
        .iter()
        .zip(recovered_masks)
        .map(|(ciphertext, mask)| ciphertext.beta - mask)
        .collect())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::bte::encryption::encrypt;
    use ark_bls12_381::Bls12_381;
    use ark_ec::PrimeGroup;
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

        let path = "markers_bsgs_decrypt_test.bin";
        let timer = start_timer!(|| "loading markers");
        let markers = if std::path::Path::new(path).exists() {
            Markers::<PairingOutput<E>>::read_from_file(path)
        } else {
            let m = Markers::<PairingOutput<E>>::new();
            m.save_to_file(path);
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

    #[test]
    fn test_decrypt_cca_fft() {
        let mut rng = test_rng();
        let n = 1 << 3;
        let l = encryption::NUM_CHUNKS;
        let batch_size = 4;
        let t: usize = n / 2;

        let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
        let ste_crs = ste::crs::CRS::new(n, l, &mut rng);
        let kzg_crs = crate::nizk::kzg::Crs::<E>::new(
            crate::nizk::range::required_kzg_degree(encryption::CHUNK_BITS as usize),
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
        let (ak, ek) = ste::aggregate::AggregateKey::<E>::new(pk.clone(), &ste_crs);

        let gen_t = PairingOutput::<E>::generator();
        let messages = (0..batch_size)
            .map(|i| gen_t * <E as ark_ec::pairing::Pairing>::ScalarField::from((i + 1) as u64))
            .collect::<Vec<_>>();
        let cts = messages
            .iter()
            .enumerate()
            .map(|(i, &message)| {
                encryption::encrypt_cca(i, message, &bte_crs, &ste_crs, &kzg_crs, &ek, t, &mut rng)
            })
            .collect::<Vec<_>>();

        let partial_decryptions = (0..t)
            .map(|i| sk[i].batch_partial_decryption_cca(&ste_crs, &pk[i], &cts, &mut rng))
            .collect::<Vec<_>>();

        let path = "markers_bsgs_cca_decrypt_test.bin";
        let markers = if std::path::Path::new(path).exists() {
            Markers::<PairingOutput<E>>::read_from_file(path)
        } else {
            let m = Markers::<PairingOutput<E>>::new();
            m.save_to_file(path);
            m
        };

        let recovered = decrypt_cca_fft(
            &cts,
            &bte_crs,
            &ste_crs,
            &kzg_crs,
            t,
            &partial_decryptions,
            &ak,
            &ek,
            markers,
        )
        .unwrap();
        assert_eq!(recovered, messages);
    }
}
