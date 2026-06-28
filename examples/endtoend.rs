use ark_bls12_381::Bls12_381;
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    PrimeGroup,
};
use ark_std::{end_timer, start_timer, test_rng, Zero};
use silent_batched_threshold_encryption::{
    bte::{
        self, batch_eval,
        encryption::{CHUNK_BITS, NUM_CHUNKS},
    },
    dlog::{self, Markers},
    nizk::{kzg, pd, range},
    ste,
};
use std::time::Instant;

type E = Bls12_381;

struct Timings {
    batch_size: usize,
    partial_dec_ms: f64,
    reconstruct_18_s: f64,
    reconstruct_sb_s: f64,
}

fn run_benchmark(batch_size: usize, markers: &Markers<PairingOutput<E>>) -> Timings {
    let mut rng = test_rng();
    let n = 1 << 7;
    let l = NUM_CHUNKS;
    debug_assert!(
        batch_size
            <= dlog::max_homomorphic_batch_size(bte::encryption::CHUNK_BITS, dlog::DLOG_RANGE_BITS),
        "batch_size exceeds BSGS DLog range"
    );
    let t: usize = n / 2;

    println!("\n========================================");
    println!(
        "Parameters: n = {}, l = {}, batch_size = {}, t = {}",
        n, l, batch_size, t
    );
    println!("========================================");

    let timer = start_timer!(|| "Sampling CRS");
    let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
    let ste_crs = ste::crs::CRS::new(n, l, &mut rng);
    let kzg_crs = kzg::Crs::<E>::new(range::required_kzg_degree(CHUNK_BITS as usize), &mut rng);
    end_timer!(timer);

    let timer = start_timer!(|| "Sampling Keys");
    let sk = (0..n)
        .map(|i| ste::setup::SecretKey::<E>::new(&mut rng, i))
        .collect::<Vec<_>>();

    let lag_pk = sk
        .iter()
        .enumerate()
        .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
        .collect::<Vec<_>>();
    end_timer!(timer);

    let timer = start_timer!(|| "Aggregating Keys");
    let (ak, ek) = ste::aggregate::AggregateKey::<E>::new(lag_pk.clone(), &ste_crs);
    end_timer!(timer);

    let timer = start_timer!(|| "Encrypting Messages");
    let gen_t = PairingOutput::<E>::generator();
    let messages = (0..batch_size)
        .map(|i| gen_t * <E as Pairing>::ScalarField::from((i + 1) as u64))
        .collect::<Vec<_>>();
    let cts = (0..batch_size)
        .map(|i| {
            bte::encryption::encrypt_cca(
                i,
                messages[i],
                &bte_crs,
                &ste_crs,
                &kzg_crs,
                &ek,
                t,
                &mut rng,
            )
        })
        .collect::<Vec<_>>();
    end_timer!(timer);

    let timer = start_timer!(|| "Verifying CCA Ciphertexts");
    assert!(
        bte::encryption::verify_cca_batch(&cts, &bte_crs, &ste_crs, &kzg_crs, &ek),
        "CCA ciphertext verification failed"
    );
    end_timer!(timer);

    // --- Partial decryption: time a single party (includes ciphertext aggregation) ---
    let _ = sk[0].batch_partial_decryption_cca(&ste_crs, &lag_pk[0], &cts, &mut rng);
    let t0 = Instant::now();
    let _ = sk[0].batch_partial_decryption_cca(&ste_crs, &lag_pk[0], &cts, &mut rng);
    let partial_dec_single = t0.elapsed();

    // Build all partial decryptions for reconstruction
    let verified_partial_decryptions = (0..t)
        .map(|i| sk[i].batch_partial_decryption_cca(&ste_crs, &lag_pk[i], &cts, &mut rng))
        .collect::<Vec<_>>();

    let bases = cts
        .iter()
        .map(|c| c.encrypted_key.sa1[1])
        .collect::<Vec<_>>();
    for verified in &verified_partial_decryptions {
        let id = verified.partial.id;
        assert!(
            pd::verify_for_bases(
                &ste_crs,
                &lag_pk[id],
                &bases,
                verified.partial.pd,
                &verified.proof,
            ),
            "partial decryption proof verification failed for party {id}"
        );
    }

    let mut partial_decryptions = vec![ste::setup::PartialDecryption::<E>::zero(); n];
    let mut selector = vec![false; n];
    for verified in &verified_partial_decryptions {
        let id = verified.partial.id;
        partial_decryptions[id] = verified.partial.clone();
        selector[id] = true;
    }

    // --- [18]: naive B^2 PPRF eval only (no STE layer) ---
    // Recover k_agg via STE (shared cost, not counted for [18])
    let k_agg_ct = cts
        .iter()
        .fold(ste::encryption::Ciphertext::<E>::zero(l, t), |acc, c| {
            acc.add(&c.encrypted_key)
        });
    let k_agg_t =
        ste::decryption::agg_dec(&partial_decryptions, &k_agg_ct, &selector, &ak, &ste_crs);
    let k_agg_chunks: Vec<_> = k_agg_t
        .iter()
        .map(|y| markers.compute_dlog(y).expect("DLog failed"))
        .collect();
    let mut k_agg_scalar = <E as ark_ec::pairing::Pairing>::ScalarField::zero();
    let mut offset = <E as ark_ec::pairing::Pairing>::ScalarField::from(1u64);
    let chunk_radix = <E as Pairing>::ScalarField::from(1u128 << CHUNK_BITS);
    for chunk in &k_agg_chunks {
        k_agg_scalar += offset * chunk;
        offset *= chunk_radix;
    }
    let k_agg = bte::PRF::from_key(k_agg_scalar);
    let pprfs: Vec<_> = cts.iter().map(|c| c.pprf.clone()).collect();

    // Time ONLY the B^2 PPRF eval loop (what [18] measures)
    let t0 = Instant::now();
    for i in 0..batch_size {
        let _mask = k_agg.eval(i, &bte_crs) - batch_eval(&pprfs, i, &bte_crs);
    }
    let reconstruct_18 = t0.elapsed();

    // --- Sigma_SB: full reconstruction (STE + DLog + FFT PPRF evals) ---
    let t0 = Instant::now();
    let recovered = bte::decryption::decrypt_cca_fft(
        &cts,
        &bte_crs,
        &ste_crs,
        &kzg_crs,
        t,
        &verified_partial_decryptions,
        &ak,
        &ek,
        markers.clone(),
    )
    .expect("CCA decryption failed");
    assert_eq!(recovered, messages, "CCA decryption recovered wrong messages");
    let reconstruct_sb = t0.elapsed();

    let timings = Timings {
        batch_size,
        partial_dec_ms: partial_dec_single.as_secs_f64() * 1000.0,
        reconstruct_18_s: reconstruct_18.as_secs_f64(),
        reconstruct_sb_s: reconstruct_sb.as_secs_f64(),
    };

    println!("  Partial dec (1 party): {:.2} ms", timings.partial_dec_ms);
    println!(
        "  Reconstruction [18] (PPRF evals only): {:.2} s",
        timings.reconstruct_18_s
    );
    println!(
        "  Reconstruction Sigma_SB (full):        {:.2} s",
        timings.reconstruct_sb_s
    );

    timings
}

fn main() {
    let path = "markers_bsgs.bin";
    let markers = if std::path::Path::new(path).exists() {
        let timer = start_timer!(|| "Loading BSGS markers");
        let m = Markers::<PairingOutput<E>>::read_from_file(path);
        end_timer!(timer);
        m
    } else {
        println!("Markers file not found, generating new markers...");
        let m = Markers::<PairingOutput<E>>::new();
        m.save_to_file(path);
        m
    };

    let batch_sizes = [8, 32, 128, 512];
    let results: Vec<Timings> = batch_sizes
        .iter()
        .map(|&b| run_benchmark(b, &markers))
        .collect();

    println!("\n\n╔══════════════════════════════════════════════╗");
    println!("║     Partial-Decryption Benchmarks (ms)       ║");
    println!("╠════════════╦═══════════════════════════════════╣");
    println!("║ Batch size ║        [18], Sigma_SB            ║");
    println!("╠════════════╬═══════════════════════════════════╣");
    for r in &results {
        println!(
            "║ {:>10} ║ {:>15.2}                   ║",
            r.batch_size, r.partial_dec_ms
        );
    }
    println!("╚════════════╩═══════════════════════════════════╝");

    println!();
    println!("╔══════════════════════════════════════════════╗");
    println!("║       Reconstruction Benchmarks (s)          ║");
    println!("╠════════════╦═══════════════╦═════════════════╣");
    println!("║ Batch size ║     [18]      ║    Sigma_SB     ║");
    println!("╠════════════╬═══════════════╬═════════════════╣");
    for r in &results {
        println!(
            "║ {:>10} ║ {:>13.2} ║ {:>15.2} ║",
            r.batch_size, r.reconstruct_18_s, r.reconstruct_sb_s
        );
    }
    println!("╚════════════╩═══════════════╩═════════════════╝");
}
