use ark_bls12_381::Bls12_381;
use ark_ec::pairing::PairingOutput;
use ark_std::{end_timer, start_timer, test_rng};
use silent_batched_threshold_encryption::{
    bte::{self, encryption::NUM_CHUNKS},
    cca::{CcaStatementContext, PedersenCommitments, ValidityProof, ValidityProofBatchItem},
    dlog::{self, Markers},
    ste,
};

type E = Bls12_381;

fn run_benchmark(batch_size: usize) {
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
    let (ak, ek) = ste::aggregate::AggregateKey::<E>::new(lag_pk, &ste_crs);
    end_timer!(timer);

    let cca_batch_size = batch_size;
    let context = CcaStatementContext::new(&bte_crs, &ste_crs, &ek);
    let timer = start_timer!(|| format!(
        "Encrypting and proving {} CCA-valid ciphertexts",
        cca_batch_size
    ));
    let mut cca_cts = Vec::with_capacity(cca_batch_size);
    let mut cca_commitments = Vec::with_capacity(cca_batch_size);
    let mut cca_proofs = Vec::with_capacity(cca_batch_size);
    for position in 0..cca_batch_size {
        let (ciphertext, witness) =
            bte::encryption::encrypt_with_witness(position, &bte_crs, &ste_crs, &ek, t, &mut rng);
        let (commitments, openings) =
            PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);
        let proof = ValidityProof::prove_with_context(
            &context,
            &ciphertext,
            &bte_crs,
            &ste_crs,
            &ek,
            &commitments,
            &witness,
            &openings,
            &mut rng,
        );
        cca_cts.push(ciphertext);
        cca_commitments.push(commitments);
        cca_proofs.push(proof);
    }
    end_timer!(timer);

    let timer = start_timer!(|| "Verifying CCA validity proofs [individual]");
    assert!((0..cca_batch_size).all(|i| {
        cca_proofs[i].verify_with_context(
            &context,
            &cca_cts[i],
            &bte_crs,
            &ste_crs,
            &ek,
            &cca_commitments[i],
        )
    }));
    end_timer!(timer);

    let validity_statements = (0..cca_batch_size)
        .map(|i| ValidityProofBatchItem {
            ciphertext: &cca_cts[i],
            chunk_commitments: &cca_commitments[i],
            proof: &cca_proofs[i],
        })
        .collect::<Vec<_>>();
    let timer = start_timer!(|| "Verifying CCA validity proofs [batched]");
    assert!(ValidityProof::verify_batch_with_context(
        &context,
        &validity_statements,
        &bte_crs,
        &ste_crs,
        &ek,
    ));
    end_timer!(timer);

    let timer = start_timer!(|| "Encrypting Messages");
    let cts = (0..batch_size)
        .map(|i| bte::encryption::encrypt(i, &bte_crs, &ste_crs, &ek, t, &mut rng))
        .collect::<Vec<_>>();
    end_timer!(timer);

    let timer = start_timer!(|| "Computing Partial Decryptions");
    let agg_ct = cts
        .iter()
        .fold(ste::encryption::Ciphertext::<E>::zero(l, t), |acc, c| {
            acc.add(&c.encrypted_key)
        });
    let mut partial_decryptions: Vec<ste::setup::PartialDecryption<E>> = Vec::new();
    for i in 0..t {
        partial_decryptions.push(sk[i].partial_decryption(&agg_ct));
    }
    for _ in t..n {
        partial_decryptions.push(ste::setup::PartialDecryption::<E>::zero());
    }
    let selector: Vec<bool> = (0..n).map(|i| i < t).collect();
    end_timer!(timer);

    let path = format!(
        "markers_bsgs_{}_{}.bin",
        dlog::DLOG_RANGE_BITS,
        dlog::DLOG_MARKER_BITS
    );
    let markers = if std::path::Path::new(&path).exists() {
        Markers::<PairingOutput<E>>::read_from_file(&path)
    } else {
        println!("Markers file not found, generating new markers...");
        let m = Markers::<PairingOutput<E>>::new();
        m.save_to_file(&path);
        m
    };

    let timer = start_timer!(|| "Decrypting [standard batch_eval]");
    bte::decryption::decrypt(
        &cts,
        &bte_crs,
        &ste_crs,
        t,
        &partial_decryptions,
        &selector,
        &ak,
        markers.clone(),
    );
    end_timer!(timer);

    let timer = start_timer!(|| "Decrypting [fft_batch_eval]");
    bte::decryption::decrypt_fft(
        &cts,
        &bte_crs,
        &ste_crs,
        t,
        &partial_decryptions,
        &selector,
        &ak,
        markers,
    );
    end_timer!(timer);
}

fn main() {
    for &batch_size in &[8, 32, 128, 512] {
        run_benchmark(batch_size);
    }
}
