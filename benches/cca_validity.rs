use ark_std::test_rng;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use silent_batched_threshold_encryption::{
    bte::{
        self,
        encryption::{CHUNK_BITS, NUM_CHUNKS},
    },
    cca::{
        CcaStatementContext, PedersenCommitments, RangeProof, RangeProofBatchItem, SchnorrProof,
        ValidityProof, ValidityProofBatchItem,
    },
    ste,
};

type E = ark_bls12_381::Bls12_381;

fn bench_cca_validity(c: &mut Criterion) {
    let mut rng = test_rng();
    let n = (2 * CHUNK_BITS as usize + 3).next_power_of_two();
    let l = NUM_CHUNKS;
    let batch_size = 512;
    let t: usize = n / 2;
    let position = 0;

    let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
    let ste_crs = ste::crs::CRS::new(n, l, &mut rng);

    let sk = (0..n)
        .map(|i| ste::setup::SecretKey::<E>::new(&mut rng, i))
        .collect::<Vec<_>>();
    let pk = sk
        .iter()
        .enumerate()
        .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
        .collect::<Vec<_>>();
    let (_ak, ek) = ste::aggregate::AggregateKey::<E>::new(pk, &ste_crs);
    let context = CcaStatementContext::new(&bte_crs, &ste_crs, &ek);

    let (ciphertext, witness) =
        bte::encryption::encrypt_with_witness(position, &bte_crs, &ste_crs, &ek, t, &mut rng);
    let (commitments, openings) = PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);
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
    let range_proof = RangeProof::prove_with_context(
        &context.range_params_digest,
        &commitments,
        &witness,
        &openings,
        &ste_crs,
        &mut rng,
    );
    let schnorr_proof = SchnorrProof::prove_with_context(
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

    let mut group = c.benchmark_group("cca_validity");

    group.bench_function("baseline_bte_encrypt_without_cca_proof", |b| {
        b.iter(|| bte::encryption::encrypt(position, &bte_crs, &ste_crs, &ek, t, &mut rng))
    });

    group.bench_function("pedersen_commit_prf_chunks_only", |b| {
        b.iter(|| PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng))
    });

    group.bench_function("range_proof_prove_for_committed_chunks_only", |b| {
        b.iter(|| {
            RangeProof::prove_with_context(
                &context.range_params_digest,
                &commitments,
                &witness,
                &openings,
                &ste_crs,
                &mut rng,
            )
        })
    });

    group.bench_function("range_proof_verify_committed_chunks_only", |b| {
        b.iter(|| {
            range_proof.verify_with_context(&context.range_params_digest, &commitments, &ste_crs)
        })
    });

    group.bench_function("ciphertext_linkage_schnorr_prove_only", |b| {
        b.iter(|| {
            SchnorrProof::prove_with_context(
                &context,
                &ciphertext,
                &bte_crs,
                &ste_crs,
                &ek,
                &commitments,
                &witness,
                &openings,
                &mut rng,
            )
        })
    });

    group.bench_function("ciphertext_linkage_schnorr_verify_only", |b| {
        b.iter(|| {
            schnorr_proof.verify_with_context(
                &context,
                &ciphertext,
                &bte_crs,
                &ste_crs,
                &ek,
                &commitments,
            )
        })
    });

    group.bench_function(
        "full_cca_validity_prove_excluding_encryption_and_commitments",
        |b| {
            b.iter(|| {
                ValidityProof::prove_with_context(
                    &context,
                    &ciphertext,
                    &bte_crs,
                    &ste_crs,
                    &ek,
                    &commitments,
                    &witness,
                    &openings,
                    &mut rng,
                )
            })
        },
    );

    group.bench_function("full_cca_validity_verify", |b| {
        b.iter(|| {
            proof.verify_with_context(&context, &ciphertext, &bte_crs, &ste_crs, &ek, &commitments)
        })
    });

    for &verify_batch_size in &[1usize, 2, 4, 8] {
        let mut ciphertexts = Vec::with_capacity(verify_batch_size);
        let mut commitment_batches = Vec::with_capacity(verify_batch_size);
        let mut proofs = Vec::with_capacity(verify_batch_size);

        for position in 0..verify_batch_size {
            let (ciphertext, witness) = bte::encryption::encrypt_with_witness(
                position, &bte_crs, &ste_crs, &ek, t, &mut rng,
            );
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
            ciphertexts.push(ciphertext);
            commitment_batches.push(commitments);
            proofs.push(proof);
        }

        let range_statements = (0..verify_batch_size)
            .map(|i| RangeProofBatchItem {
                chunk_commitments: &commitment_batches[i],
                proof: &proofs[i].range_proof,
            })
            .collect::<Vec<_>>();
        let validity_statements = (0..verify_batch_size)
            .map(|i| ValidityProofBatchItem {
                ciphertext: &ciphertexts[i],
                chunk_commitments: &commitment_batches[i],
                proof: &proofs[i],
            })
            .collect::<Vec<_>>();

        group.bench_with_input(
            BenchmarkId::new("range_verify_individual_loop", verify_batch_size),
            &verify_batch_size,
            |b, _| {
                b.iter(|| {
                    black_box((0..verify_batch_size).all(|i| {
                        proofs[i].range_proof.verify_with_context(
                            &context.range_params_digest,
                            &commitment_batches[i],
                            &ste_crs,
                        )
                    }))
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("range_verify_batched_kzg", verify_batch_size),
            &verify_batch_size,
            |b, _| {
                b.iter(|| {
                    black_box(RangeProof::verify_batch_with_context(
                        &context.range_params_digest,
                        &range_statements,
                        &ste_crs,
                    ))
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("full_cca_verify_individual_loop", verify_batch_size),
            &verify_batch_size,
            |b, _| {
                b.iter(|| {
                    black_box((0..verify_batch_size).all(|i| {
                        proofs[i].verify_with_context(
                            &context,
                            &ciphertexts[i],
                            &bte_crs,
                            &ste_crs,
                            &ek,
                            &commitment_batches[i],
                        )
                    }))
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("full_cca_verify_batched", verify_batch_size),
            &verify_batch_size,
            |b, _| {
                b.iter(|| {
                    black_box(ValidityProof::verify_batch_with_context(
                        &context,
                        &validity_statements,
                        &bte_crs,
                        &ste_crs,
                        &ek,
                    ))
                })
            },
        );
    }

    group.bench_function(
        "pedersen_commitments_plus_full_cca_validity_prove_excluding_encryption",
        |b| {
            b.iter(|| {
                let (commitments, openings) =
                    PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);
                ValidityProof::prove_with_context(
                    &context,
                    &ciphertext,
                    &bte_crs,
                    &ste_crs,
                    &ek,
                    &commitments,
                    &witness,
                    &openings,
                    &mut rng,
                )
            })
        },
    );

    group.bench_function(
        "bte_encrypt_plus_pedersen_commitments_plus_full_cca_validity_prove",
        |b| {
            b.iter(|| {
                let (ciphertext, witness) = bte::encryption::encrypt_with_witness(
                    position, &bte_crs, &ste_crs, &ek, t, &mut rng,
                );
                let (commitments, openings) =
                    PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);
                (
                    ciphertext.clone(),
                    commitments.clone(),
                    ValidityProof::prove_with_context(
                        &context,
                        &ciphertext,
                        &bte_crs,
                        &ste_crs,
                        &ek,
                        &commitments,
                        &witness,
                        &openings,
                        &mut rng,
                    ),
                )
            })
        },
    );

    group.finish();
}

criterion_group!(benches, bench_cca_validity);
criterion_main!(benches);
