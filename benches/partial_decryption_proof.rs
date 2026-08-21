use ark_ec::pairing::PairingOutput;
use ark_std::{test_rng, Zero};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use silent_batched_threshold_encryption::{
    bte::{
        self,
        encryption::{CHUNK_BITS, NUM_CHUNKS},
    },
    ste,
};

type E = ark_bls12_381::Bls12_381;

fn bench_partial_decryption_proof(c: &mut Criterion) {
    let mut rng = test_rng();
    let n = (2 * CHUNK_BITS as usize + 3).next_power_of_two();
    let l = NUM_CHUNKS;
    let batch_size = 512;
    let t = n / 2;

    let ste_crs = ste::crs::CRS::<E>::new(n, l, &mut rng);
    let sk = (0..n)
        .map(|i| ste::setup::SecretKey::<E>::new(&mut rng, i))
        .collect::<Vec<_>>();
    let pk = sk
        .iter()
        .enumerate()
        .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
        .collect::<Vec<_>>();
    let (_ak, ek) = ste::aggregate::AggregateKey::<E>::new(pk.clone(), &ste_crs);

    let message = vec![PairingOutput::<E>::zero(); l];
    let ste_ciphertext = ste::encryption::encrypt(&ek, t, &ste_crs, &message, &mut rng);
    let (single_partial_decryption, single_proof) =
        sk[0].partial_decryption_with_proof(&ste_ciphertext, &pk[0], &ste_crs, &mut rng);

    let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
    let bte_ciphertexts = (0..batch_size)
        .map(|i| bte::encryption::encrypt(i, &bte_crs, &ste_crs, &ek, t, &mut rng))
        .collect::<Vec<_>>();
    let (batch_partial_decryption, batch_proof) =
        sk[0].batch_partial_decryption_with_proof(&bte_ciphertexts, &pk[0], &ste_crs, &mut rng);

    let mut group = c.benchmark_group("partial_decryption_validity");

    group.bench_function("single_ste_partial_decryption_prove_compact_schnorr", |b| {
        b.iter(|| {
            black_box(sk[0].partial_decryption_with_proof(
                &ste_ciphertext,
                &pk[0],
                &ste_crs,
                &mut rng,
            ))
        })
    });

    group.bench_function(
        "single_ste_partial_decryption_verify_compact_schnorr",
        |b| {
            b.iter(|| {
                black_box(single_proof.verify(
                    &single_partial_decryption,
                    &ste_ciphertext,
                    &pk[0],
                    &ste_crs,
                ))
            })
        },
    );

    group.bench_function(
        "batch_512_bte_partial_decryption_prove_compact_schnorr",
        |b| {
            b.iter(|| {
                black_box(sk[0].batch_partial_decryption_with_proof(
                    &bte_ciphertexts,
                    &pk[0],
                    &ste_crs,
                    &mut rng,
                ))
            })
        },
    );

    group.bench_function(
        "batch_512_bte_partial_decryption_verify_compact_schnorr",
        |b| {
            b.iter(|| {
                black_box(batch_proof.verify_batch(
                    &batch_partial_decryption,
                    &bte_ciphertexts,
                    &pk[0],
                    &ste_crs,
                ))
            })
        },
    );

    group.finish();
}

criterion_group!(benches, bench_partial_decryption_proof);
criterion_main!(benches);
