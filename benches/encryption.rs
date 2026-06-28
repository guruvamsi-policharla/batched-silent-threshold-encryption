use ark_ec::PrimeGroup;
use ark_std::{end_timer, start_timer, test_rng};
use criterion::{criterion_group, criterion_main, Criterion};
use silent_batched_threshold_encryption::{
    bte::{self, encryption::NUM_CHUNKS},
    nizk::{kzg, range},
    ste,
};

type E = ark_bls12_381::Bls12_381;

fn bench_encrypt(c: &mut Criterion) {
    let mut rng = test_rng();
    let n = 1 << 3;
    let l = NUM_CHUNKS;
    let batch_size = 512;
    let t: usize = n / 2;

    let timer = start_timer!(|| "Sampling CRS");
    let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
    let ste_crs = ste::crs::CRS::new(n, l, &mut rng);
    let kzg_crs = kzg::Crs::<E>::new(
        range::required_kzg_degree(bte::encryption::CHUNK_BITS as usize),
        &mut rng,
    );
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

    c.bench_function("encrypt", |b| {
        b.iter(|| bte::encryption::encrypt(0, &bte_crs, &ste_crs, &ek, t, &mut rng))
    });

    let message = ark_ec::pairing::PairingOutput::<E>::generator();
    c.bench_function("encrypt_cca", |b| {
        b.iter(|| {
            bte::encryption::encrypt_cca(0, message, &bte_crs, &ste_crs, &kzg_crs, &ek, t, &mut rng)
        })
    });
}

criterion_group!(benches, bench_encrypt);
criterion_main!(benches);
