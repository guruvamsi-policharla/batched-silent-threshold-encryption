use criterion::{criterion_group, criterion_main, Criterion};
use silent_threshold_encryption::bte::{
    crs::CRS,
    pprf::{batch_eval, naive_batch_eval, PRF},
};

type E = ark_bls12_381::Bls12_381;

fn bench_setup(c: &mut Criterion) {
    // WARNING: This benchmark will take a very long time. It is only meant to measure the speedup when compared to the faster Lagrange setup
    let mut group = c.benchmark_group("batch_eval");
    group.sample_size(10);
    let mut rng = ark_std::test_rng();

    let n = 1 << 9; // actually n-1 total parties. one party is a dummy party that is always true
    let crs = CRS::<E>::new(n, &mut rng);

    let prfs = (0..n).map(|_| PRF::<E>::new(&mut rng)).collect::<Vec<_>>();
    let pprfs = prfs
        .iter()
        .enumerate()
        .map(|(i, prf)| prf.puncture(i, &crs))
        .collect::<Vec<_>>();

    let input = 7;

    group.bench_function("Batch Eval", |b| b.iter(|| batch_eval(&pprfs, input, &crs)));
    group.bench_function("Naive Batch Eval", |b| {
        b.iter(|| naive_batch_eval(&pprfs, input, &crs))
    });

    group.finish();
}

criterion_group!(benches, bench_setup);
criterion_main!(benches);
