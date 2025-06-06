/// Estimate of Beat-MEV cpa decryption time
use ark_std::test_rng;
use ark_std::UniformRand;
use ark_std::Zero;
use criterion::BenchmarkId;
use criterion::{criterion_group, criterion_main, Criterion};

type E = ark_bls12_381::Bls12_381;
type G1 = <E as ark_ec::pairing::Pairing>::G1;
type F = <E as ark_ec::pairing::Pairing>::ScalarField;

fn partialdec(ct1: &Vec<G1>, sk: F) {
    let agg_ct1 = ct1.iter().fold(G1::zero(), |acc, c| acc + c);

    let _partial_decryption = agg_ct1 * sk;
}

fn bench_sbtepd(c: &mut Criterion) {
    let mut rng = test_rng();
    let sk = F::rand(&mut rng);

    let mut group = c.benchmark_group("sbte_pd");
    for &batch_size in [8usize, 32, 128, 512].iter() {
        let ct1 = (0..batch_size)
            .map(|_| G1::rand(&mut rng))
            .collect::<Vec<_>>();

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &(ct1, sk),
            |b, inp| {
                b.iter(|| partialdec(&inp.0, inp.1));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_sbtepd);
criterion_main!(benches);
