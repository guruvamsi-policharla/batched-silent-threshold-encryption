use ark_ec::CurveGroup;
use ark_ec::VariableBaseMSM;
/// Estimate of Beat-MEV cpa decryption time
use ark_std::test_rng;
use ark_std::UniformRand;
use criterion::BenchmarkId;
use criterion::{criterion_group, criterion_main, Criterion};

type E = ark_bls12_381::Bls12_381;
type G1 = <E as ark_ec::pairing::Pairing>::G1;
type G1Affine = <G1 as CurveGroup>::Affine;
type F = <E as ark_ec::pairing::Pairing>::ScalarField;

fn partialdec(ct1: &Vec<G1Affine>, scalars: &Vec<F>, sk: F) {
    let agg_ct1 = G1::msm(&ct1, &scalars).unwrap();

    let _partial_decryption = agg_ct1 * sk;
}

fn bench_btepd(c: &mut Criterion) {
    let mut rng = test_rng();
    let sk = F::rand(&mut rng);

    let mut group = c.benchmark_group("bte_pd");
    for &batch_size in [8usize, 32, 128, 512].iter() {
        let ct1 = (0..batch_size)
            .map(|_| G1::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let scalars = (0..batch_size)
            .map(|_| F::rand(&mut rng))
            .collect::<Vec<_>>();

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &(ct1, scalars, sk),
            |b, inp| {
                b.iter(|| partialdec(&inp.0, &inp.1, inp.2));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_btepd);
criterion_main!(benches);
