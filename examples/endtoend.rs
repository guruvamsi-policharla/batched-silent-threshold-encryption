use ark_bls12_381::Bls12_381;
use ark_ec::pairing::PairingOutput;
use ark_std::{end_timer, start_timer, test_rng};
use silent_batched_threshold_encryption::{bte, dlog::Markers, ste};

type E = Bls12_381;

fn main() {
    let mut rng = test_rng();
    let n = 1 << 7;
    let l = 8;
    let batch_size = 23;
    let log_max_input = 41;
    let log_markers = 25;
    let t: usize = n / 2;

    println!(
        "Parameters: n = {}, l = {}, batch_size = {}, t = {}",
        n, l, batch_size, t
    );

    let timer = start_timer!(|| "Sampling CRS");
    let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
    let ste_crs = ste::crs::CRS::new(n, l, &mut rng);
    // let lag_polys = ste::setup::LagPolys::<F>::new(ste_crs.n);
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
    let (_ak, ek) = ste::aggregate::AggregateKey::<E>::new(lag_pk, &ste_crs);
    end_timer!(timer);

    let timer = start_timer!(|| "Encrypting Messages");
    let cts = (0..batch_size)
        .map(|i| bte::encryption::encrypt(i, &bte_crs, &ste_crs, &ek, t, &mut rng))
        .collect::<Vec<_>>();
    end_timer!(timer);

    // aggregate the ciphertexts
    let timer = start_timer!(|| "Aggregating Ciphertexts");
    let agg_ct = cts.iter().fold(
        ste::encryption::Ciphertext::<E>::zero(batch_size, t),
        |acc, c| acc.add(&c.encrypted_key),
    );
    end_timer!(timer);

    // compute partial decryptions
    let timer = start_timer!(|| "Computing Partial Decryptions");
    let mut partial_decryptions: Vec<ste::setup::PartialDecryption<E>> = Vec::new();
    for i in 0..t {
        partial_decryptions.push(sk[i].partial_decryption(&agg_ct));
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

    // read the markers
    let path = &format!("markers_{}_{}.bin", log_max_input, log_markers);
    let timer = start_timer!(|| "loading markers");
    let markers = if std::path::Path::new(path).exists() {
        Markers::<PairingOutput<E>>::read_from_file(path)
    } else {
        println!("Markers file not found, generating new markers...");
        let m = Markers::<PairingOutput<E>>::new(log_max_input, log_markers);
        m.save_to_file(path);
        m
    };
    end_timer!(timer);

    // decrypt the ciphertexts
    let timer = start_timer!(|| "Decrypting Ciphertexts");
    bte::decryption::decrypt(
        &cts,
        &bte_crs,
        &ste_crs,
        t,
        &partial_decryptions,
        &selector,
        &_ak,
        markers,
    );
    end_timer!(timer);
}
