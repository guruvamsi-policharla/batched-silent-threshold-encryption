# Batched Threshold Encryption with Silent Setup

Rust implementation of **Batched Threshold Encryption with Silent Setup**, from [ePrint:2025/1419](https://eprint.iacr.org/2025/1419).

The library has been confirmed to work with version 1.87.0 of the Rust compiler. An end-to-end example demonstrating the full BSTE workflow is provided in the `examples/` directory.

## Dependencies
Install rust via:

```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh```

## Benchmarking
The library can be built using ```cargo build --release```.

Use ```cargo bench``` to benchmark the various components:
- `setup` - Key generation and aggregation
- `encryption` - Encryption time
- `bte_pd` - Batched threshold encryption partial decryption
- `sbte_pd` - Silent batched threshold encryption partial decryption
- `beatmev_pd` - Estimate of Beat-MEV partial decryption time (reimplemented to normalize performance with respect to arkworks)

To run all benchmarks: ```cargo bench```

To run a specific benchmark: ```cargo bench --bench <bench_name>```

Use ```cargo run --example endtoend``` to run an end-to-end demonstration of the SBTE scheme.

The results are saved in the `target/criterion` directory. A concise HTML report is generated in `target/criterion/index.html` and can be viewed in a browser (Google Chrome recommended).

If you wish to benchmark for a different set of parameters, you can modify the files in the `benches/` directory. 

## Unit Tests
Individual unit tests can be found at the end of the respective files in the `src/` directory. These test the correctness of the STE, BTE, and SBTE implementations.

Run all tests: ```cargo test```

Run a specific test: ```cargo test <test_name>```

This will help verify the correctness of the cryptographic operations and ensure proper functionality of the threshold encryption schemes.

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Overview

This implementation consists of three main components:

### Silent Threshold Encryption (STE)
Located in `src/ste/`:
* [`src/ste/setup.rs`](src/ste/setup.rs): Key generation, aggregation, and partial decryption operations using BLS signatures. Contains methods for sampling public key pairs.
* [`src/ste/encryption.rs`](src/ste/encryption.rs): Implementation of the STE encryption scheme with linearly homomorphic properties.
* [`src/ste/decryption.rs`](src/ste/decryption.rs): Aggregate decryption (`agg_dec`) that combines partial decryptions to recover messages.
* [`src/ste/aggregate.rs`](src/ste/aggregate.rs): Methods for aggregating keys of a given committee.

### Batched Threshold Encryption (BTE)  
Located in `src/bte/`:
* [`src/bte/mod.rs`](src/bte/mod.rs): Core BTE functionality including puncturable pseudorandom functions (PRF and PPRF) with homomorphic properties.
* [`src/bte/encryption.rs`](src/bte/encryption.rs): Batched encryption methods
* [`src/bte/decryption.rs`](src/bte/decryption.rs): Batched decryption that recovers the aggregate PRF key and unmasks all encrypted messages efficiently.
* [`src/bte/crs.rs`](src/bte/crs.rs): Common reference string setup for the BTE scheme.

### Batched Silent Threshold Encryption (BSTE)
Located in `src/sbte.rs`: Combines STE and BTE to enable efficient batched decryption with silent setup

### Additional Components
* [`src/dlog/`](src/dlog/): Discrete logarithm computation utilities with precomputed markers for efficient solving.
* [`src/utils.rs`](src/utils.rs): General utility functions and cryptographic helpers.

## License
This library is released under the MIT License.
