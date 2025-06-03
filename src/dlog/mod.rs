use crate::utils::{ark_de, ark_map_de, ark_map_se, ark_se};
use ark_ec::PrimeGroup;
use ark_std::{end_timer, start_timer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bases and markers to solve a DLog problem with the power in the range of [0, 2^size)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Markers<G: PrimeGroup> {
    pub max_input: usize,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub bases: Vec<G>,
    #[serde(serialize_with = "ark_map_se", deserialize_with = "ark_map_de")]
    pub markers_map: std::collections::HashMap<[u8; 32], usize>,
}

impl<G: PrimeGroup> Markers<G> {
    pub fn new(max_input: usize) -> Self {
        let size = max_input;

        let timer: ark_std::perf_trace::TimerInfo = start_timer!(|| "computing bases");
        let mut bases = vec![G::zero(); 1 << size]; // elements from 0 to 2^size

        // NOTE: AVOID CALLING G::generator(). Arkworks actually computes the pairing every time instead of using a hardcoded generation
        bases[0] = G::generator();
        for i in 1..(1 << size) {
            bases[i] = bases[i - 1] + bases[0];
        }
        end_timer!(timer);

        let mut markers = vec![G::zero(); 1 << size]; // markers at evenly spaced 2^size points between 0 and 2^{2*size}
        let diff = G::generator() * G::ScalarField::from(1 << size);

        let timer = start_timer!(|| "computing markers");
        for i in 1..(1 << size) {
            markers[i] = markers[i - 1] + diff;
        }
        end_timer!(timer);

        // hash the markers using sha2
        let mut marker_hashes = Vec::with_capacity(markers.len());
        let timer = start_timer!(|| "hashing markers");
        for marker in &markers {
            // Serialize the marker to bytes using bincode
            let mut bytes = Vec::new();
            marker.serialize_uncompressed(&mut bytes).unwrap();
            let hash: [u8; 32] = Sha256::digest(&bytes).into();
            marker_hashes.push(hash);
        }
        end_timer!(timer);

        // store markers in a hashmap
        let timer = start_timer!(|| "generating markers map");
        let mut markers_map = std::collections::HashMap::new();
        for i in 0..(1 << size) {
            markers_map.insert(marker_hashes[i], i);
        }
        end_timer!(timer);

        Markers {
            max_input,
            bases,
            markers_map,
        }
    }

    // save to file
    pub fn save_to_file(&self, path: &str) {
        let file = std::fs::File::create(path).unwrap();
        let mut writer = std::io::BufWriter::new(file);
        bincode::serialize_into(&mut writer, self).unwrap();
    }

    // read from file
    pub fn read_from_file(path: &str) -> Self {
        let file = std::fs::File::open(path).unwrap();
        let reader = std::io::BufReader::new(file);
        bincode::deserialize_from(reader).unwrap()
    }

    pub fn compute_dlog(&self, target: &G) -> Option<G::ScalarField> {
        let size = self.max_input;
        let mut darts = vec![G::zero(); 1 << size]; // throwing darts hoping they will hit one of the markers
        for i in 0..(1 << size) {
            darts[i] = *target + self.bases[i];
        }

        // check for intersection between darts and markers_map
        for i in 0..(1 << size) {
            let mut bytes = Vec::new();
            darts[i].serialize_uncompressed(&mut bytes).unwrap();
            let hash: [u8; 32] = Sha256::digest(&bytes).into();

            if let Some(&j) = self.markers_map.get(&hash) {
                return Some(G::ScalarField::from(((1 << size) * j - i - 1) as u128));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::pairing::{Pairing, PairingOutput};

    type E = ark_bls12_381::Bls12_381;
    // type G1 = <E as Pairing>::G1;
    // type G2 = <E as Pairing>::G2;
    type Fr = <E as Pairing>::ScalarField;
    type GT = PairingOutput<E>;

    #[test]
    fn test_compute_dlog() {
        let size = 18;
        // sample a random value between 0 and 2^size
        let random_value: u128 = 100;
        let should_be_dlog = Fr::from(random_value);

        let target = GT::generator() * should_be_dlog;
        let path = &format!("markers_{}.bin", size);

        // Read markers from file if exists, else create new and save
        let timer = start_timer!(|| "loading markers");
        let markers = if std::path::Path::new(path).exists() {
            Markers::<GT>::read_from_file(path)
        } else {
            println!("Markers file not found, generating new markers...");
            let m = Markers::<GT>::new(size);
            m.save_to_file(path);
            m
        };
        end_timer!(timer);

        let computed_dlog = markers.compute_dlog(&target).unwrap();
        assert_eq!(
            computed_dlog, should_be_dlog,
            "Computed DLog from markers does not match the expected value"
        );
    }
}
