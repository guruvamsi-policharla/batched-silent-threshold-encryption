use ark_ec::PrimeGroup;
use ark_std::{end_timer, start_timer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bases and markers to solve a DLog problem with the power in the range of [0, 2^size)
/// log_max_input must be log_markers + log_bases
/// The performance here has some interesting quirks that can be further optimized
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Markers<G: PrimeGroup> {
    pub log_max_input: usize,
    pub log_markers: usize,
    pub markers_map: std::collections::HashMap<[u8; 6], usize>,
    _phantom: std::marker::PhantomData<G>,
}

impl<G: PrimeGroup> Markers<G> {
    pub fn new(log_max_input: usize, log_markers: usize) -> Self {
        let log_bases = log_max_input - log_markers;

        // markers at evenly spaced 2^size points between 0 and 2^{2*size}
        let timer = start_timer!(|| "computing markers");
        let mut marker = G::zero();
        let diff = G::generator() * G::ScalarField::from(1 << log_bases);
        let mut markers_map = std::collections::HashMap::new();

        let mut bytes = Vec::new();
        marker.serialize_uncompressed(&mut bytes).unwrap();
        let hash: [u8; 6] = Sha256::digest(&bytes)[0..6].try_into().unwrap();
        markers_map.insert(hash, 0);

        for i in 1..(1 << log_markers) {
            marker += diff;

            let mut bytes = Vec::new();
            marker.serialize_uncompressed(&mut bytes).unwrap();
            let hash: [u8; 6] = Sha256::digest(&bytes)[0..6].try_into().unwrap();
            markers_map.insert(hash, i);
        }
        end_timer!(timer);

        Markers {
            log_max_input,
            log_markers,
            markers_map,
            _phantom: std::marker::PhantomData,
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
        let log_bases = self.log_max_input - self.log_markers;
        let mut darts = vec![G::zero(); 1 << log_bases]; // throwing darts hoping they will hit one of the markers
        let gen_t = G::generator();
        darts[0] = *target + gen_t;
        for i in 1..(1 << log_bases) {
            darts[i] = darts[i - 1] + gen_t;
        }

        // check for intersection between darts and markers_map
        for i in 0..(1 << log_bases) {
            let mut bytes = Vec::new();
            darts[i].serialize_uncompressed(&mut bytes).unwrap();
            let hash: [u8; 6] = Sha256::digest(&bytes)[0..6].try_into().unwrap();

            if let Some(&j) = self.markers_map.get(&hash) {
                return Some(G::ScalarField::from(((1 << log_bases) * j - i - 1) as u128));
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
        let log_max_input = 41;
        let log_markers = 25;
        // sample a random value between 0 and 2^size
        let random_value: u128 = 100;
        let should_be_dlog = Fr::from(random_value);

        let target = GT::generator() * should_be_dlog;
        let path = &format!("markers_{}_{}.bin", log_max_input, log_markers);

        // Read markers from file if exists, else create new and save
        let timer = start_timer!(|| "loading markers");
        let markers = if std::path::Path::new(path).exists() {
            Markers::<GT>::read_from_file(path)
        } else {
            println!("Markers file not found, generating new markers...");
            let m = Markers::<GT>::new(log_max_input, log_markers);
            m.save_to_file(path);
            m
        };
        end_timer!(timer);
        let timer = start_timer!(|| "computing dlog");
        let computed_dlog = markers.compute_dlog(&target).unwrap();
        end_timer!(timer);
        assert_eq!(
            computed_dlog, should_be_dlog,
            "Computed DLog from markers does not match the expected value"
        );
    }
}
