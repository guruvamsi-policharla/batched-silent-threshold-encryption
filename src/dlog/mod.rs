use ark_ec::PrimeGroup;
use ark_std::{end_timer, start_timer};
use serde::{Deserialize, Serialize};

/// Bases and markers to solve a DLog problem with the power in the range of [0, 2^size)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Markers<G: PrimeGroup> {
    pub range: usize,
    pub bases: Vec<G>,
    pub markers_map: ark_std::collections::HashMap<G, usize>,
}

impl<G: PrimeGroup> Markers<G> {
    pub fn new(range: usize) -> Self {
        let size = range / 2;

        let timer: ark_std::perf_trace::TimerInfo = start_timer!(|| "computing bases");
        let mut bases = vec![G::zero(); 1 << size]; // elements from 0 to 2^size
        for i in 1..(1 << size) {
            bases[i] = bases[i - 1] + G::generator();
        }
        end_timer!(timer);

        let mut markers = vec![G::zero(); 1 << size]; // markers at evenly space 2^size points between 0 and 2^40
        let diff = G::generator() * G::ScalarField::from(1 << size);

        let timer = start_timer!(|| "computing markers");
        for i in 1..(1 << size) {
            markers[i] = markers[i - 1] + diff;
        }
        end_timer!(timer);

        // store markers in a hashmap
        let timer = start_timer!(|| "generating markers map");
        let mut markers_map = std::collections::HashMap::new();
        for i in 0..(1 << size) {
            markers_map.insert(markers[i], i);
        }
        end_timer!(timer);

        Markers {
            range,
            bases,
            markers_map,
        }
    }

    // // save to file
    // pub fn save_to_file(&self, path: &str) {
    //     let file = std::fs::File::create(path).unwrap();
    //     let mut writer = std::io::BufWriter::new(file);
    //     bincode::serialize_into(&mut writer, self).unwrap();
    // }

    pub fn compute_dlog(&self, target: G) {
        let size = self.range / 2;
        let timer = start_timer!(|| "generating darts");
        let mut darts = vec![G::zero(); 1 << size]; // throwing darts hoping they will hit one of the markers
        for i in 0..(1 << size) {
            darts[i] = target + self.bases[i];
        }
        end_timer!(timer);

        // check for intersection between darts and markers_map
        let timer = start_timer!(|| "checking darts");
        for i in 0..(1 << size) {
            if let Some(&j) = self.markers_map.get(&darts[i]) {
                println!("Found a match at {}: {}", i, j);
                return;
            }
        }
        end_timer!(timer);
    }
}

// Solving DLog via brute force for a size of 2*size
pub fn compute_dlog<G: PrimeGroup>(target: G, size: usize) {
    let timer = start_timer!(|| "computing bases");
    let mut bases = vec![G::zero(); 1 << size]; //elements from 0 to 2^size
    for i in 1..(1 << size) {
        bases[i] = bases[i - 1] + G::generator();
    }
    end_timer!(timer);

    let mut markers = vec![G::zero(); 1 << size]; //markers at evenly space 2^size points between 0 and 2^40
    let diff = G::generator() * G::ScalarField::from(1 << size);

    let timer = start_timer!(|| "computing markers");
    for i in 1..(1 << size) {
        markers[i] = markers[i - 1] + diff;
    }
    end_timer!(timer);

    // store markers in a hashmap
    // todo: receive this as input
    let timer = start_timer!(|| "generating markers map");
    let mut markers_map = std::collections::HashMap::new();
    for i in 0..(1 << size) {
        markers_map.insert(markers[i], i);
    }
    end_timer!(timer);

    let timer = start_timer!(|| "generating darts");
    let mut darts = vec![G::zero(); 1 << size]; //throwing darts hoping they will hit one of the markers
    for i in 0..(1 << size) {
        darts[i] = target + bases[i];
    }
    end_timer!(timer);

    // check for intersection between darts and markers_map
    let timer = start_timer!(|| "checking darts");
    for i in 0..(1 << size) {
        if let Some(&j) = markers_map.get(&darts[i]) {
            println!("Found a match at {}: {}", i, j);
            return;
        }
    }
    end_timer!(timer);
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ec::pairing::{Pairing, PairingOutput};

    type E = ark_bls12_381::Bls12_381;
    type G1 = <E as Pairing>::G1;
    type G2 = <E as Pairing>::G2;
    type Fr = <E as Pairing>::ScalarField;
    type GT = PairingOutput<E>;

    #[test]
    fn test_compute_dlog() {
        let size = 20;
        let target = G1::generator() * Fr::from((1 << size) + (1 << (size / 2)));
        compute_dlog(target, size);
    }
}
