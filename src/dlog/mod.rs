use ark_ec::PrimeGroup;
use ark_std::{end_timer, start_timer};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// Maximum exponent the BSGS solver can handle: inputs must be in `[0, 2^DLOG_RANGE_BITS)`.
///
/// The range follows the active chunk feature. `chunks-16` keeps the original
/// 25-bit range, while `chunks-8` uses 41 bits so 512 32-bit chunks can be
/// summed homomorphically.
#[cfg(feature = "chunks-16")]
pub const DLOG_RANGE_BITS: usize = 25;
#[cfg(feature = "chunks-8")]
pub const DLOG_RANGE_BITS: usize = 41;

/// Number of giant-step markers stored in the table.
#[cfg(feature = "chunks-16")]
pub const DLOG_MARKER_BITS: usize = 13;
#[cfg(feature = "chunks-8")]
pub const DLOG_MARKER_BITS: usize = 20;

/// Number of baby steps at solve time. Must equal `DLOG_RANGE_BITS - DLOG_MARKER_BITS`.
pub const DLOG_STEP_BITS: usize = DLOG_RANGE_BITS - DLOG_MARKER_BITS;

/// Byte width for hash-map keys: first 16 bytes of the uncompressed point serialization.
pub const DLOG_KEY_BYTES: usize = 16;

/// Largest value a single chunk limb can take (`2^chunk_bits − 1`).
#[inline]
pub fn max_chunk_value(chunk_bits: u32) -> u128 {
    assert!(chunk_bits < 128, "chunk_bits must be < 128");
    (1u128 << chunk_bits) - 1
}

/// Maximum exponent the DLog solver can recover (`2^range_bits − 1`).
#[inline]
pub fn max_dlog_exponent(range_bits: usize) -> u128 {
    assert!(range_bits < 128, "range_bits must be < 128");
    (1u128 << range_bits) - 1
}

/// How many ciphertexts can be homomorphically summed without overflowing the DLog range per slot.
///
/// Each ciphertext contributes one chunk per slot; each chunk is in `[0, 2^chunk_bits − 1]`. After
/// adding `B` ciphertexts, a slot sum is at most `B · (2^chunk_bits − 1)`. We require that to be
/// `≤ 2^range_bits − 1` so `compute_dlog` can recover it.
#[inline]
pub fn max_homomorphic_batch_size(chunk_bits: u32, range_bits: usize) -> usize {
    let m = max_chunk_value(chunk_bits);
    let cap = max_dlog_exponent(range_bits);
    if m == 0 {
        return usize::MAX;
    }
    (cap / m) as usize
}

/// Panics if `batch_size` exceeds [`max_homomorphic_batch_size`] for the given parameters.
#[inline]
pub fn assert_homomorphic_batch_safe(batch_size: usize, chunk_bits: u32, range_bits: usize) {
    let max_b = max_homomorphic_batch_size(chunk_bits, range_bits);
    assert!(
        batch_size <= max_b,
        "homomorphic batch too large: batch_size={} but at most {} ciphertexts may be summed \
         (each {}-bit chunk limb is at most {}; {} limbs sum to at most {} > 2^{}−1)",
        batch_size,
        max_b,
        chunk_bits,
        max_chunk_value(chunk_bits),
        batch_size,
        batch_size as u128 * max_chunk_value(chunk_bits),
        range_bits,
    );
}

fn point_key_into<G: PrimeGroup>(p: &G, buf: &mut Vec<u8>) -> [u8; DLOG_KEY_BYTES] {
    buf.clear();
    p.serialize_uncompressed(&mut *buf).unwrap();
    buf[0..DLOG_KEY_BYTES].try_into().expect("slice length")
}

/// Baby-step / giant-step DLog solver for exponents in `[0, 2^log_max_input)`.
///
/// Giant steps are at multiples of `2^log_bases` (i.e. `g^{j · 2^log_bases}` for `j = 0..2^log_markers`).
/// At solve time, `2^log_bases` baby steps are taken from the target, and each is checked against
/// the stored giants.
///
/// Storage: `O(2^log_markers)` hash-map entries.
/// Solve:   `O(2^log_bases)` group additions + hash lookups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Markers<G: PrimeGroup> {
    pub log_max_input: usize,
    pub log_markers: usize,
    markers_map: std::collections::HashMap<[u8; DLOG_KEY_BYTES], usize>,
    _phantom: PhantomData<G>,
}

impl<G: PrimeGroup> Markers<G> {
    /// Builds a BSGS table using the default parameters ([`DLOG_RANGE_BITS`], [`DLOG_MARKER_BITS`]).
    pub fn new() -> Self {
        Self::with_params(DLOG_RANGE_BITS, DLOG_MARKER_BITS)
    }

    /// Builds a BSGS table with custom parameters.
    ///
    /// `log_max_input` = total range bits, `log_markers` = giant-step count bits.
    /// Baby-step count = `2^(log_max_input - log_markers)`.
    pub fn with_params(log_max_input: usize, log_markers: usize) -> Self {
        assert!(
            log_max_input >= log_markers,
            "log_max_input must be >= log_markers"
        );
        let log_bases = log_max_input - log_markers;

        let timer = start_timer!(|| format!(
            "computing BSGS markers (2^{} giants, 2^{} babies)",
            log_markers, log_bases
        ));

        let step = G::generator() * G::ScalarField::from(1u64 << log_bases);
        let mut marker = G::zero();
        let num_markers = (1usize << log_markers) + 1;
        let mut markers_map = std::collections::HashMap::with_capacity(num_markers);
        let mut buf = Vec::with_capacity(1024);

        markers_map.insert(point_key_into(&marker, &mut buf), 0);
        for i in 1..num_markers {
            marker += step;
            markers_map.insert(point_key_into(&marker, &mut buf), i);
        }
        end_timer!(timer);

        Self {
            log_max_input,
            log_markers,
            markers_map,
            _phantom: PhantomData,
        }
    }

    pub fn save_to_file(&self, path: &str) {
        let file = std::fs::File::create(path).unwrap();
        let mut writer = std::io::BufWriter::new(file);
        bincode::serialize_into(&mut writer, self).unwrap();
    }

    pub fn read_from_file(path: &str) -> Self {
        let file = std::fs::File::open(path).unwrap();
        let reader = std::io::BufReader::new(file);
        bincode::deserialize_from(reader).unwrap()
    }

    /// Solves `target = g^x` for `x ∈ [0, 2^log_max_input)` via baby-step / giant-step.
    ///
    /// Takes `2^log_bases` baby steps from the target, checking each against the stored giants.
    /// Returns `None` if the exponent is out of range.
    pub fn compute_dlog(&self, target: &G) -> Option<G::ScalarField> {
        let log_bases = self.log_max_input - self.log_markers;
        let num_steps = 1usize << log_bases;
        let gen = G::generator();
        let mut buf = Vec::with_capacity(1024);

        let mut dart = *target + gen;
        for i in 0..num_steps {
            let key = point_key_into(&dart, &mut buf);
            if let Some(&j) = self.markers_map.get(&key) {
                let x = (j << log_bases).wrapping_sub(i).wrapping_sub(1);
                return Some(G::ScalarField::from(x as u128));
            }
            dart += gen;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::pairing::{Pairing, PairingOutput};

    type E = ark_bls12_381::Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    type GT = PairingOutput<E>;

    #[test]
    fn test_compute_dlog() {
        let path = format!(
            "markers_bsgs_test_{}_{}.bin",
            DLOG_RANGE_BITS, DLOG_MARKER_BITS
        );

        let should_be_dlog = Fr::from(100u64);
        let target = GT::generator() * should_be_dlog;

        let timer = start_timer!(|| "loading markers");
        let markers = if std::path::Path::new(&path).exists() {
            Markers::<GT>::read_from_file(&path)
        } else {
            let m = Markers::<GT>::new();
            m.save_to_file(&path);
            m
        };
        end_timer!(timer);

        let computed_dlog = markers.compute_dlog(&target).unwrap();
        assert_eq!(computed_dlog, should_be_dlog);
    }

    #[test]
    fn test_compute_dlog_large() {
        let markers = Markers::<GT>::new();
        // 512 ciphertexts × max 16-bit chunk = 512 * 65535 = 33_553_920
        let large_val = 33_553_920u128;
        let target = GT::generator() * Fr::from(large_val);
        let result = markers.compute_dlog(&target).unwrap();
        assert_eq!(result, Fr::from(large_val));
    }

    #[test]
    fn max_batch_with_bsgs() {
        assert_eq!(
            max_homomorphic_batch_size(crate::bte::encryption::CHUNK_BITS, DLOG_RANGE_BITS),
            512
        );
        assert_eq!(
            max_homomorphic_batch_size(8, DLOG_RANGE_BITS),
            (max_dlog_exponent(DLOG_RANGE_BITS) / max_chunk_value(8)) as usize
        );
    }
}
