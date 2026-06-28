use ark_ff::PrimeField;
use ark_serialize::{CanonicalSerialize, Compress};
use merlin::Transcript;

/// Append an arkworks value using canonical compressed serialization.
pub fn append_serializable<T: CanonicalSerialize>(
    transcript: &mut Transcript,
    label: &'static [u8],
    value: &T,
) {
    let mut bytes = Vec::new();
    value
        .serialize_with_mode(&mut bytes, Compress::Yes)
        .expect("canonical serialization should not fail for transcript input");
    transcript.append_message(label, &bytes);
}

pub fn append_usize(transcript: &mut Transcript, label: &'static [u8], value: usize) {
    transcript.append_message(label, &(value as u64).to_le_bytes());
}

pub fn challenge_scalar<F: PrimeField>(transcript: &mut Transcript, label: &'static [u8]) -> F {
    let mut bytes = [0u8; 64];
    transcript.challenge_bytes(label, &mut bytes);
    F::from_le_bytes_mod_order(&bytes)
}

pub fn challenge_scalar_not_in_subgroup<F: PrimeField>(
    transcript: &mut Transcript,
    label: &'static [u8],
    subgroup_size: usize,
) -> F {
    for counter in 0u64.. {
        let mut bytes = [0u8; 64];
        transcript.append_message(b"reject-counter", &counter.to_le_bytes());
        transcript.challenge_bytes(label, &mut bytes);
        let candidate = F::from_le_bytes_mod_order(&bytes);
        if !candidate.is_zero() && candidate.pow(&[subgroup_size as u64]) != F::one() {
            return candidate;
        }
    }

    unreachable!("unbounded loop must eventually sample outside a small subgroup")
}
