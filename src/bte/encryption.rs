use crate::bte::{crs::CRS, PPRF, PRF};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_std::rand::Rng;

pub struct Ciphertext<E: Pairing> {
    pub pprf: PPRF<E>,
    // encrypt key under the threshold scheme
    pub encrypted_key: E::ScalarField, //todo: replace this with the STE ciphertext
    pub mask: PairingOutput<E>,        // todo: message masked with bytes
}

/// Sample a key, puncture it at position, and mask message at that evalaution point.
pub fn encrypt<E: Pairing>(position: usize, crs: &CRS<E>, rng: &mut impl Rng) -> Ciphertext<E> {
    // sample a PRF key

    let prf = PRF::<E>::new(rng);

    // puncture the PRF at the given position
    let pprf = prf.puncture(position, &crs);

    Ciphertext {
        pprf: pprf,
        encrypted_key: prf.key, // todo: this should be replaced with the STE ciphertext
        mask: prf.eval(position, crs),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    type E = Bls12_381;

    #[test]
    fn test_encrypt() {
        let mut rng = test_rng();
        let crs = CRS::<E>::new(10, &mut rng);
        let position = 5;

        let ciphertext = encrypt(position, &crs, &mut rng);
        assert_eq!(ciphertext.pprf.point, position);
    }
}
