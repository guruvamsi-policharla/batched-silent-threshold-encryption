use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::PrimeGroup;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use ark_std::Zero;

pub mod crs;
pub mod decryption;
pub mod encryption;
use crate::bte::crs::CRS;

#[derive(Clone, Debug)]
pub struct PRF<E: Pairing> {
    pub key: E::ScalarField,
}

impl<E: Pairing> PRF<E> {
    pub fn new(rng: &mut impl Rng) -> Self {
        let key = E::ScalarField::rand(rng);

        Self { key }
    }

    pub fn from_key(key: E::ScalarField) -> Self {
        Self { key }
    }

    pub fn eval(&self, input: usize, crs: &CRS<E>) -> PairingOutput<E> {
        if input >= crs.batch_size {
            panic!("input must be smaller than batch_size");
        } else if input == 0 {
            return crs.gt_nplus1 * self.key;
        } else {
            return E::pairing(
                crs.powers_of_g[crs.batch_size + 1 + input] * self.key,
                E::G2::generator(),
            );
        }
    }

    pub fn puncture(&self, point: usize, crs: &CRS<E>) -> PPRF<E> {
        if point >= crs.batch_size {
            panic!("puncture point must be smaller than batch_size");
        } else {
            return PPRF {
                key: crs.powers_of_g[point] * self.key,
                point,
            };
        }
    }
}

#[derive(Clone, Debug)]
pub struct PPRF<E: Pairing> {
    pub key: E::G1,
    pub point: usize,
}

impl<E: Pairing> PPRF<E> {
    pub fn eval(&self, input: usize, crs: &CRS<E>) -> PairingOutput<E> {
        if input == crs.batch_size + 1 || input == self.point {
            panic!(
                "invalid input to puncture PRF: {}, punctured at {}",
                input, self.point
            );
        } else {
            return E::pairing(
                self.key,
                crs.powers_of_h[crs.batch_size + 1 + input - self.point],
            );
        }
    }
}

/// returns the aggregation of the evaluation of batch_size different PPRFs at `input`
pub fn batch_eval<E: Pairing>(
    pprfs: &Vec<PPRF<E>>,
    input: usize,
    crs: &CRS<E>,
) -> PairingOutput<E> {
    let lhs = pprfs.iter().map(|pprf| pprf.key).collect::<Vec<_>>();

    let rhs = pprfs
        .iter()
        .map(|pprf| crs.powers_of_h[crs.batch_size + 1 + input - pprf.point])
        .collect::<Vec<_>>();

    E::multi_pairing(lhs, rhs)
}

/// returns the aggregation of the evaluation of batch_size different PPRFs at `input`
pub fn naive_batch_eval<E: Pairing>(
    pprfs: &Vec<PPRF<E>>,
    input: usize,
    crs: &CRS<E>,
) -> PairingOutput<E> {
    let mut res = PairingOutput::<E>::zero();
    for pprf in pprfs.iter() {
        res += E::pairing(
            pprf.key,
            crs.powers_of_h[crs.batch_size + 1 + input - pprf.point],
        );
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_puncture() {
        let mut rng = test_rng();
        let batch_size = 10;
        let crs = CRS::<Bls12_381>::new(batch_size, &mut rng);
        let prf = PRF::<Bls12_381>::new(&mut rng);

        let point = 3;
        let pprf = prf.puncture(point, &crs);

        let input = 5;
        let output = prf.eval(input, &crs);
        let punctured_output = pprf.eval(input, &crs);

        assert_eq!(output, punctured_output);
    }

    #[test]
    fn test_homomorphism() {
        let mut rng = test_rng();
        let batch_size = 10;
        let crs = CRS::<Bls12_381>::new(batch_size, &mut rng);

        let prf1 = PRF::<Bls12_381>::new(&mut rng);
        let prf2 = PRF::<Bls12_381>::new(&mut rng);

        let input = 7;
        let output = prf1.eval(input, &crs) + prf2.eval(input, &crs);

        let agg_key = prf1.key + prf2.key;
        let agg_prf = PRF::<Bls12_381>::from_key(agg_key);

        let agg_output = agg_prf.eval(input, &crs);
        assert_eq!(output, agg_output);

        let point1 = 3;
        let point2 = 5;
        let pprf1 = prf1.puncture(point1, &crs);
        let pprf2 = prf2.puncture(point2, &crs);

        let output = batch_eval(&vec![pprf1, pprf2], input, &crs);

        assert_eq!(output, agg_output);
    }
}
