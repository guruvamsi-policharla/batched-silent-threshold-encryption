use super::crs::CRS;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::PrimeGroup;
use ark_std::rand::Rng;
use ark_std::UniformRand;

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
        if input == crs.n + 1 {
            panic!("input cannot be n+1");
        } else {
            return E::pairing(
                crs.powers_of_g[crs.n + 1 + input] * self.key,
                E::G2::generator(),
            );
        }
    }

    pub fn puncture(&self, point: usize, crs: &CRS<E>) -> PPRF<E> {
        if point == crs.n + 1 {
            panic!("puncture point cannot be n+1");
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
        if input == crs.n + 1 || input == self.point {
            panic!(
                "invalid input to puncture PRF: {}, punctured at {}",
                input, self.point
            );
        } else {
            return E::pairing(self.key, crs.powers_of_h[crs.n + 1 + input - self.point]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_puncture() {
        let mut rng = test_rng();
        let n = 10;
        let crs = CRS::<Bls12_381>::new(n, &mut rng);
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
        let n = 10;
        let crs = CRS::<Bls12_381>::new(n, &mut rng);

        let prf1 = PRF::<Bls12_381>::new(&mut rng);
        let prf2 = PRF::<Bls12_381>::new(&mut rng);

        let input = 7;
        let output = prf1.eval(input, &crs) + prf2.eval(input, &crs);

        let agg_key = prf1.key + prf2.key;
        let agg_prf = PRF::<Bls12_381>::from_key(agg_key);

        let agg_output = agg_prf.eval(input, &crs);
        assert_eq!(output, agg_output);
    }
}
