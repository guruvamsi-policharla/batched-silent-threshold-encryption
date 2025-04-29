use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::{One, Zero};

use ark_ec::AffineRepr;
use ark_ec::ScalarMul;
use ark_std::rand::Rng;
use ark_std::UniformRand;

#[derive(Clone, Debug)]
pub struct CRS<E: Pairing> {
    // contains g^{x^i} at positions i = 0, 1, ...,n, n+2, ..., 2*n
    // at position i = n+1, contains g^0
    pub powers_of_g: Vec<E::G1>,
    pub powers_of_h: Vec<E::G2>,
    pub n: usize,
}

impl<E: Pairing> CRS<E> {
    pub fn new(n: usize, rng: &mut impl Rng) -> Self {
        let x = E::ScalarField::rand(rng);
        let mut powers_of_x = vec![E::ScalarField::one()];

        let mut cur = x;
        for _ in 0..=2 * n {
            powers_of_x.push(cur);
            cur *= &x;
        }
        // at position i = n+1, contains 0
        powers_of_x[n + 1] = E::ScalarField::zero();

        let powers_of_g_affine = E::G1::generator().batch_mul(&powers_of_x[0..2 * n]);
        let powers_of_g = powers_of_g_affine
            .iter()
            .map(|g| g.into_group())
            .collect::<Vec<_>>();

        let powers_of_h_affine = E::G2::generator().batch_mul(&powers_of_x[0..2 * n]);
        let powers_of_h = powers_of_h_affine
            .iter()
            .map(|h| h.into_group())
            .collect::<Vec<_>>();

        Self {
            powers_of_g,
            powers_of_h,
            n,
        }
    }
}
