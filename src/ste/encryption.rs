use crate::ste::{aggregate::EncryptionKey, crs::CRS};
use crate::utils::{ark_de, ark_se};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    PrimeGroup,
};
use ark_serialize::*;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use ark_std::Zero;
use serde::{Deserialize, Serialize};
use std::ops::Mul;

#[derive(
    Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone, PartialEq,
)]
pub struct Ciphertext<E: Pairing> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sa1: [E::G1; 2],
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sa2: [E::G2; 6],
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub ct: Vec<PairingOutput<E>>, // key to be used for encapsulation (linearly homomorphic)
    // #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    // pub ct: Vec<u8>, //encrypted message
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub t: usize, //threshold
}

impl<E: Pairing> Ciphertext<E> {
    pub fn new(sa1: [E::G1; 2], sa2: [E::G2; 6], ct: Vec<PairingOutput<E>>, t: usize) -> Self {
        Ciphertext { sa1, sa2, ct, t }
    }

    pub fn add(&self, other: &Ciphertext<E>) -> Ciphertext<E> {
        assert_eq!(self.t, other.t, "Thresholds must match for addition");
        let sa1 = [self.sa1[0] + other.sa1[0], self.sa1[1] + other.sa1[1]];
        let sa2 = [
            self.sa2[0] + other.sa2[0],
            self.sa2[1] + other.sa2[1],
            self.sa2[2] + other.sa2[2],
            self.sa2[3] + other.sa2[3],
            self.sa2[4] + other.sa2[4],
            self.sa2[5] + other.sa2[5],
        ];
        let ct = self.ct.iter().zip(&other.ct).map(|(a, b)| a + b).collect();
        Ciphertext::new(sa1, sa2, ct, self.t)
    }

    pub fn zero(l: usize, t: usize) -> Self {
        Ciphertext {
            sa1: [E::G1::zero(); 2],
            sa2: [E::G2::zero(); 6],
            ct: vec![PairingOutput::<E>::zero(); l],
            t,
        }
    }
}

/// t is the threshold for encryption and apk is the aggregated public key
pub fn encrypt<E: Pairing>(
    ek: &EncryptionKey<E>,
    t: usize,
    crs: &CRS<E>,
    m: &Vec<PairingOutput<E>>,
    rng: &mut impl Rng,
) -> Ciphertext<E> {
    let mut sa1 = [E::G1::generator(); 2];
    let mut sa2 = [E::G2::generator(); 6];

    let s = (0..5)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    // s[0] = E::ScalarField::zero();
    // s[1] = E::ScalarField::zero();
    // s[2] = E::ScalarField::zero();
    // s[3] = E::ScalarField::zero();
    // s[4] = E::ScalarField::zero();

    // sa1[0] = s0*ask + s3*g^{tau^{t}} + s4*g
    sa1[0] = (ek.ask * s[0]) + (crs.powers_of_g[0][t] * s[3]) + (crs.powers_of_g[0][0] * s[4]);

    // sa1[1] = s2*g
    sa1[1] = crs.powers_of_g[0][0] * s[2];

    // sa2[0] = s0*h + s2*gamma_g2
    sa2[0] = (crs.powers_of_h[0][0] * s[0]) + (ek.gamma_g2[0] * s[2]);

    // sa2[1] = s0*z_g2
    sa2[1] = ek.z_g2 * s[0];

    // sa2[2] = s0*h^tau + s1*h^{tau^2}
    sa2[2] = crs.powers_of_h[0][1] * s[0] + crs.powers_of_h[0][2] * s[1];

    // sa2[3] = s1*h
    sa2[3] = crs.powers_of_h[0][0] * s[1];

    // sa2[4] = s3*h
    sa2[4] = crs.powers_of_h[0][0] * s[3];

    // sa2[5] = s4*h^{tau}
    sa2[5] = (crs.powers_of_h[0][1]) * s[4];

    // ct = s4*e_gh[i] + m[i]
    let mut ct = vec![PairingOutput::<E>::zero(); crs.l];
    for i in 0..crs.l {
        ct[i] = ek.e_gh[i].mul(s[4]) + m[i];
    }

    Ciphertext { sa1, sa2, ct, t }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ste::{
        aggregate::AggregateKey,
        crs::CRS,
        setup::{LagPublicKey, SecretKey},
    };

    type E = ark_bls12_381::Bls12_381;
    type G1 = <E as Pairing>::G1;
    type G2 = <E as Pairing>::G2;

    #[test]
    fn test_encryption() {
        let mut rng = ark_std::test_rng();
        let n = 8;
        let l = 2;
        let crs = CRS::new(n, l, &mut rng);

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<LagPublicKey<E>> = Vec::new();

        for i in 0..n {
            sk.push(SecretKey::<E>::new(&mut rng, i));
            pk.push(sk[i].get_lagrange_pk(i, &crs))
        }

        let (_ak, ek) = AggregateKey::<E>::new(pk, &crs);

        let m = vec![PairingOutput::<E>::generator(); crs.l];

        let ct = encrypt::<E>(&ek, n / 2, &crs, &m, &mut rng);

        let mut ct_bytes = Vec::new();
        ct.serialize_compressed(&mut ct_bytes).unwrap();
        println!("Compressed ciphertext: {} bytes", ct_bytes.len());

        let mut g1_bytes = Vec::new();
        let mut g2_bytes = Vec::new();
        let mut e_gh_bytes = Vec::new();

        let g = G1::generator();
        let h = G2::generator();

        g.serialize_compressed(&mut g1_bytes).unwrap();
        h.serialize_compressed(&mut g2_bytes).unwrap();
        ek.e_gh.serialize_compressed(&mut e_gh_bytes).unwrap();

        println!("G1 len: {} bytes", g1_bytes.len());
        println!("G2 len: {} bytes", g2_bytes.len());
        println!("GT len: {} bytes", e_gh_bytes.len());
    }
}
