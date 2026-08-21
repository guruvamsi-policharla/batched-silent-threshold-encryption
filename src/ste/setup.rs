use crate::bte;
use crate::ste::crs::CRS;
use crate::ste::encryption::Ciphertext;
use crate::ste::utils::{lagrange_poly, open_all_values};
use ark_ec::{pairing::Pairing, AffineRepr, VariableBaseMSM};
use ark_ff::{FftField, PrimeField};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_serialize::*;
use ark_std::{rand::RngCore, UniformRand, Zero};
use sha2::{Digest, Sha256};

use crate::utils::{ark_de, ark_se};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct LagPolys<F: FftField> {
    pub l: Vec<DensePolynomial<F>>,
    pub l_minus0: Vec<DensePolynomial<F>>,
    pub l_x: Vec<DensePolynomial<F>>,
    pub li_lj_z: Vec<Vec<DensePolynomial<F>>>,
    pub denom: F,
}

impl<F: FftField> LagPolys<F> {
    // domain is the roots of unity of size n
    pub fn new(n: usize) -> Self {
        let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();

        // compute polynomial L_i(X)
        let mut l = vec![DensePolynomial::zero(); n];
        for i in 0..n {
            l[i] = lagrange_poly(n, i);
        }

        // compute polynomial (L_i(X) - L_i(0))*X
        let mut l_minus0 = vec![DensePolynomial::zero(); n];
        for i in 0..n {
            let mut li_minus0_coeffs = l[i].coeffs.clone();
            li_minus0_coeffs[0] = F::zero();
            li_minus0_coeffs.insert(0, F::zero());
            l_minus0[i] = DensePolynomial::from_coefficients_vec(li_minus0_coeffs);
        }

        // compute polynomial (L_i(X) - L_i(0))/X
        let mut l_x = vec![DensePolynomial::zero(); n];
        for i in 0..n {
            l_x[i] = DensePolynomial::from_coefficients_vec(l_minus0[i].coeffs[2..].to_vec());
        }

        // compute polynomial L_i(X)*L_j(X)/Z(X) and (L_i(X)*L_i(X) - L_i(X))/Z(X)
        let mut li_lj_z = vec![vec![DensePolynomial::zero(); n]; n];
        for i in 0..n {
            for j in 0..n {
                li_lj_z[i][j] = if i == j {
                    (&l[i] * &l[i] - &l[i]).divide_by_vanishing_poly(domain).0
                } else {
                    (&l[i] * &l[j]).divide_by_vanishing_poly(domain).0
                };
            }
        }

        let mut denom = F::one();
        for i in 1..n {
            denom *= F::one() - domain.element(i);
        }

        // for i in 0..n {
        //     for j in 0..n {
        //         let monomial =
        //             DensePolynomial::from_coefficients_vec(vec![-domain.element(j), F::one()]);

        //         let computed = &l[i] / &monomial;
        //         assert_eq!(
        //             li_lj_z[i][j].evaluate(&F::zero()),
        //             computed.evaluate(&F::zero()) / (denom * domain.element(n - j))
        //         );
        //     }
        // }

        Self {
            l,
            l_minus0,
            l_x,
            li_lj_z,
            denom: denom.inverse().unwrap(),
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone)]
pub struct SecretKey<E: Pairing> {
    pub id: usize,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    sk: E::ScalarField,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PartialDecryption<E: Pairing> {
    /// Party id
    pub id: usize,
    /// Party commitment
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub pd: E::G1, // sk * (s_3 * [1]_1)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PartialDecryptionProof<E: Pairing> {
    // Fiat-Shamir challenge. The first-round commitments are reconstructed by
    // the verifier from `z_sk`, the public statement, and this challenge.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub challenge: E::ScalarField,
    // Schnorr response z = r + challenge * sk.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub z_sk: E::ScalarField,
}

impl<E: Pairing> PartialDecryption<E> {
    pub fn zero() -> Self {
        PartialDecryption {
            id: 0,
            pd: E::G1::zero(),
        }
    }
}

struct PartialDecryptionCommitments<E: Pairing> {
    a_pk: E::G1,
    a_pd: E::G1,
}

impl<E: Pairing> PartialDecryptionProof<E> {
    pub fn verify(
        &self,
        partial_decryption: &PartialDecryption<E>,
        ct: &Ciphertext<E>,
        public_key: &LagPublicKey<E>,
        crs: &CRS<E>,
    ) -> bool {
        let ciphertext_digest = partial_decryption_ciphertext_digest(ct);
        self.verify_for_base(
            partial_decryption,
            ct.sa1[1],
            &ciphertext_digest,
            public_key,
            crs,
        )
    }

    pub fn verify_batch(
        &self,
        partial_decryption: &PartialDecryption<E>,
        cts: &[bte::encryption::Ciphertext<E>],
        public_key: &LagPublicKey<E>,
        crs: &CRS<E>,
    ) -> bool {
        if cts.is_empty() {
            return false;
        }
        let ciphertext_digest = batch_partial_decryption_ciphertext_digest(cts);
        self.verify_for_base(
            partial_decryption,
            batch_partial_decryption_base(cts),
            &ciphertext_digest,
            public_key,
            crs,
        )
    }

    fn verify_for_base(
        &self,
        partial_decryption: &PartialDecryption<E>,
        decryption_base: E::G1,
        ciphertext_digest: &[u8; 32],
        public_key: &LagPublicKey<E>,
        crs: &CRS<E>,
    ) -> bool {
        if !valid_partial_decryption_statement(partial_decryption, public_key, crs) {
            return false;
        }

        // Compact Schnorr reconstruction:
        //   A_pk = gen_g[0] * z - pk * c
        //   A_pd = decryption_base * z - pd * c
        // If z = r + c*sk and the statement is honest, these are exactly the
        // prover's first-round commitments gen_g[0]*r and decryption_base*r.
        let commitments = PartialDecryptionCommitments {
            a_pk: crs.gen_g[0] * self.z_sk - public_key.bls_pk[0] * self.challenge,
            a_pd: decryption_base * self.z_sk - partial_decryption.pd * self.challenge,
        };
        let challenge = partial_decryption_challenge(
            partial_decryption,
            decryption_base,
            ciphertext_digest,
            public_key,
            crs,
            &commitments,
        );
        challenge == self.challenge
    }
}

fn valid_partial_decryption_statement<E: Pairing>(
    partial_decryption: &PartialDecryption<E>,
    public_key: &LagPublicKey<E>,
    crs: &CRS<E>,
) -> bool {
    partial_decryption.id == public_key.id
        && public_key.position < crs.n
        && !crs.gen_g.is_empty()
        && !public_key.bls_pk.is_empty()
}

fn batch_partial_decryption_base<E: Pairing>(cts: &[bte::encryption::Ciphertext<E>]) -> E::G1 {
    cts.iter().map(|c| c.encrypted_key.sa1[1]).sum::<E::G1>()
}

fn partial_decryption_ciphertext_digest<E: Pairing>(ct: &Ciphertext<E>) -> [u8; 32] {
    let mut transcript = PartialDecryptionTranscript::new(b"STE-PARTIAL-DECRYPTION-CT-V1");
    transcript.append_serializable(b"ciphertext", ct);
    transcript.finalize()
}

fn batch_partial_decryption_ciphertext_digest<E: Pairing>(
    cts: &[bte::encryption::Ciphertext<E>],
) -> [u8; 32] {
    let mut transcript = PartialDecryptionTranscript::new(b"STE-BATCH-PARTIAL-DECRYPTION-CT-V1");
    transcript.append_usize(b"num_ciphertexts", cts.len());
    for ct in cts {
        transcript.append_serializable(b"encrypted_key", &ct.encrypted_key);
    }
    transcript.finalize()
}

fn partial_decryption_challenge<E: Pairing>(
    partial_decryption: &PartialDecryption<E>,
    decryption_base: E::G1,
    ciphertext_digest: &[u8; 32],
    public_key: &LagPublicKey<E>,
    crs: &CRS<E>,
    commitments: &PartialDecryptionCommitments<E>,
) -> E::ScalarField {
    let mut transcript = PartialDecryptionTranscript::new(b"STE-PARTIAL-DECRYPTION-SCHNORR-V1");
    transcript.append_usize(b"crs_n", crs.n);
    transcript.append_usize(b"crs_l", crs.l);
    transcript.append_serializable(b"public_generator", &crs.gen_g[0]);
    transcript.append_usize(b"party_id", public_key.id);
    transcript.append_usize(b"party_position", public_key.position);
    transcript.append_serializable(b"public_key", &public_key.bls_pk[0]);
    transcript.append_usize(b"partial_decryption_id", partial_decryption.id);
    transcript.append_serializable(b"decryption_base", &decryption_base);
    transcript.append_serializable(b"partial_decryption", &partial_decryption.pd);
    transcript.append_bytes(b"ciphertext_digest", ciphertext_digest);
    transcript.append_serializable(b"a_pk", &commitments.a_pk);
    transcript.append_serializable(b"a_pd", &commitments.a_pd);
    E::ScalarField::from_le_bytes_mod_order(&transcript.finalize())
}

struct PartialDecryptionTranscript {
    hasher: Sha256,
}

impl PartialDecryptionTranscript {
    fn new(domain: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        Self { hasher }
    }

    fn append_label(&mut self, label: &[u8]) {
        self.hasher.update((label.len() as u64).to_le_bytes());
        self.hasher.update(label);
    }

    fn append_usize(&mut self, label: &[u8], value: usize) {
        self.append_label(label);
        self.hasher.update((value as u64).to_le_bytes());
    }

    fn append_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        self.append_label(label);
        self.hasher.update((bytes.len() as u64).to_le_bytes());
        self.hasher.update(bytes);
    }

    fn append_serializable<T: CanonicalSerialize>(&mut self, label: &[u8], value: &T) {
        self.append_label(label);
        let mut bytes = Vec::new();
        value
            .serialize_compressed(&mut bytes)
            .expect("canonical serialization should succeed");
        self.hasher.update((bytes.len() as u64).to_le_bytes());
        self.hasher.update(bytes);
    }

    fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

/// Position oblivious public key -- slower to aggregate
#[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub bls_pk: Vec<E::G1>, //BLS pk
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub hints: Vec<Vec<E::G1Affine>>, //hints
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub y: Vec<Vec<E::G1Affine>>, // preprocessed toeplitz matrix. only for efficiency and can be computed from hints
    pub id: usize, // canonically assigned unique id in the system
}

/// Public key that can only be used in a fixed position -- faster to aggregate
#[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone)]
pub struct LagPublicKey<E: Pairing> {
    pub id: usize,       //id of the party
    pub position: usize, //position in the aggregate key
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub bls_pk: Vec<E::G1>, //BLS pk
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sk_li: Vec<E::G1>, //hint
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sk_li_minus0: Vec<E::G1>, //hint
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sk_li_lj_z: Vec<Vec<E::G1>>, //hint
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sk_li_x: Vec<E::G1>, //hint
}

impl<E: Pairing> LagPublicKey<E> {
    pub fn new(
        id: usize,
        position: usize,
        bls_pk: Vec<E::G1>,
        sk_li: Vec<E::G1>,
        sk_li_minus0: Vec<E::G1>,
        sk_li_lj_z: Vec<Vec<E::G1>>, //i = id
        sk_li_x: Vec<E::G1>,
    ) -> Self {
        LagPublicKey {
            id,
            position,
            bls_pk,
            sk_li,
            sk_li_minus0,
            sk_li_lj_z,
            sk_li_x,
        }
    }
}

impl<E: Pairing> SecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R, id: usize) -> Self {
        SecretKey {
            id,
            sk: E::ScalarField::rand(rng),
        }
    }

    pub fn from_scalar(sk: E::ScalarField, id: usize) -> Self {
        SecretKey { id, sk }
    }

    pub fn get_pk(&self, crs: &CRS<E>) -> PublicKey<E> {
        let mut hints = vec![vec![E::G1Affine::zero(); crs.n + 1]; crs.l];
        let bls_pk = crs.gen_g.iter().map(|&g| g * self.sk).collect::<Vec<_>>();

        for j in 0..crs.l {
            for i in 0..crs.n + 1 {
                hints[j][i] = (crs.powers_of_g[j][i] * self.sk).into();
            }
        }

        // compute y
        let mut y = vec![vec![E::G1Affine::zero(); 2 * crs.n]; crs.l];
        for j in 0..crs.l {
            for i in 0..2 * crs.n {
                y[j][i] = (crs.y[j][i] * self.sk).into();
            }
        }

        PublicKey {
            id: self.id,
            bls_pk,
            hints,
            y,
        }
    }

    pub fn get_lagrange_pk(&self, position: usize, crs: &CRS<E>) -> LagPublicKey<E> {
        let bls_pk = crs.gen_g.iter().map(|&g| g * self.sk).collect::<Vec<_>>();

        let sk_li = crs
            .li
            .iter()
            .map(|li| li[position] * self.sk)
            .collect::<Vec<_>>();

        let sk_li_minus0 = crs
            .li_minus0
            .iter()
            .map(|li_minus0| li_minus0[position] * self.sk)
            .collect::<Vec<_>>();

        let sk_li_x = crs
            .li_x
            .iter()
            .map(|li_x| li_x[position] * self.sk)
            .collect::<Vec<_>>();

        let mut sk_li_lj_z = vec![vec![E::G1::zero(); crs.n]; crs.l];
        for k in 0..crs.l {
            for j in 0..crs.n {
                sk_li_lj_z[k][j] = crs.li_lj_z[k][position][j] * self.sk;
            }
        }

        LagPublicKey {
            id: self.id,
            position,
            bls_pk,
            sk_li,
            sk_li_minus0,
            sk_li_lj_z,
            sk_li_x,
        }
    }

    pub fn partial_decryption(&self, ct: &Ciphertext<E>) -> PartialDecryption<E> {
        PartialDecryption {
            id: self.id,
            pd: ct.sa1[1] * self.sk,
        }
    }

    pub fn partial_decryption_with_proof(
        &self,
        ct: &Ciphertext<E>,
        public_key: &LagPublicKey<E>,
        crs: &CRS<E>,
        rng: &mut impl RngCore,
    ) -> (PartialDecryption<E>, PartialDecryptionProof<E>) {
        let partial_decryption = self.partial_decryption(ct);
        let ciphertext_digest = partial_decryption_ciphertext_digest(ct);
        let proof = self.partial_decryption_proof_for_base(
            &partial_decryption,
            ct.sa1[1],
            &ciphertext_digest,
            public_key,
            crs,
            rng,
        );
        (partial_decryption, proof)
    }

    pub fn batch_partial_decryption(
        &self,
        ct: &Vec<bte::encryption::Ciphertext<E>>,
    ) -> PartialDecryption<E> {
        let pd: E::G1 = ct.iter().map(|c| c.encrypted_key.sa1[1]).sum::<E::G1>() * self.sk;

        PartialDecryption { id: self.id, pd }
    }

    pub fn batch_partial_decryption_with_proof(
        &self,
        ct: &[bte::encryption::Ciphertext<E>],
        public_key: &LagPublicKey<E>,
        crs: &CRS<E>,
        rng: &mut impl RngCore,
    ) -> (PartialDecryption<E>, PartialDecryptionProof<E>) {
        assert!(
            !ct.is_empty(),
            "cannot prove an empty batch partial decryption"
        );

        let partial_decryption = PartialDecryption {
            id: self.id,
            pd: batch_partial_decryption_base(ct) * self.sk,
        };
        let ciphertext_digest = batch_partial_decryption_ciphertext_digest(ct);
        let proof = self.partial_decryption_proof_for_base(
            &partial_decryption,
            batch_partial_decryption_base(ct),
            &ciphertext_digest,
            public_key,
            crs,
            rng,
        );
        (partial_decryption, proof)
    }

    fn partial_decryption_proof_for_base(
        &self,
        partial_decryption: &PartialDecryption<E>,
        decryption_base: E::G1,
        ciphertext_digest: &[u8; 32],
        public_key: &LagPublicKey<E>,
        crs: &CRS<E>,
        rng: &mut impl RngCore,
    ) -> PartialDecryptionProof<E> {
        assert_eq!(
            self.id, public_key.id,
            "partial decryption proof must use the prover's public key"
        );
        assert!(
            valid_partial_decryption_statement(partial_decryption, public_key, crs),
            "invalid partial decryption proof statement"
        );

        let r = E::ScalarField::rand(rng);
        let commitments = PartialDecryptionCommitments {
            a_pk: crs.gen_g[0] * r,
            a_pd: decryption_base * r,
        };
        let challenge = partial_decryption_challenge(
            partial_decryption,
            decryption_base,
            ciphertext_digest,
            public_key,
            crs,
            &commitments,
        );
        let z_sk = r + challenge * self.sk;

        PartialDecryptionProof { challenge, z_sk }
    }
}

impl<E: Pairing> PublicKey<E> {
    pub fn get_lag_public_key(
        &self,
        position: usize,
        crs: &CRS<E>,
        lag_polys: &LagPolys<E::ScalarField>,
    ) -> LagPublicKey<E> {
        assert!(position < crs.n, "position out of bounds");

        let bls_pk = self.bls_pk.clone();

        // compute sk_li
        let mut sk_li = vec![E::G1::zero(); crs.l];
        for j in 0..crs.l {
            sk_li[j] = E::G1::msm(
                &self.hints[j][0..lag_polys.l[position].degree() + 1],
                &lag_polys.l[position],
            )
            .unwrap();
        }

        // compute sk_li_minus0
        let mut sk_li_minus0 = vec![E::G1::zero(); crs.l];
        for j in 0..crs.l {
            sk_li_minus0[j] = E::G1::msm(
                &self.hints[j][0..lag_polys.l_minus0[position].degree() + 1],
                &lag_polys.l_minus0[position],
            )
            .unwrap();
        }

        // compute sk_li_x
        let mut sk_li_x = vec![E::G1::zero(); crs.l];
        for j in 0..crs.l {
            sk_li_x[j] = E::G1::msm(
                &self.hints[j][0..lag_polys.l_x[position].degree() + 1],
                &lag_polys.l_x[position],
            )
            .unwrap();
        }

        // compute sk*Li*Lj/Z = sk*Li/(X-omega^j)*(omega^j/denom) for all j in [n]\{i}
        // for j = i: (Li^2 - Li)/Z = (Li - 1)/(X-omega^i)*(omega^i/denom)
        // this is the same as computing KZG opening proofs at all points
        // in the roots of unity domain for the polynomial Li(X), where the
        // crs is {g^sk, g^{sk * tau}, g^{sk * tau^2}, ...}
        // todo: optimize and maybe move to https://eprint.iacr.org/2024/1279.pdf
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(crs.n).unwrap();
        let mut sk_li_lj_z = vec![vec![E::G1::zero(); crs.n]; crs.l];
        for k in 0..crs.l {
            sk_li_lj_z[k] =
                open_all_values::<E>(&self.y[k], &lag_polys.l[position].coeffs, &domain);
            for j in 0..crs.n {
                sk_li_lj_z[k][j] *= domain.element(j) * lag_polys.denom;
            }
        }

        // // compute sk_li_lj_z
        // let mut sk_li_lj_z = vec![E::G1::zero(); crs.n];

        // let timer = start_timer!(|| "msm version");
        // for j in 0..crs.n {
        //     sk_li_lj_z[j] = E::G1::msm(
        //         &self.hints[0..lag_polys.li_lj_z[id][j].degree() + 1],
        //         &lag_polys.li_lj_z[id][j],
        //     )
        //     .unwrap();
        // }
        // end_timer!(timer);

        // assert_eq!(sk_li_lj_z, my_sk_li_lj_z);

        LagPublicKey {
            id: self.id,
            position,
            bls_pk,
            sk_li,
            sk_li_minus0,
            sk_li_lj_z,
            sk_li_x,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ste::aggregate::AggregateKey;
    use ark_ec::pairing::PairingOutput;
    type E = ark_bls12_381::Bls12_381;
    type F = ark_bls12_381::Fr;

    #[test]
    fn test_setup() {
        let mut rng = ark_std::test_rng();
        let n = 1 << 4;
        let l = 8;
        let crs = CRS::<E>::new(n, l, &mut rng);

        assert_eq!(crs.gen_g.len(), l);
        assert_eq!(crs.gen_h.len(), l);

        assert_eq!(crs.powers_of_g.len(), l);
        assert_eq!(crs.powers_of_g[0].len(), n + 1);

        assert_eq!(crs.powers_of_h.len(), l);
        assert_eq!(crs.powers_of_h[0].len(), n + 1);

        assert_eq!(crs.li.len(), l);
        assert_eq!(crs.li[0].len(), n);

        assert_eq!(crs.li_minus0.len(), l);
        assert_eq!(crs.li_minus0[0].len(), n);

        assert_eq!(crs.li_x.len(), l);
        assert_eq!(crs.li_x[0].len(), n);

        assert_eq!(crs.li_lj_z.len(), l);
        assert_eq!(crs.li_lj_z[0].len(), n);
        assert_eq!(crs.li_lj_z[0][0].len(), n);

        assert_eq!(crs.gamma_g2.len(), l);

        assert_eq!(crs.y.len(), l);
        assert_eq!(crs.y[0].len(), 2 * n);

        let sk = SecretKey::<E>::new(&mut rng, 0);
        let pk = sk.get_pk(&crs);

        assert_eq!(pk.id, sk.id);
        assert_eq!(pk.bls_pk.len(), l);
        assert_eq!(pk.hints.len(), l);
        assert_eq!(pk.hints[0].len(), n + 1);
        assert_eq!(pk.y.len(), l);
        assert_eq!(pk.y[0].len(), 2 * n);

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<LagPublicKey<E>> = Vec::new();
        let mut lagrange_pk: Vec<LagPublicKey<E>> = Vec::new();

        for i in 0..n {
            sk.push(SecretKey::<E>::new(&mut rng, i));
            pk.push(sk[i].get_lagrange_pk(i, &crs));
            lagrange_pk.push(sk[i].get_lagrange_pk(i, &crs));

            assert_eq!(pk[i].sk_li, lagrange_pk[i].sk_li);
            assert_eq!(pk[i].sk_li_minus0, lagrange_pk[i].sk_li_minus0);
            assert_eq!(pk[i].sk_li_x, lagrange_pk[i].sk_li_x); //computed incorrectly go fix it
            assert_eq!(pk[i].sk_li_lj_z, lagrange_pk[i].sk_li_lj_z);
        }

        let _ak = AggregateKey::<E>::new(pk, &crs);
    }

    #[test]
    fn test_setup_lag_setup() {
        let mut rng = ark_std::test_rng();
        let n = 8;
        let l = 8;
        let crs = CRS::<E>::new(n, l, &mut rng);
        let lagpolys = LagPolys::<F>::new(n);

        let sk = SecretKey::<E>::new(&mut rng, 0);
        let pk = sk.get_pk(&crs);

        let lag_pk = sk.get_lagrange_pk(0, &crs);

        let computed_lag_pk = pk.get_lag_public_key(0, &crs, &lagpolys);

        assert_eq!(computed_lag_pk.bls_pk, lag_pk.bls_pk);
        assert_eq!(computed_lag_pk.sk_li, lag_pk.sk_li);
        assert_eq!(computed_lag_pk.sk_li_minus0, lag_pk.sk_li_minus0);
        assert_eq!(computed_lag_pk.sk_li_x, lag_pk.sk_li_x);
        assert_eq!(computed_lag_pk.sk_li_lj_z, lag_pk.sk_li_lj_z);
    }

    #[test]
    fn partial_decryption_proof_verifies() {
        let mut rng = ark_std::test_rng();
        let n = 8;
        let l = 4;
        let t = n / 2;
        let crs = CRS::<E>::new(n, l, &mut rng);
        let sk = (0..n)
            .map(|i| SecretKey::<E>::new(&mut rng, i))
            .collect::<Vec<_>>();
        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &crs))
            .collect::<Vec<_>>();
        let (_ak, ek) = AggregateKey::<E>::new(pk.clone(), &crs);
        let message = vec![PairingOutput::<E>::zero(); l];
        let ct = crate::ste::encryption::encrypt(&ek, t, &crs, &message, &mut rng);

        let (partial_decryption, proof) =
            sk[0].partial_decryption_with_proof(&ct, &pk[0], &crs, &mut rng);

        assert!(proof.verify(&partial_decryption, &ct, &pk[0], &crs));

        let mut tampered_partial_decryption = partial_decryption.clone();
        tampered_partial_decryption.pd += crs.gen_g[0];
        assert!(!proof.verify(&tampered_partial_decryption, &ct, &pk[0], &crs));

        let mut tampered_ct = ct.clone();
        tampered_ct.sa1[1] += crs.gen_g[0];
        assert!(!proof.verify(&partial_decryption, &tampered_ct, &pk[0], &crs));
    }

    #[test]
    fn batch_partial_decryption_proof_verifies() {
        let mut rng = ark_std::test_rng();
        let n = 8;
        let l = bte::encryption::NUM_CHUNKS;
        let batch_size = 2;
        let t = n / 2;
        let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
        let crs = CRS::<E>::new(n, l, &mut rng);
        let sk = (0..n)
            .map(|i| SecretKey::<E>::new(&mut rng, i))
            .collect::<Vec<_>>();
        let pk = sk
            .iter()
            .enumerate()
            .map(|(i, sk)| sk.get_lagrange_pk(i, &crs))
            .collect::<Vec<_>>();
        let (_ak, ek) = AggregateKey::<E>::new(pk.clone(), &crs);
        let cts = (0..batch_size)
            .map(|i| bte::encryption::encrypt(i, &bte_crs, &crs, &ek, t, &mut rng))
            .collect::<Vec<_>>();

        let (partial_decryption, proof) =
            sk[0].batch_partial_decryption_with_proof(&cts, &pk[0], &crs, &mut rng);

        assert!(proof.verify_batch(&partial_decryption, &cts, &pk[0], &crs));

        let mut tampered_cts = cts.clone();
        tampered_cts[0].encrypted_key.sa1[1] += crs.gen_g[0];
        assert!(!proof.verify_batch(&partial_decryption, &tampered_cts, &pk[0], &crs));
    }
}
