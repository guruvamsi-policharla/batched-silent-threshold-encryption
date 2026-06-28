use crate::{
    bte::{self, encryption::CcaCiphertext},
    dlog::Markers,
    nizk::kzg,
    ste::{
        self,
        aggregate::{AggregateKey, EncryptionKey},
        setup::{LagPublicKey, SecretKey, VerifiedPartialDecryption},
    },
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_std::rand::{Rng, RngCore};

pub struct PublicParams<E: Pairing> {
    pub bte_crs: bte::crs::CRS<E>,
    pub ste_crs: ste::crs::CRS<E>,
    pub kzg_crs: kzg::Crs<E>,
}

pub fn setup<E: Pairing>(
    committee_size: usize,
    batch_size: usize,
    rng: &mut impl Rng,
) -> PublicParams<E> {
    let bte_crs = bte::crs::CRS::<E>::new(batch_size, rng);
    let ste_crs = ste::crs::CRS::<E>::new(committee_size, bte::encryption::NUM_CHUNKS, rng);
    let kzg_crs = kzg::Crs::<E>::new(
        crate::nizk::range::required_kzg_degree(bte::encryption::CHUNK_BITS as usize),
        rng,
    );
    PublicParams {
        bte_crs,
        ste_crs,
        kzg_crs,
    }
}

pub fn kgen<E: Pairing>(id: usize, rng: &mut impl RngCore) -> SecretKey<E> {
    SecretKey::<E>::new(rng, id)
}

pub fn prep<E: Pairing>(
    public_keys: Vec<LagPublicKey<E>>,
    pp: &PublicParams<E>,
) -> (AggregateKey<E>, EncryptionKey<E>) {
    AggregateKey::<E>::new(public_keys, &pp.ste_crs)
}

pub fn enc<E: Pairing>(
    pp: &PublicParams<E>,
    ek: &EncryptionKey<E>,
    message: PairingOutput<E>,
    position: usize,
    threshold: usize,
    rng: &mut impl Rng,
) -> CcaCiphertext<E> {
    bte::encryption::encrypt_cca(
        position,
        message,
        &pp.bte_crs,
        &pp.ste_crs,
        &pp.kzg_crs,
        ek,
        threshold,
        rng,
    )
}

pub fn vfy<E: Pairing>(
    pp: &PublicParams<E>,
    ek: &EncryptionKey<E>,
    ciphertext: &CcaCiphertext<E>,
) -> bool {
    bte::encryption::verify_cca(ciphertext, &pp.bte_crs, &pp.ste_crs, &pp.kzg_crs, ek)
}

pub fn batch_dec<E: Pairing, R: RngCore>(
    pp: &PublicParams<E>,
    sk: &SecretKey<E>,
    pk: &LagPublicKey<E>,
    ciphertexts: &[CcaCiphertext<E>],
    rng: &mut R,
) -> VerifiedPartialDecryption<E> {
    sk.batch_partial_decryption_cca(&pp.ste_crs, pk, ciphertexts, rng)
}

pub fn comb<E: Pairing>(
    pp: &PublicParams<E>,
    aggregate_key: &AggregateKey<E>,
    encryption_key: &EncryptionKey<E>,
    ciphertexts: &[CcaCiphertext<E>],
    threshold: usize,
    partial_decryptions: &[VerifiedPartialDecryption<E>],
    markers: Markers<PairingOutput<E>>,
) -> Result<Vec<PairingOutput<E>>, bte::decryption::CcaDecryptionError> {
    bte::decryption::decrypt_cca_fft(
        ciphertexts,
        &pp.bte_crs,
        &pp.ste_crs,
        &pp.kzg_crs,
        threshold,
        partial_decryptions,
        aggregate_key,
        encryption_key,
        markers,
    )
}
