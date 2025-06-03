use ark_ec::pairing::Pairing;

pub struct Ciphertext<E: Pairing> {
    pub ste_ct: crate::ste::encryption::Ciphertext<E>,
    pub bte_ct: crate::bte::encryption::Ciphertext<E>,
}

pub fn encrypt() {}
