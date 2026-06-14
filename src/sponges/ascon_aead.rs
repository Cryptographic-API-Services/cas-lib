use ascon_aead::{AsconAead128 as Ascon128, Key, AsconAead128Nonce, aead::{Aead, KeyInit}};
use rand::{rngs::OsRng, RngCore};

use crate::error::{CasError, CasResult};

use super::cas_ascon_aead::{CASAsconAead};

const ASCON_KEY_LEN: usize = 16;
const ASCON_NONCE_LEN: usize = 16;

pub struct AsconAead;

impl CASAsconAead for AsconAead {
    /// Encrypts with AsconAead.
    /// Returns an error if the key or nonce is not 16 bytes long, or if encryption fails.
    fn encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>> {
        let key_array: [u8; ASCON_KEY_LEN] =
            key.try_into().map_err(|_| CasError::InvalidKey)?;
        let nonce_array: [u8; ASCON_NONCE_LEN] =
            nonce.try_into().map_err(|_| CasError::InvalidNonce)?;
        let key_generic_array = Key::<Ascon128>::from(key_array);
        let nonce_generic_array = AsconAead128Nonce::from(nonce_array);
        let cipher = Ascon128::new(&key_generic_array);
        cipher
            .encrypt(&nonce_generic_array, plaintext.as_ref())
            .map_err(|_| CasError::EncryptionFailed)
    }

    /// Decrypts with AsconAead.
    /// Returns an error if the key or nonce is not 16 bytes long, or if decryption fails.
    fn decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>> {
        let key_array: [u8; ASCON_KEY_LEN] =
            key.try_into().map_err(|_| CasError::InvalidKey)?;
        let nonce_array: [u8; ASCON_NONCE_LEN] =
            nonce.try_into().map_err(|_| CasError::InvalidNonce)?;
        let key_generic_array = Key::<Ascon128>::from(key_array);
        let nonce_generic_array = AsconAead128Nonce::from(nonce_array);
        let cipher = Ascon128::new(&key_generic_array);
        cipher
            .decrypt(&nonce_generic_array, ciphertext.as_ref())
            .map_err(|_| CasError::DecryptionFailed)
    }

    /// Generates a 16-byte key for Ascon Aead
    fn generate_key() -> Vec<u8> {
        let mut key_bytes = [0u8; ASCON_KEY_LEN];
        OsRng.fill_bytes(&mut key_bytes);
        return Key::<Ascon128>::from(key_bytes).to_vec();
    }

    /// Generates a Ascon Aead nonce
    fn generate_nonce() -> Vec<u8> {
        let mut nonce_bytes = [0u8; ASCON_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        return AsconAead128Nonce::from(nonce_bytes).to_vec();
    }
}
