use ascon_aead::AsconAead128 as Ascon128;

use crate::error::CasResult;

use crate::symmetric::aead_helpers;
use crate::symmetric::cas_symmetric_encryption::CASAeadSeal;

use super::cas_ascon_aead::{CASAsconAead, CASAsconAeadAad};

const ASCON_KEY_LEN: usize = 16;
const ASCON_NONCE_LEN: usize = 16;

pub struct AsconAead;

impl CASAsconAead for AsconAead {
    /// Encrypts with AsconAead.
    /// Returns an error if the key or nonce is not 16 bytes long, or if encryption fails.
    fn encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::encrypt_with_aad::<Ascon128>(&key, &nonce, &plaintext, &[])
    }

    /// Decrypts with AsconAead.
    /// Returns an error if the key or nonce is not 16 bytes long, or if decryption fails.
    fn decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::decrypt_with_aad::<Ascon128>(&key, &nonce, &ciphertext, &[])
    }

    /// Generates a 16-byte key for Ascon Aead
    fn generate_key() -> Vec<u8> {
        aead_helpers::random_bytes(ASCON_KEY_LEN)
    }

    /// Generates a Ascon Aead nonce
    fn generate_nonce() -> Vec<u8> {
        aead_helpers::random_bytes(ASCON_NONCE_LEN)
    }
}

impl CASAsconAeadAad for AsconAead {
    /// Encrypts with Ascon-AEAD128 taking a key, nonce and additional authenticated data.
    /// Returns an error if the key or nonce is not 16 bytes long, or if encryption fails.
    fn encrypt_plaintext_with_aad(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::encrypt_with_aad::<Ascon128>(&key, &nonce, &plaintext, &aad)
    }

    /// Decrypts with Ascon-AEAD128 taking a key, nonce and additional authenticated data.
    /// Returns an error if the key or nonce is not 16 bytes long, or if decryption fails.
    fn decrypt_ciphertext_with_aad(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::decrypt_with_aad::<Ascon128>(&key, &nonce, &ciphertext, &aad)
    }
}

impl CASAeadSeal for AsconAead {
    const NONCE_LEN: usize = ASCON_NONCE_LEN;

    /// Encrypts with Ascon-AEAD128 under a fresh random nonce and returns
    /// `nonce || ciphertext || tag`.
    fn seal(key: Vec<u8>, plaintext: Vec<u8>, aad: Option<Vec<u8>>) -> CasResult<Vec<u8>> {
        aead_helpers::seal::<Ascon128>(&key, &plaintext, aad.as_deref())
    }

    /// Splits and decrypts a `nonce || ciphertext || tag` blob from [`CASAeadSeal::seal`].
    fn open(key: Vec<u8>, sealed: Vec<u8>, aad: Option<Vec<u8>>) -> CasResult<Vec<u8>> {
        aead_helpers::open::<Ascon128>(&key, &sealed, aad.as_deref())
    }
}
