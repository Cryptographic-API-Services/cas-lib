use rand::RngCore;
use aes_gcm::{aead::Aead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit};
use rand::rngs::OsRng;

use crate::error::{CasError, CasResult};
use crate::symmetric::aead_helpers;
use crate::symmetric::cas_symmetric_encryption::{
    CASAeadSeal, Chacha20Poly1305AadEncryption, Chacha20Poly1305Encryption,
};

const CHACHA20_KEY_LEN: usize = 32;
const CHACHA20_NONCE_LEN: usize = 12;

pub struct CASChacha20Poly1305;

impl Chacha20Poly1305Encryption for CASChacha20Poly1305 {

    fn generate_key() -> Vec<u8> {
        ChaCha20Poly1305::generate_key(&mut OsRng).to_vec()
    }

    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>> {
        if aes_key.len() != CHACHA20_KEY_LEN {
            return Err(CasError::InvalidKey);
        }
        if nonce.len() != CHACHA20_NONCE_LEN {
            return Err(CasError::InvalidNonce);
        }
        let key = Key::from_slice(aes_key.as_slice());
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(nonce.as_slice());
        cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| CasError::EncryptionFailed)
    }

    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>> {
        if aes_key.len() != CHACHA20_KEY_LEN {
            return Err(CasError::InvalidKey);
        }
        if nonce.len() != CHACHA20_NONCE_LEN {
            return Err(CasError::InvalidNonce);
        }
        let key = Key::from_slice(aes_key.as_slice());
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(nonce.as_slice());
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| CasError::DecryptionFailed)
    }

    fn generate_nonce() -> Vec<u8> {
        let mut nonce = [0u8; CHACHA20_NONCE_LEN]; // ChaCha20Poly1305 uses 96-bit (12-byte) nonces
        OsRng.fill_bytes(&mut nonce);
        nonce.to_vec()
    }
}

impl Chacha20Poly1305AadEncryption for CASChacha20Poly1305 {
    /// Encrypts with ChaCha20-Poly1305 taking a key, nonce and additional authenticated data
    fn encrypt_plaintext_with_aad(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::encrypt_with_aad::<ChaCha20Poly1305>(&key, &nonce, &plaintext, &aad)
    }

    /// Decrypts with ChaCha20-Poly1305 taking a key, nonce and additional authenticated data
    fn decrypt_ciphertext_with_aad(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::decrypt_with_aad::<ChaCha20Poly1305>(&key, &nonce, &ciphertext, &aad)
    }
}

impl CASAeadSeal for CASChacha20Poly1305 {
    const NONCE_LEN: usize = CHACHA20_NONCE_LEN;

    /// Encrypts with ChaCha20-Poly1305 under a fresh random nonce and returns
    /// `nonce || ciphertext || tag`.
    fn seal(key: Vec<u8>, plaintext: Vec<u8>, aad: Option<Vec<u8>>) -> CasResult<Vec<u8>> {
        aead_helpers::seal::<ChaCha20Poly1305>(&key, &plaintext, aad.as_deref())
    }

    /// Splits and decrypts a `nonce || ciphertext || tag` blob from [`CASAeadSeal::seal`].
    fn open(key: Vec<u8>, sealed: Vec<u8>, aad: Option<Vec<u8>>) -> CasResult<Vec<u8>> {
        aead_helpers::open::<ChaCha20Poly1305>(&key, &sealed, aad.as_deref())
    }
}
