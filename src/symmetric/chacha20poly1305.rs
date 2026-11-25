use chacha20poly1305::ChaCha20Poly1305;

use crate::error::CasResult;
use crate::symmetric::aead_helpers;
use crate::symmetric::cas_symmetric_encryption::{
    CASAeadSeal, Chacha20Poly1305AadEncryption, Chacha20Poly1305Encryption,
};

const CHACHA20_KEY_LEN: usize = 32;
const CHACHA20_NONCE_LEN: usize = 12;

pub struct CASChacha20Poly1305;

impl Chacha20Poly1305Encryption for CASChacha20Poly1305 {

    fn generate_key() -> Vec<u8> {
        aead_helpers::random_bytes::<CHACHA20_KEY_LEN>()
    }

    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::encrypt_with_aad::<ChaCha20Poly1305>(&aes_key, &nonce, &plaintext, &[])
    }

    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::decrypt_with_aad::<ChaCha20Poly1305>(&aes_key, &nonce, &ciphertext, &[])
    }

    fn generate_nonce() -> Vec<u8> {
        aead_helpers::random_bytes::<CHACHA20_NONCE_LEN>()
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
