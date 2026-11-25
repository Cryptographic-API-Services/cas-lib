use crate::error::CasResult;

pub trait CASAsconAead {
    fn generate_key() -> Vec<u8>;
    /// Generates a random 16-byte nonce from `OsRng`. Use each nonce for one message only.
    fn generate_nonce() -> Vec<u8>;
    /// Encrypts `plaintext` under `nonce`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce, and it must never be used twice with the
    /// same key. Reusing an Ascon-AEAD128 nonce breaks its confidentiality
    /// guarantee. Prefer
    /// [`CASAeadSeal::seal`](crate::symmetric::cas_symmetric_encryption::CASAeadSeal::seal),
    /// which draws a fresh nonce for every call.
    fn encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce`.
    fn decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>>;
}

/// Ascon-AEAD128 with additional authenticated data (AAD).
///
/// The AAD is not encrypted, but it is bound to the authentication tag:
/// decryption only succeeds when the same AAD is supplied.
pub trait CASAsconAeadAad {
    /// Encrypts `plaintext` under `nonce` and binds `aad`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce, and it must never be used twice with the
    /// same key. Reusing an Ascon-AEAD128 nonce breaks its confidentiality
    /// guarantee. Prefer
    /// [`CASAeadSeal::seal`](crate::symmetric::cas_symmetric_encryption::CASAeadSeal::seal),
    /// which draws a fresh nonce for every call.
    fn encrypt_plaintext_with_aad(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce` and checks `aad`.
    fn decrypt_ciphertext_with_aad(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
}
