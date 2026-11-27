use aes_gcm::{Aes128Gcm, Aes256Gcm};

use crate::error::{CasError, CasResult};
use crate::key_exchange::x25519::{
    derive_key_from_x25519_shared_secret, KDF_LABEL_AES_128_GCM, KDF_LABEL_AES_256_GCM,
};

use super::aead_helpers;
use super::cas_symmetric_encryption::{
    CASAES128AadEncryption, CASAES128Encryption, CASAES256AadEncryption, CASAES256Encryption,
    CASAeadSeal,
};

const AES_NONCE_LEN: usize = 12;
const AES128_KEY_LEN: usize = 16;
const AES256_KEY_LEN: usize = 32;

pub struct CASAES128;
pub struct CASAES256;

impl CASAES256Encryption for CASAES256 {

    /// Generates an AES256 key from a vector.
    /// Returns an error if the input is not 32 bytes long.
    fn key_from_vec(key_slice: Vec<u8>) -> CasResult<Vec<u8>> {
        if key_slice.len() != AES256_KEY_LEN {
            return Err(CasError::InvalidKey);
        }
        Ok(key_slice)
    }

    /// Generates a random 32-byte AES-256 key.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random number generator fails.
    fn generate_key() -> Vec<u8> {
        aead_helpers::random_bytes::<AES256_KEY_LEN>()
    }


    /// Encrypts with AES-256-GCM taking an aes_key and aes_nonce
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::encrypt_with_aad::<Aes256Gcm>(&aes_key, &nonce, &plaintext, &[])
    }


    /// Decrypts with AES-256-GCM taking an aes_key and aes_nonce
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::decrypt_with_aad::<Aes256Gcm>(&aes_key, &nonce, &ciphertext, &[])
    }

    /// Derives a 256-bit AES-256-GCM key from an X25519 shared secret with HKDF-SHA256.
    ///
    /// Pass the shared secret from `X25519::diffie_hellman` and **both** parties' public
    /// keys, in either order. The key is bound to AES-256-GCM and to those public keys, so a
    /// shared secret used for several ciphers yields unrelated keys, and both peers
    /// derive the same key only if they saw the same public keys.
    ///
    /// Returns [`CasError::InvalidKey`] if any input is not 32 bytes or the shared secret
    /// is all zeros. Keys derived by cas-lib 0.4 and earlier (one HKDF `info` for every
    /// cipher, no public keys) are different; both peers must use the same version.
    ///
    /// The returned key is secret and owned by the caller, who must zeroize it when done
    /// (FFI layers: before freeing it). See the crate-level docs.
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>, public_key_a: Vec<u8>, public_key_b: Vec<u8>) -> CasResult<Vec<u8>> {
        derive_key_from_x25519_shared_secret(shared_secret, public_key_a, public_key_b, KDF_LABEL_AES_256_GCM, 32)
    }


    /// Generates a random 12-byte AES-GCM nonce. Use each nonce for one message only.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random number generator fails.
    fn generate_nonce() -> Vec<u8> {
        aead_helpers::random_bytes::<AES_NONCE_LEN>()
    }
}

impl CASAES256AadEncryption for CASAES256 {

    /// Encrypts with AES-256-GCM taking an aes_key, aes_nonce and additional authenticated data
    fn encrypt_plaintext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::encrypt_with_aad::<Aes256Gcm>(&aes_key, &nonce, &plaintext, &aad)
    }

    /// Decrypts with AES-256-GCM taking an aes_key, aes_nonce and additional authenticated data
    fn decrypt_ciphertext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::decrypt_with_aad::<Aes256Gcm>(&aes_key, &nonce, &ciphertext, &aad)
    }
}

impl CASAES128AadEncryption for CASAES128 {

    /// Encrypts with AES-128-GCM taking an aes_key, aes_nonce and additional authenticated data
    fn encrypt_plaintext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::encrypt_with_aad::<Aes128Gcm>(&aes_key, &nonce, &plaintext, &aad)
    }

    /// Decrypts with AES-128-GCM taking an aes_key, aes_nonce and additional authenticated data
    fn decrypt_ciphertext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::decrypt_with_aad::<Aes128Gcm>(&aes_key, &nonce, &ciphertext, &aad)
    }
}

impl CASAES128Encryption for CASAES128 {

    /// Generates an AES128 key from a vector.
    /// Returns an error if the input is not 16 bytes long.
    fn key_from_vec(key_slice: Vec<u8>) -> CasResult<Vec<u8>> {
        if key_slice.len() != AES128_KEY_LEN {
            return Err(CasError::InvalidKey);
        }
        Ok(key_slice)
    }

    /// Generates a random 16-byte AES-128 key.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random number generator fails.
    fn generate_key() -> Vec<u8> {
        aead_helpers::random_bytes::<AES128_KEY_LEN>()
    }



    /// Encrypts with AES-128-GCM taking an aes_key and aes_nonce
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::encrypt_with_aad::<Aes128Gcm>(&aes_key, &nonce, &plaintext, &[])
    }



    /// Decrypts with AES-128-GCM taking an aes_key and aes_nonce
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>> {
        aead_helpers::decrypt_with_aad::<Aes128Gcm>(&aes_key, &nonce, &ciphertext, &[])
    }



    /// Derives a 128-bit AES-128-GCM key from an X25519 shared secret with HKDF-SHA256.
    ///
    /// Pass the shared secret from `X25519::diffie_hellman` and **both** parties' public
    /// keys, in either order. The key is bound to AES-128-GCM and to those public keys, so a
    /// shared secret used for several ciphers yields unrelated keys, and both peers
    /// derive the same key only if they saw the same public keys.
    ///
    /// Returns [`CasError::InvalidKey`] if any input is not 32 bytes or the shared secret
    /// is all zeros. Keys derived by cas-lib 0.4 and earlier (one HKDF `info` for every
    /// cipher, no public keys) are different; both peers must use the same version.
    ///
    /// The returned key is secret and owned by the caller, who must zeroize it when done
    /// (FFI layers: before freeing it). See the crate-level docs.
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>, public_key_a: Vec<u8>, public_key_b: Vec<u8>) -> CasResult<Vec<u8>> {
        derive_key_from_x25519_shared_secret(shared_secret, public_key_a, public_key_b, KDF_LABEL_AES_128_GCM, 16)
    }


    /// Generates a random 12-byte AES-GCM nonce. Use each nonce for one message only.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random number generator fails.
    fn generate_nonce() -> Vec<u8> {
        aead_helpers::random_bytes::<AES_NONCE_LEN>()
    }
}

impl CASAeadSeal for CASAES256 {
    const NONCE_LEN: usize = AES_NONCE_LEN;

    /// Encrypts with AES-256-GCM under a fresh random nonce and returns
    /// `nonce || ciphertext || tag`.
    fn seal(key: Vec<u8>, plaintext: Vec<u8>, aad: Option<Vec<u8>>) -> CasResult<Vec<u8>> {
        aead_helpers::seal::<Aes256Gcm>(&key, &plaintext, aad.as_deref())
    }

    /// Splits and decrypts a `nonce || ciphertext || tag` blob from [`CASAeadSeal::seal`].
    fn open(key: Vec<u8>, sealed: Vec<u8>, aad: Option<Vec<u8>>) -> CasResult<Vec<u8>> {
        aead_helpers::open::<Aes256Gcm>(&key, &sealed, aad.as_deref())
    }
}

impl CASAeadSeal for CASAES128 {
    const NONCE_LEN: usize = AES_NONCE_LEN;

    /// Encrypts with AES-128-GCM under a fresh random nonce and returns
    /// `nonce || ciphertext || tag`.
    fn seal(key: Vec<u8>, plaintext: Vec<u8>, aad: Option<Vec<u8>>) -> CasResult<Vec<u8>> {
        aead_helpers::seal::<Aes128Gcm>(&key, &plaintext, aad.as_deref())
    }

    /// Splits and decrypts a `nonce || ciphertext || tag` blob from [`CASAeadSeal::seal`].
    fn open(key: Vec<u8>, sealed: Vec<u8>, aad: Option<Vec<u8>>) -> CasResult<Vec<u8>> {
        aead_helpers::open::<Aes128Gcm>(&key, &sealed, aad.as_deref())
    }
}
