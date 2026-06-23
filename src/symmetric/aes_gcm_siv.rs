use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes128GcmSiv, Aes256GcmSiv, Key, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

use crate::error::{CasError, CasResult};

use super::cas_symmetric_encryption::{CASAES128SIVEncryption, CASAES256SIVEncryption};

const AES_SIV_NONCE_LEN: usize = 12;
const AES128_KEY_LEN: usize = 16;
const AES256_KEY_LEN: usize = 32;

pub struct CASAES128SIV;
pub struct CASAES256SIV;

impl CASAES256SIVEncryption for CASAES256SIV {

    /// Generates an AES-256-GCM-SIV key from a vector.
    /// Returns an error if the input is not 32 bytes long.
    fn key_from_vec(key_slice: Vec<u8>) -> CasResult<Vec<u8>> {
        if key_slice.len() != AES256_KEY_LEN {
            return Err(CasError::InvalidKey);
        }
        let key = Key::<Aes256GcmSiv>::from_slice(key_slice.as_slice());
        Ok(key.to_vec())
    }

    /// Generates an AES-256-GCM-SIV 32-byte key
    fn generate_key() -> Vec<u8> {
        let mut os_rng = OsRng;
        Aes256GcmSiv::generate_key(&mut os_rng).to_vec()
    }

    /// Encrypts with AES-256-GCM-SIV taking an aes_key and nonce
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>> {
        if aes_key.len() != AES256_KEY_LEN {
            return Err(CasError::InvalidKey);
        }
        if nonce.len() != AES_SIV_NONCE_LEN {
            return Err(CasError::InvalidNonce);
        }
        let key = Key::<Aes256GcmSiv>::from_slice(aes_key.as_slice());
        let cipher = Aes256GcmSiv::new(key);
        let nonce = Nonce::from_slice(nonce.as_slice());
        cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| CasError::EncryptionFailed)
    }

    /// Decrypts with AES-256-GCM-SIV taking an aes_key and nonce
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>> {
        if aes_key.len() != AES256_KEY_LEN {
            return Err(CasError::InvalidKey);
        }
        if nonce.len() != AES_SIV_NONCE_LEN {
            return Err(CasError::InvalidNonce);
        }
        let key = Key::<Aes256GcmSiv>::from_slice(aes_key.as_slice());
        let cipher = Aes256GcmSiv::new(key);
        let nonce = Nonce::from_slice(nonce.as_slice());
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| CasError::DecryptionFailed)
    }

    /// Creates an AES-256-GCM-SIV 32-byte key from an X25519 shared secret
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> CasResult<Vec<u8>> {
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut aes_key: Box<[u8; 32]> = Box::new([0u8; 32]);
        hk.expand(b"aes key", &mut *aes_key)
            .map_err(|_| CasError::KeyGenerationFailed)?;
        Ok(aes_key.to_vec())
    }

    /// Generates an AES-GCM-SIV nonce
    fn generate_nonce() -> Vec<u8> {
        let mut os_rng = OsRng;
        let mut nonce = [0u8; AES_SIV_NONCE_LEN];
        os_rng.fill_bytes(&mut nonce);
        nonce.to_vec()
    }
}

impl CASAES128SIVEncryption for CASAES128SIV {

    /// Generates an AES-128-GCM-SIV key from a vector.
    /// Returns an error if the input is not 16 bytes long.
    fn key_from_vec(key_slice: Vec<u8>) -> CasResult<Vec<u8>> {
        if key_slice.len() != AES128_KEY_LEN {
            return Err(CasError::InvalidKey);
        }
        let key = Key::<Aes128GcmSiv>::from_slice(key_slice.as_slice());
        Ok(key.to_vec())
    }

    /// Generates an AES-128-GCM-SIV 16-byte key
    fn generate_key() -> Vec<u8> {
        let mut os_rng = OsRng;
        Aes128GcmSiv::generate_key(&mut os_rng).to_vec()
    }

    /// Encrypts with AES-128-GCM-SIV taking an aes_key and nonce
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>> {
        if aes_key.len() != AES128_KEY_LEN {
            return Err(CasError::InvalidKey);
        }
        if nonce.len() != AES_SIV_NONCE_LEN {
            return Err(CasError::InvalidNonce);
        }
        let key = Key::<Aes128GcmSiv>::from_slice(aes_key.as_slice());
        let cipher = Aes128GcmSiv::new(key);
        let nonce = Nonce::from_slice(nonce.as_slice());
        cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| CasError::EncryptionFailed)
    }

    /// Decrypts with AES-128-GCM-SIV taking an aes_key and nonce
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>> {
        if aes_key.len() != AES128_KEY_LEN {
            return Err(CasError::InvalidKey);
        }
        if nonce.len() != AES_SIV_NONCE_LEN {
            return Err(CasError::InvalidNonce);
        }
        let key = Key::<Aes128GcmSiv>::from_slice(aes_key.as_slice());
        let cipher = Aes128GcmSiv::new(key);
        let nonce = Nonce::from_slice(nonce.as_slice());
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| CasError::DecryptionFailed)
    }

    /// Creates an AES-128-GCM-SIV 16-byte key from an X25519 shared secret
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> CasResult<Vec<u8>> {
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut aes_key = Box::new([0u8; 16]);
        hk.expand(b"aes key", &mut *aes_key)
            .map_err(|_| CasError::KeyGenerationFailed)?;
        Ok(aes_key.to_vec())
    }

    /// Generates an AES-GCM-SIV nonce
    fn generate_nonce() -> Vec<u8> {
        let mut os_rng = OsRng;
        let mut nonce = [0u8; AES_SIV_NONCE_LEN];
        os_rng.fill_bytes(&mut nonce);
        nonce.to_vec()
    }
}
