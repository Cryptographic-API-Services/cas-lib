use aes_kw::{KekAes128, KekAes256};
use rand::{rngs::OsRng, RngCore};

use crate::error::{CasError, CasResult};

use super::cas_symmetric_encryption::{CASAES128KeyWrap, CASAES256KeyWrap};

const AES128_KEY_LEN: usize = 16;
const AES256_KEY_LEN: usize = 32;

/// AES-KW and AES-KWP operate on 64-bit (8-byte) semiblocks (RFC 3394 / RFC 5649).
const SEMIBLOCK_LEN: usize = 8;

pub struct CASAES128KW;
pub struct CASAES256KW;

/// Validates plaintext for unpadded AES-KW (RFC 3394 / NIST SP 800-38F KW-AE):
/// the key data must be at least two semiblocks (16 bytes) and a whole number
/// of semiblocks.
fn validate_kw_plaintext(key_to_wrap: &[u8]) -> CasResult<()> {
    if key_to_wrap.len() < 2 * SEMIBLOCK_LEN || key_to_wrap.len() % SEMIBLOCK_LEN != 0 {
        return Err(CasError::InvalidInput);
    }
    Ok(())
}

/// Validates ciphertext for unpadded AES-KW (RFC 3394 / NIST SP 800-38F KW-AD):
/// a wrapped key is the plaintext plus one semiblock of integrity data, so it
/// must be at least three semiblocks (24 bytes) and a whole number of semiblocks.
fn validate_kw_ciphertext(wrapped_key: &[u8]) -> CasResult<()> {
    if wrapped_key.len() < 3 * SEMIBLOCK_LEN || wrapped_key.len() % SEMIBLOCK_LEN != 0 {
        return Err(CasError::InvalidInput);
    }
    Ok(())
}

/// Validates plaintext for padded AES-KWP (RFC 5649 / NIST SP 800-38F KWP-AE):
/// the key data may be any length between 1 and 2^32 - 1 bytes.
fn validate_kwp_plaintext(key_to_wrap: &[u8]) -> CasResult<()> {
    if key_to_wrap.is_empty() || u32::try_from(key_to_wrap.len()).is_err() {
        return Err(CasError::InvalidInput);
    }
    Ok(())
}

/// Validates ciphertext for padded AES-KWP (RFC 5649 / NIST SP 800-38F KWP-AD):
/// the smallest wrapped output is two semiblocks (16 bytes), and every wrapped
/// key is a whole number of semiblocks.
fn validate_kwp_ciphertext(wrapped_key: &[u8]) -> CasResult<()> {
    if wrapped_key.len() < 2 * SEMIBLOCK_LEN || wrapped_key.len() % SEMIBLOCK_LEN != 0 {
        return Err(CasError::InvalidInput);
    }
    Ok(())
}

impl CASAES256KeyWrap for CASAES256KW {
    /// Generates a 32-byte AES-256 key-encryption key (KEK)
    fn generate_kek() -> Vec<u8> {
        let mut os_rng = OsRng;
        let mut kek = [0u8; AES256_KEY_LEN];
        os_rng.fill_bytes(&mut kek);
        kek.to_vec()
    }

    /// Wraps a key with AES-256-KW (RFC 3394 / NIST SP 800-38F KW).
    /// The key to wrap must be a multiple of 8 bytes and at least 16 bytes long;
    /// the wrapped output is 8 bytes longer than the input.
    fn wrap_key(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = KekAes256::try_from(kek.as_slice()).map_err(|_| CasError::InvalidKey)?;
        validate_kw_plaintext(&key_to_wrap)?;
        kek.wrap_vec(&key_to_wrap)
            .map_err(|_| CasError::EncryptionFailed)
    }

    /// Unwraps an AES-256-KW wrapped key (RFC 3394 / NIST SP 800-38F KW),
    /// verifying its integrity check value.
    fn unwrap_key(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = KekAes256::try_from(kek.as_slice()).map_err(|_| CasError::InvalidKey)?;
        validate_kw_ciphertext(&wrapped_key)?;
        kek.unwrap_vec(&wrapped_key)
            .map_err(|_| CasError::DecryptionFailed)
    }

    /// Wraps a key of any length with AES-256-KWP (RFC 5649 / NIST SP 800-38F KWP).
    /// The key to wrap is padded to a multiple of 8 bytes before wrapping.
    fn wrap_key_with_padding(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = KekAes256::try_from(kek.as_slice()).map_err(|_| CasError::InvalidKey)?;
        validate_kwp_plaintext(&key_to_wrap)?;
        kek.wrap_with_padding_vec(&key_to_wrap)
            .map_err(|_| CasError::EncryptionFailed)
    }

    /// Unwraps an AES-256-KWP wrapped key (RFC 5649 / NIST SP 800-38F KWP),
    /// verifying its integrity check value and padding.
    fn unwrap_key_with_padding(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = KekAes256::try_from(kek.as_slice()).map_err(|_| CasError::InvalidKey)?;
        validate_kwp_ciphertext(&wrapped_key)?;
        kek.unwrap_with_padding_vec(&wrapped_key)
            .map_err(|_| CasError::DecryptionFailed)
    }
}

impl CASAES128KeyWrap for CASAES128KW {
    /// Generates a 16-byte AES-128 key-encryption key (KEK)
    fn generate_kek() -> Vec<u8> {
        let mut os_rng = OsRng;
        let mut kek = [0u8; AES128_KEY_LEN];
        os_rng.fill_bytes(&mut kek);
        kek.to_vec()
    }

    /// Wraps a key with AES-128-KW (RFC 3394 / NIST SP 800-38F KW).
    /// The key to wrap must be a multiple of 8 bytes and at least 16 bytes long;
    /// the wrapped output is 8 bytes longer than the input.
    fn wrap_key(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = KekAes128::try_from(kek.as_slice()).map_err(|_| CasError::InvalidKey)?;
        validate_kw_plaintext(&key_to_wrap)?;
        kek.wrap_vec(&key_to_wrap)
            .map_err(|_| CasError::EncryptionFailed)
    }

    /// Unwraps an AES-128-KW wrapped key (RFC 3394 / NIST SP 800-38F KW),
    /// verifying its integrity check value.
    fn unwrap_key(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = KekAes128::try_from(kek.as_slice()).map_err(|_| CasError::InvalidKey)?;
        validate_kw_ciphertext(&wrapped_key)?;
        kek.unwrap_vec(&wrapped_key)
            .map_err(|_| CasError::DecryptionFailed)
    }

    /// Wraps a key of any length with AES-128-KWP (RFC 5649 / NIST SP 800-38F KWP).
    /// The key to wrap is padded to a multiple of 8 bytes before wrapping.
    fn wrap_key_with_padding(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = KekAes128::try_from(kek.as_slice()).map_err(|_| CasError::InvalidKey)?;
        validate_kwp_plaintext(&key_to_wrap)?;
        kek.wrap_with_padding_vec(&key_to_wrap)
            .map_err(|_| CasError::EncryptionFailed)
    }

    /// Unwraps an AES-128-KWP wrapped key (RFC 5649 / NIST SP 800-38F KWP),
    /// verifying its integrity check value and padding.
    fn unwrap_key_with_padding(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = KekAes128::try_from(kek.as_slice()).map_err(|_| CasError::InvalidKey)?;
        validate_kwp_ciphertext(&wrapped_key)?;
        kek.unwrap_with_padding_vec(&wrapped_key)
            .map_err(|_| CasError::DecryptionFailed)
    }
}
