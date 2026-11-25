use aes_kw::{KeyInit, KwAes128, KwAes256, KwpAes128, KwpAes256, IV_LEN};
use zeroize::Zeroizing;

use crate::error::{CasError, CasResult};

use super::aead_helpers::random_bytes;
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

fn init_kek<K: KeyInit>(kek: &[u8]) -> CasResult<K> {
    K::new_from_slice(kek).map_err(|_| CasError::InvalidKey)
}

/// Length of a KWP-wrapped key: the input padded to whole semiblocks, plus
/// one semiblock of integrity data.
fn kwp_wrapped_len(key_len: usize) -> usize {
    key_len.div_ceil(SEMIBLOCK_LEN) * SEMIBLOCK_LEN + IV_LEN
}

/// Copies the unwrapped key out of `buf`, which is zeroized when dropped.
fn take_unwrapped(buf: Zeroizing<Vec<u8>>, len: usize) -> Vec<u8> {
    buf[..len].to_vec()
}

impl CASAES256KeyWrap for CASAES256KW {
    /// Generates a 32-byte AES-256 key-encryption key (KEK)
    fn generate_kek() -> Vec<u8> {
        random_bytes::<AES256_KEY_LEN>()
    }

    /// Wraps a key with AES-256-KW (RFC 3394 / NIST SP 800-38F KW).
    /// The key to wrap must be a multiple of 8 bytes and at least 16 bytes long;
    /// the wrapped output is 8 bytes longer than the input.
    fn wrap_key(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = init_kek::<KwAes256>(&kek)?;
        validate_kw_plaintext(&key_to_wrap)?;
        let mut wrapped = vec![0u8; key_to_wrap.len() + IV_LEN];
        kek.wrap_key(&key_to_wrap, &mut wrapped)
            .map_err(|_| CasError::EncryptionFailed)?;
        Ok(wrapped)
    }

    /// Unwraps an AES-256-KW wrapped key (RFC 3394 / NIST SP 800-38F KW),
    /// verifying its integrity check value.
    fn unwrap_key(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = init_kek::<KwAes256>(&kek)?;
        validate_kw_ciphertext(&wrapped_key)?;
        let mut unwrapped = Zeroizing::new(vec![0u8; wrapped_key.len() - IV_LEN]);
        let len = kek.unwrap_key(&wrapped_key, &mut unwrapped)
            .map_err(|_| CasError::DecryptionFailed)?
            .len();
        Ok(take_unwrapped(unwrapped, len))
    }

    /// Wraps a key of any length with AES-256-KWP (RFC 5649 / NIST SP 800-38F KWP).
    /// The key to wrap is padded to a multiple of 8 bytes before wrapping.
    fn wrap_key_with_padding(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = init_kek::<KwpAes256>(&kek)?;
        validate_kwp_plaintext(&key_to_wrap)?;
        let mut wrapped = vec![0u8; kwp_wrapped_len(key_to_wrap.len())];
        kek.wrap_key(&key_to_wrap, &mut wrapped)
            .map_err(|_| CasError::EncryptionFailed)?;
        Ok(wrapped)
    }

    /// Unwraps an AES-256-KWP wrapped key (RFC 5649 / NIST SP 800-38F KWP),
    /// verifying its integrity check value and padding.
    fn unwrap_key_with_padding(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = init_kek::<KwpAes256>(&kek)?;
        validate_kwp_ciphertext(&wrapped_key)?;
        let mut unwrapped = Zeroizing::new(vec![0u8; wrapped_key.len() - IV_LEN]);
        let len = kek.unwrap_key(&wrapped_key, &mut unwrapped)
            .map_err(|_| CasError::DecryptionFailed)?
            .len();
        Ok(take_unwrapped(unwrapped, len))
    }
}

impl CASAES128KeyWrap for CASAES128KW {
    /// Generates a 16-byte AES-128 key-encryption key (KEK)
    fn generate_kek() -> Vec<u8> {
        random_bytes::<AES128_KEY_LEN>()
    }

    /// Wraps a key with AES-128-KW (RFC 3394 / NIST SP 800-38F KW).
    /// The key to wrap must be a multiple of 8 bytes and at least 16 bytes long;
    /// the wrapped output is 8 bytes longer than the input.
    fn wrap_key(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = init_kek::<KwAes128>(&kek)?;
        validate_kw_plaintext(&key_to_wrap)?;
        let mut wrapped = vec![0u8; key_to_wrap.len() + IV_LEN];
        kek.wrap_key(&key_to_wrap, &mut wrapped)
            .map_err(|_| CasError::EncryptionFailed)?;
        Ok(wrapped)
    }

    /// Unwraps an AES-128-KW wrapped key (RFC 3394 / NIST SP 800-38F KW),
    /// verifying its integrity check value.
    fn unwrap_key(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = init_kek::<KwAes128>(&kek)?;
        validate_kw_ciphertext(&wrapped_key)?;
        let mut unwrapped = Zeroizing::new(vec![0u8; wrapped_key.len() - IV_LEN]);
        let len = kek.unwrap_key(&wrapped_key, &mut unwrapped)
            .map_err(|_| CasError::DecryptionFailed)?
            .len();
        Ok(take_unwrapped(unwrapped, len))
    }

    /// Wraps a key of any length with AES-128-KWP (RFC 5649 / NIST SP 800-38F KWP).
    /// The key to wrap is padded to a multiple of 8 bytes before wrapping.
    fn wrap_key_with_padding(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = init_kek::<KwpAes128>(&kek)?;
        validate_kwp_plaintext(&key_to_wrap)?;
        let mut wrapped = vec![0u8; kwp_wrapped_len(key_to_wrap.len())];
        kek.wrap_key(&key_to_wrap, &mut wrapped)
            .map_err(|_| CasError::EncryptionFailed)?;
        Ok(wrapped)
    }

    /// Unwraps an AES-128-KWP wrapped key (RFC 5649 / NIST SP 800-38F KWP),
    /// verifying its integrity check value and padding.
    fn unwrap_key_with_padding(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>> {
        let kek = init_kek::<KwpAes128>(&kek)?;
        validate_kwp_ciphertext(&wrapped_key)?;
        let mut unwrapped = Zeroizing::new(vec![0u8; wrapped_key.len() - IV_LEN]);
        let len = kek.unwrap_key(&wrapped_key, &mut unwrapped)
            .map_err(|_| CasError::DecryptionFailed)?
            .len();
        Ok(take_unwrapped(unwrapped, len))
    }
}
