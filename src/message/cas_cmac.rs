use aes::{Aes128, Aes256};
use cmac::{digest::KeyInit, Cmac, Mac};
use zeroize::Zeroizing;

use crate::error::{CasError, CasResult};
use crate::message::cmac::CASCMAC;

/// CMAC with AES-128: a 16-byte key and a 16-byte tag.
pub struct CMACAES128;

/// CMAC with AES-256: a 32-byte key and a 16-byte tag.
pub struct CMACAES256;

/// Keys a fresh CMAC instance and feeds it `message`. The key argument is
/// zeroized when it is dropped; the AES key schedule and the CMAC state are
/// zeroized by `aes` / `cmac` on drop (their `zeroize` features).
fn keyed<M: KeyInit + Mac>(key: Vec<u8>, message: &[u8]) -> CasResult<M> {
    let key = Zeroizing::new(key);
    let mut mac = <M as KeyInit>::new_from_slice(&key).map_err(|_| CasError::InvalidKey)?;
    mac.update(message);
    Ok(mac)
}

impl CASCMAC for CMACAES128 {
    /// Computes the AES-128-CMAC tag of `message`. `key` must be 16 bytes.
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>> {
        Ok(keyed::<Cmac<Aes128>>(key, &message)?.finalize().into_bytes().to_vec())
    }

    /// Verifies a 16-byte AES-128-CMAC tag in constant time. `key` must be 16 bytes.
    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        Ok(keyed::<Cmac<Aes128>>(key, &message)?.verify_slice(&signature).is_ok())
    }
}

impl CASCMAC for CMACAES256 {
    /// Computes the AES-256-CMAC tag of `message`. `key` must be 32 bytes.
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>> {
        Ok(keyed::<Cmac<Aes256>>(key, &message)?.finalize().into_bytes().to_vec())
    }

    /// Verifies a 16-byte AES-256-CMAC tag in constant time. `key` must be 32 bytes.
    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        Ok(keyed::<Cmac<Aes256>>(key, &message)?.verify_slice(&signature).is_ok())
    }
}
