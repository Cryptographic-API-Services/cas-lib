use crate::error::{CasError, CasResult};
use super::cas_hmac::CASHMAC;
use hmac::{Hmac, KeyInit, Mac, SimpleHmac};
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};
use zeroize::Zeroizing;

// SHA-2 uses `Hmac`, which needs the hash's block-level core. sha3 0.12 no
// longer exposes one, so SHA-3 uses `SimpleHmac`, which computes the same HMAC
// (RFC 2104) over any `Digest`.

/// HMAC-SHA-256: 32-byte tag.
pub struct HMACSha256;
/// HMAC-SHA-384: 48-byte tag.
pub struct HMACSha384;
/// HMAC-SHA-512: 64-byte tag.
pub struct HMACSha512;

/// HMAC-SHA3-256: 32-byte tag.
pub struct HMACSha3_256;
/// HMAC-SHA3-384: 48-byte tag.
pub struct HMACSha3_384;
/// HMAC-SHA3-512: 64-byte tag.
pub struct HMACSha3_512;

/// HMAC-SHA-256, under its previous name.
#[deprecated(note = "renamed to `HMACSha256`")]
pub type HMAC = HMACSha256;

/// Keys a fresh MAC instance and feeds it `message`. The key argument is
/// zeroized when it is dropped.
fn keyed<M: KeyInit + Mac>(key: Vec<u8>, message: &[u8]) -> CasResult<M> {
    let key = Zeroizing::new(key);
    let mut mac = <M as KeyInit>::new_from_slice(&key).map_err(|_| CasError::InvalidKey)?;
    mac.update(message);
    Ok(mac)
}

impl CASHMAC for HMACSha256 {
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>> {
        Ok(keyed::<Hmac<Sha256>>(key, &message)?.finalize().into_bytes().to_vec())
    }

    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        Ok(keyed::<Hmac<Sha256>>(key, &message)?.verify_slice(&signature).is_ok())
    }
}

impl CASHMAC for HMACSha384 {
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>> {
        Ok(keyed::<Hmac<Sha384>>(key, &message)?.finalize().into_bytes().to_vec())
    }

    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        Ok(keyed::<Hmac<Sha384>>(key, &message)?.verify_slice(&signature).is_ok())
    }
}

impl CASHMAC for HMACSha512 {
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>> {
        Ok(keyed::<Hmac<Sha512>>(key, &message)?.finalize().into_bytes().to_vec())
    }

    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        Ok(keyed::<Hmac<Sha512>>(key, &message)?.verify_slice(&signature).is_ok())
    }
}

impl CASHMAC for HMACSha3_256 {
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>> {
        Ok(keyed::<SimpleHmac<Sha3_256>>(key, &message)?.finalize().into_bytes().to_vec())
    }

    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        Ok(keyed::<SimpleHmac<Sha3_256>>(key, &message)?.verify_slice(&signature).is_ok())
    }
}

impl CASHMAC for HMACSha3_384 {
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>> {
        Ok(keyed::<SimpleHmac<Sha3_384>>(key, &message)?.finalize().into_bytes().to_vec())
    }

    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        Ok(keyed::<SimpleHmac<Sha3_384>>(key, &message)?.verify_slice(&signature).is_ok())
    }
}

impl CASHMAC for HMACSha3_512 {
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>> {
        Ok(keyed::<SimpleHmac<Sha3_512>>(key, &message)?.finalize().into_bytes().to_vec())
    }

    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        Ok(keyed::<SimpleHmac<Sha3_512>>(key, &message)?.verify_slice(&signature).is_ok())
    }
}