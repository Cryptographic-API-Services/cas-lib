
use crate::error::{CasError, CasResult};
use super::cas_hmac::CASHMAC;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;
pub struct HMAC;
pub struct HMACSha512;

impl CASHMAC for HMAC {
    /// Signs a message using HMAC with SHA-256.
    /// Returns the signature as a vector of bytes.
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&key).map_err(|_| CasError::InvalidKey)?;
        mac.update(&message);
        Ok(mac.finalize().into_bytes().to_vec())
    }



    /// Verifies a signature using HMAC with SHA-256.
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is not, and
    /// an error if the key could not be used.
    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        let mut mac = HmacSha256::new_from_slice(&key).map_err(|_| CasError::InvalidKey)?;
        mac.update(&message);
        Ok(mac.verify_slice(&signature).is_ok())
    }


}

impl CASHMAC for HMACSha512 {
    /// Signs a message using HMAC with SHA2-512.
    /// Returns the signature as a vector of bytes.
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>> {
        let mut mac = HmacSha512::new_from_slice(&key).map_err(|_| CasError::InvalidKey)?;
        mac.update(&message);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Verifies a signature using HMAC with SHA2-512.
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is not, and
    /// an error if the key could not be used.
    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        let mut mac = HmacSha512::new_from_slice(&key).map_err(|_| CasError::InvalidKey)?;
        mac.update(&message);
        Ok(mac.verify_slice(&signature).is_ok())
    }
}
