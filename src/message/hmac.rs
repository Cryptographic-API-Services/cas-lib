
use super::cas_hmac::CASHMAC;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
pub struct HMAC;

impl CASHMAC for HMAC {
    /// Signs a message using HMAC with SHA-256.
    /// Returns the signature as a vector of bytes.
    fn sign(key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&message);
        let result = mac.finalize().into_bytes().to_vec();
        result
    }

    

    /// Verifies a signature using HMAC with SHA-256.
    /// Returns true if the signature is valid, false otherwise.
    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&message);
        return mac.verify_slice(&signature).is_ok();
    }


}
