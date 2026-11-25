use crate::error::CasResult;

pub struct RSAKeyPairResult {
    /// PKCS#8 PEM private key.
    pub private_key: String,
    /// PKCS#1 PEM public key.
    pub public_key: String,
}

/// RSA key generation and signatures. Every signing function hashes the
/// message with SHA-256 itself: pass the message, not a digest of it.
pub trait CASRSAEncryption {
    /// Generates a 2048-, 3072- or 4096-bit key pair.
    fn generate_rsa_keys(key_size: usize) -> CasResult<RSAKeyPairResult>;
    /// RSASSA-PKCS1-v1_5 with SHA-256 (`RS256`).
    fn sign(private_key: String, message: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Verifies an RSASSA-PKCS1-v1_5 SHA-256 (`RS256`) signature.
    fn verify(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool>;
    /// RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt (`PS256`).
    /// Recommended for new designs.
    fn sign_pss(private_key: String, message: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Verifies an RSASSA-PSS SHA-256 (`PS256`) signature with a 32-byte salt.
    fn verify_pss(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool>;
}
