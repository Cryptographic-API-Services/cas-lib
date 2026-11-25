use getrandom::SysRng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    sha2::Sha256,
    traits::PublicKeyParts,
    PrivateKey, PublicKey,
};
use zeroize::Zeroizing;

use crate::error::{CasError, CasResult};

use super::types::{CASRSAEncryption, RSAKeyPairResult};

/// The smallest RSA modulus size (in bits) this library will generate, sign
/// with or verify against. Keys below 2048 bits are considered insecure.
const MIN_RSA_KEY_SIZE: usize = 2048;

/// Rejects a parsed key whose modulus is smaller than [`MIN_RSA_KEY_SIZE`].
fn ensure_min_key_size(key: &impl PublicKeyParts) -> CasResult<()> {
    // The modulus is public, so a variable-time bit count is fine here.
    if (key.n().bit_width_vartime() as usize) < MIN_RSA_KEY_SIZE {
        return Err(CasError::InvalidParameters);
    }
    Ok(())
}

/// Parses a PKCS#8 PEM private key and checks its size. The PEM string is
/// zeroized once it has been parsed; the parsed key zeroizes itself on drop.
fn parse_private_key(private_key: String) -> CasResult<PrivateKey> {
    let pem = Zeroizing::new(private_key);
    let private_key = PrivateKey::from_pkcs8_pem(&pem).map_err(|_| CasError::InvalidPemKey)?;
    ensure_min_key_size(&private_key)?;
    Ok(private_key)
}

/// Parses a PKCS#1 PEM public key and checks its size.
fn parse_public_key(public_key: &str) -> CasResult<PublicKey> {
    let public_key = PublicKey::from_pkcs1_pem(public_key).map_err(|_| CasError::InvalidPemKey)?;
    ensure_min_key_size(&public_key)?;
    Ok(public_key)
}

pub struct CASRSA;

impl CASRSAEncryption for CASRSA {
    /// Generates an RSA key pair of the specified size.
    /// The key size must be 2048, 3072 or 4096 bits; other sizes are rejected
    /// with [`CasError::InvalidParameters`].
    fn generate_rsa_keys(key_size: usize) -> CasResult<RSAKeyPairResult> {
        if key_size < MIN_RSA_KEY_SIZE {
            return Err(CasError::InvalidParameters);
        }
        if key_size != 2048 && key_size != 3072 && key_size != 4096 {
            return Err(CasError::InvalidParameters);
        }
        let private_key =
            PrivateKey::new(&mut SysRng, key_size).map_err(|_| CasError::KeyGenerationFailed)?;
        let public_key = private_key
            .to_public_key()
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map_err(|_| CasError::InvalidPemKey)?;
        // `to_pkcs8_pem` returns a `Zeroizing<String>`; move the string out
        // rather than copying it, so no unzeroized copy is left behind.
        let mut private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|_| CasError::InvalidPemKey)?;
        Ok(RSAKeyPairResult {
            public_key,
            private_key: std::mem::take(&mut *private_pem),
        })
    }

    /// Signs `message` with RSASSA-PKCS1-v1_5 and SHA-256 (JWS `RS256`).
    ///
    /// The message is hashed inside the library and the signature carries the
    /// standard `DigestInfo` prefix, so it verifies with OpenSSL, WebCrypto and
    /// other RS256 implementations. Pass the message itself, not a digest of
    /// it. The message can be any length.
    ///
    /// Returns [`CasError::InvalidPemKey`] if the PKCS#8 PEM private key cannot
    /// be parsed, [`CasError::InvalidParameters`] if its modulus is smaller
    /// than 2048 bits and [`CasError::SigningFailed`] if signing fails.
    fn sign(private_key: String, message: Vec<u8>) -> CasResult<Vec<u8>> {
        let private_key = parse_private_key(private_key)?;
        private_key
            .pkcs1v15_sign::<Sha256>(&message)
            .map_err(|_| CasError::SigningFailed)
    }

    /// Verifies an RSASSA-PKCS1-v1_5 SHA-256 (`RS256`) `signature` over
    /// `message`, as produced by [`CASRSA::sign`] or any standard RS256 signer.
    ///
    /// Returns `Ok(true)` if the signature is valid and `Ok(false)` if it is not.
    /// Returns [`CasError::InvalidPemKey`] if the PKCS#1 PEM public key cannot be
    /// parsed and [`CasError::InvalidParameters`] if its modulus is smaller than
    /// 2048 bits.
    fn verify(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        let public_key = parse_public_key(&public_key)?;
        Ok(public_key
            .pkcs1v15_verify::<Sha256>(&message, &signature)
            .is_ok())
    }

    /// Signs `message` with RSASSA-PSS, SHA-256, MGF1-SHA-256 and a 32-byte
    /// random salt (JWS `PS256`). Recommended over [`CASRSA::sign`] for new
    /// designs. PSS signatures are randomized, so signing the same message
    /// twice gives different signatures; both verify.
    ///
    /// The message is hashed inside the library and can be any length.
    ///
    /// Returns [`CasError::InvalidPemKey`] if the PKCS#8 PEM private key cannot
    /// be parsed, [`CasError::InvalidParameters`] if its modulus is smaller
    /// than 2048 bits and [`CasError::SigningFailed`] if signing fails.
    fn sign_pss(private_key: String, message: Vec<u8>) -> CasResult<Vec<u8>> {
        let private_key = parse_private_key(private_key)?;
        private_key
            .pss_sign::<Sha256>(&message)
            .map_err(|_| CasError::SigningFailed)
    }

    /// Verifies an RSASSA-PSS SHA-256 (`PS256`) `signature` over `message`, as
    /// produced by [`CASRSA::sign_pss`]. The signature must use MGF1-SHA-256
    /// and a 32-byte salt; other salt lengths are rejected.
    ///
    /// Returns `Ok(true)` if the signature is valid and `Ok(false)` if it is not.
    /// Returns [`CasError::InvalidPemKey`] if the PKCS#1 PEM public key cannot be
    /// parsed and [`CasError::InvalidParameters`] if its modulus is smaller than
    /// 2048 bits.
    fn verify_pss(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        let public_key = parse_public_key(&public_key)?;
        Ok(public_key.pss_verify::<Sha256>(&message, &signature).is_ok())
    }
}
