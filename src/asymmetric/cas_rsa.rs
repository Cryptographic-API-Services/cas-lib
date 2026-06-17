use rand::rngs::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    RsaPublicKey,
};
use rsa::{Pkcs1v15Sign, RsaPrivateKey};

use crate::error::{CasError, CasResult};

use super::types::{CASRSAEncryption, RSAKeyPairResult};

/// The smallest RSA modulus size (in bits) this library will generate.
/// Keys below 2048 bits are considered insecure.
const MIN_RSA_KEY_SIZE: usize = 2048;

pub struct CASRSA;

impl CASRSAEncryption for CASRSA {
    /// Generates an RSA key pair of the specified size.
    /// The key size must be at least 2048 bits; smaller sizes are rejected with
    /// [`CasError::InvalidParameters`].
    fn generate_rsa_keys(key_size: usize) -> CasResult<RSAKeyPairResult> {
        if key_size < MIN_RSA_KEY_SIZE {
            return Err(CasError::InvalidParameters);
        }
        if key_size != 2048 && key_size != 3072 && key_size != 4096 {
            return Err(CasError::InvalidParameters);
        }
        let mut rng: OsRng = OsRng;
        let private_key: RsaPrivateKey =
            RsaPrivateKey::new(&mut rng, key_size).map_err(|_| CasError::KeyGenerationFailed)?;
        let public_key: RsaPublicKey = private_key.to_public_key();
        Ok(RSAKeyPairResult {
            public_key: public_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .map_err(|_| CasError::InvalidPemKey)?
                .to_string(),
            private_key: private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .map_err(|_| CasError::InvalidPemKey)?
                .to_string(),
        })
    }

    /// Sign the given hash with the provided private key of the RSA key pair.
    /// The parameter `hash` doesn't necessarily have to be a hash, it can be any data that you want to sign.
    fn sign(private_key: String, hash: Vec<u8>) -> CasResult<Vec<u8>> {
        let private_key =
            RsaPrivateKey::from_pkcs8_pem(&private_key).map_err(|_| CasError::InvalidPemKey)?;
        private_key
            .sign(Pkcs1v15Sign::new_unprefixed(), &hash)
            .map_err(|_| CasError::SigningFailed)
    }


    /// Verify the signature of the given hash with the provided public key of the RSA key pair.
    /// The parameter `hash` doesn't necessarily have to be a hash, it can be any data that you want to verify.
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is not, and an
    /// error if the public key could not be parsed.
    fn verify(public_key: String, hash: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        let public_key =
            RsaPublicKey::from_pkcs1_pem(&public_key).map_err(|_| CasError::InvalidPemKey)?;
        Ok(public_key
            .verify(Pkcs1v15Sign::new_unprefixed(), &hash, &signature)
            .is_ok())
    }
}
