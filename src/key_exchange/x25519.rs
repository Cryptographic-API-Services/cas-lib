

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{CasError, CasResult};
use super::cas_key_exchange::CASKeyExchange;

pub struct X25519SecretPublicKeyResult {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub struct X25519;

impl CASKeyExchange for X25519 {
    /// Generates a secret key and public key using X25519.
    /// Returns a result containing the secret key and public key as vectors of bytes.
    fn generate_secret_and_public_key() -> X25519SecretPublicKeyResult {
        let secret_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);
        let result = X25519SecretPublicKeyResult {
            secret_key: secret_key.as_bytes().to_vec(),
            public_key: public_key.as_bytes().to_vec(),
        };
        result
    }

    /// Performs a Diffie-Hellman key exchange using the provided secret key and user's public key.
    /// Returns the shared secret as a vector of bytes, or an error if either input
    /// is not 32 bytes long.
    /// The secret key and user's public key are expected to be in byte array format.
    fn diffie_hellman(my_secret_key: Vec<u8>, users_public_key: Vec<u8>) -> CasResult<Vec<u8>> {
        let secret_key_bytes: [u8; 32] =
            my_secret_key.try_into().map_err(|_| CasError::InvalidKey)?;
        let public_key_bytes: [u8; 32] =
            users_public_key.try_into().map_err(|_| CasError::InvalidKey)?;

        let secret_key = StaticSecret::from(secret_key_bytes);
        let public_key = PublicKey::from(public_key_bytes);
        Ok(secret_key.diffie_hellman(&public_key).as_bytes().to_vec())
    }
}
