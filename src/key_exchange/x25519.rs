use std::sync::mpsc;

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

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
    /// Returns the shared secret as a vector of bytes.
    /// The shared secret is computed as the Diffie-Hellman result of the secret key and the user's public key.
    /// The secret key and user's public key are expected to be in byte array format.
    fn diffie_hellman(my_secret_key: Vec<u8>, users_public_key: Vec<u8>) -> Vec<u8> {
        let mut secret_key_box = Box::new([0u8; 32]);
        secret_key_box.copy_from_slice(&my_secret_key);
        let mut users_public_key_box = Box::new([0u8; 32]);
        users_public_key_box.copy_from_slice(&users_public_key);

        let secret_key = StaticSecret::from(*secret_key_box);
        let public_key = PublicKey::from(*users_public_key_box);
        return secret_key.diffie_hellman(&public_key).as_bytes().to_vec();
    }
}