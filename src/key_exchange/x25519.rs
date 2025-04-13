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
    fn generate_secret_and_public_key() -> X25519SecretPublicKeyResult {
        let secret_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);
        let result = X25519SecretPublicKeyResult {
            secret_key: secret_key.as_bytes().to_vec(),
            public_key: public_key.as_bytes().to_vec(),
        };
        result
    }

    fn diffie_hellman(my_secret_key: Vec<u8>, users_public_key: Vec<u8>) -> [u8; 32] {
        let mut secret_key_array: [u8; 32] = Default::default();
        secret_key_array.copy_from_slice(&my_secret_key);
        let mut users_public_key_array: [u8; 32] = Default::default();
        users_public_key_array.copy_from_slice(&users_public_key);

        let secret_key = StaticSecret::from(secret_key_array);
        let public_key = PublicKey::from(users_public_key_array);
        return secret_key.diffie_hellman(&public_key).to_bytes();
    }
    
    fn generate_secret_and_public_key_threadpool() -> X25519SecretPublicKeyResult {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = <X25519 as CASKeyExchange>::generate_secret_and_public_key();
            sender.send(result);
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    fn diffie_hellman_threadpool(my_secret_key: Vec<u8>, users_public_key: Vec<u8>) -> [u8; 32] {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = <X25519 as CASKeyExchange>::diffie_hellman(my_secret_key, users_public_key);
            sender.send(result);
        });
        let result = receiver.recv().unwrap();
        result
    }
}