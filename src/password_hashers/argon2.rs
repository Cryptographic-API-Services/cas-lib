


use std::sync::mpsc;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use rand::RngCore;


pub struct CASArgon;

impl CASArgon {

    pub fn derive_aes_128_key(password: Vec<u8>) -> Vec<u8> {
        let mut rng = OsRng;
        let mut salt: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut salt);

        let mut key = Box::new([0u8; 16]);
        Argon2::default().hash_password_into(password.as_ref(), &salt, &mut *key).unwrap();
        key.to_vec()
    }

    pub fn derive_aes_256_key(password: Vec<u8>) -> Vec<u8> {
        let mut rng = OsRng;
        let mut salt: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut salt);

        let mut key = Box::new([0u8; 32]);
        Argon2::default().hash_password_into(password.as_ref(), &salt, &mut *key).unwrap();
        key.to_vec()
    }

    pub fn hash_password(password_to_hash: String) -> String {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hashed_password = argon2
            .hash_password(password_to_hash.as_bytes(), &salt)
            .unwrap()
            .to_string();
        return hashed_password;
    }

    pub fn verify_password(hashed_password: String, password_to_verify: String) -> bool {
        let hashed_password = PasswordHash::new(&hashed_password).unwrap();
        return Argon2::default()
            .verify_password(password_to_verify.as_bytes(), &hashed_password)
            .is_ok();
    }
    
    pub fn hash_password_threadpool(password: String) -> String {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let hash = Self::hash_password(password);
            sender.send(hash).unwrap();
        });
        let hash = receiver.recv().unwrap();
        hash
    }
    
    pub fn verify_password_threadpool(hashed_password: String, password_to_verify: String) -> bool {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let hash = Self::verify_password(hashed_password, password_to_verify);
            sender.send(hash).unwrap();
        });
        let hash = receiver.recv().unwrap();
        hash
    }
}