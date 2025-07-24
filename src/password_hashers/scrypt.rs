use std::sync::mpsc;



use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};

use super::cas_password_hasher::CASPasswordHasher;

pub struct CASScrypt;

impl CASPasswordHasher for CASScrypt {
    /// Hashes a password using Scrypt.
    /// Returns the hashed password as a string.
    fn hash_password(password_to_hash: String) -> String {
        let salt = SaltString::generate(&mut OsRng);
        return Scrypt
            .hash_password(password_to_hash.as_bytes(), &salt)
            .unwrap()
            .to_string();
    }

    /// Verifies a password against a hashed password using Scrypt.
    /// Returns true if the password matches the hashed password, false otherwise.
    fn verify_password(hashed_password: String, password_to_verify: String) -> bool {
        let parsed_hash = PasswordHash::new(&hashed_password).unwrap();
        return Scrypt
            .verify_password(password_to_verify.as_bytes(), &parsed_hash)
            .is_ok();
    }

    /// Hashes a password using Scrypt on the threadpool.
    /// Returns the hashed password as a string.
    fn hash_password_threadpool(password: String) -> String {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let hash = Self::hash_password(password);
            sender.send(hash).unwrap();
        });
        let hash = receiver.recv().unwrap();
        hash
    }

    /// Verifies a password against a hashed password using Scrypt on the threadpool.
    /// Returns true if the password matches the hashed password, false otherwise.
    fn verify_password_threadpool(hashed_password: String, password_to_verify: String) -> bool {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let hash = Self::verify_password(hashed_password, password_to_verify);
            sender.send(hash).unwrap();
        });
        let hash = receiver.recv().unwrap();
        hash
    }
}