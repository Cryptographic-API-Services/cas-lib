use std::sync::mpsc;

use bcrypt::{hash, verify, DEFAULT_COST};

use super::cas_password_hasher::CASPasswordHasher;

pub struct CASBCrypt;

impl CASPasswordHasher for CASBCrypt {
    /// Hashes a password using bcrypt.
    /// Returns the hashed password as a string.
    fn hash_password(password_to_hash: String) -> String {
        return hash(password_to_hash, DEFAULT_COST).unwrap();
    }

    /// Verifies a password against a hashed password using bcrypt.
    /// Returns true if the password matches the hashed password, false otherwise.
    fn verify_password(hashed_password: String, password_to_verify: String) -> bool {
        return verify(password_to_verify, &hashed_password).unwrap();
    }

    /// Hashes a password using bcrypt on the threadpool.
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

    /// Verifies a password against a hashed password using bcrypt on the threadpool.
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
