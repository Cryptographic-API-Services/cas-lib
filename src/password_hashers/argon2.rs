use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier, Params
};
use rand::RngCore;


pub struct CASArgon;

impl CASArgon {

    /// Hashes a password using Argon2 with custom parameters.
    /// Returns the hashed password as a string.
    /// Parameters:
    /// - memory_cost: Memory cost in kibibytes.
    /// - iterations: Number of iterations.
    /// - parallelism: Degree of parallelism.
    /// - password_to_hash: The password to be hashed.
    pub fn hash_password_parameters(memory_cost: u32, iterations: u32, parallelism: u32, password_to_hash: String) -> String {
        let params = Params::new(memory_cost * 1024, iterations, parallelism, None).unwrap();
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let hash = argon2.hash_password(password_to_hash.as_bytes(), &salt).unwrap();
        hash.to_string()
    }
    /// Derives a 128-bit AES key from a password using Argon2.
    /// Returns the derived key as a vector of bytes.
    pub fn derive_aes_128_key(password: Vec<u8>) -> Vec<u8> {
        let mut rng = OsRng;
        let mut salt: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut salt);

        let mut key = Box::new([0u8; 16]);
        Argon2::default().hash_password_into(password.as_ref(), &salt, &mut *key).unwrap();
        key.to_vec()
    }

    /// Derives a 256-bit AES key from a password using Argon2.
    /// Returns the derived key as a vector of bytes.
    pub fn derive_aes_256_key(password: Vec<u8>) -> Vec<u8> {
        let mut rng = OsRng;
        let mut salt: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut salt);

        let mut key = Box::new([0u8; 32]);
        Argon2::default().hash_password_into(password.as_ref(), &salt, &mut *key).unwrap();
        key.to_vec()
    }

    /// Hashes a password using Argon2.
    /// Returns the hashed password as a string.
    pub fn hash_password(password_to_hash: String) -> String {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hashed_password = argon2
            .hash_password(password_to_hash.as_bytes(), &salt)
            .unwrap()
            .to_string();
        return hashed_password;
    }

    /// Verifies a password against a hashed password using Argon2.
    /// Returns true if the password matches the hashed password, false otherwise.
    pub fn verify_password(hashed_password: String, password_to_verify: String) -> bool {
        let hashed_password = PasswordHash::new(&hashed_password).unwrap();
        return Argon2::default()
            .verify_password(password_to_verify.as_bytes(), &hashed_password)
            .is_ok();
    }
}