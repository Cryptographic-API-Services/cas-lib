



use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt, Params
};

pub struct CASScrypt;

impl CASScrypt {
    /// Hashes a passwith using Scrypt with custom params.
    /// Parameters:
    /// - password_to_hash: The password to be hashed.
    /// - cpu_memory_cost: log₂ of the Scrypt parameter `N`, the work factor.
    /// - block_size: `r` parameter: resource usage.
    /// - parallelism: `p` parameter: parallelization.
    pub fn hash_password_customized(password_to_hash: String, cpu_memory_cost: u8, block_size: u32, parallelism: u32) -> String {
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(cpu_memory_cost, block_size, parallelism, 32).unwrap();
        return Scrypt.hash_password_customized(password_to_hash.as_bytes(), None, None, params, &salt).unwrap().to_string();
    }

    /// Hashes a password using Scrypt.
    /// Returns the hashed password as a string.
    pub fn hash_password(password_to_hash: String) -> String {
        let salt = SaltString::generate(&mut OsRng);
        return Scrypt
            .hash_password(password_to_hash.as_bytes(), &salt)
            .unwrap()
            .to_string();
    }

    /// Verifies a password against a hashed password using Scrypt.
    /// Returns true if the password matches the hashed password, false otherwise.
    pub fn verify_password(hashed_password: String, password_to_verify: String) -> bool {
        let parsed_hash = PasswordHash::new(&hashed_password).unwrap();
        return Scrypt
            .verify_password(password_to_verify.as_bytes(), &parsed_hash)
            .is_ok();
    }
}