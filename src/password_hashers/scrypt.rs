




use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt, Params
};

use crate::error::{CasError, CasResult};

pub struct CASScrypt;

impl CASScrypt {
    /// Hashes a passwith using Scrypt with custom params.
    /// Parameters:
    /// - password_to_hash: The password to be hashed.
    /// - cpu_memory_cost: log₂ of the Scrypt parameter `N`, the work factor.
    /// - block_size: `r` parameter: resource usage.
    /// - parallelism: `p` parameter: parallelization.
    pub fn hash_password_customized(password_to_hash: String, cpu_memory_cost: u8, block_size: u32, parallelism: u32) -> CasResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(cpu_memory_cost, block_size, parallelism, 32)
            .map_err(|_| CasError::InvalidParameters)?;
        Ok(Scrypt
            .hash_password_customized(password_to_hash.as_bytes(), None, None, params, &salt)
            .map_err(|_| CasError::PasswordHashingFailed)?
            .to_string())
    }

    /// Hashes a password using Scrypt.
    /// Returns the hashed password as a string.
    pub fn hash_password(password_to_hash: String) -> CasResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        Ok(Scrypt
            .hash_password(password_to_hash.as_bytes(), &salt)
            .map_err(|_| CasError::PasswordHashingFailed)?
            .to_string())
    }

    /// Verifies a password against a hashed password using Scrypt.
    /// Returns `Ok(true)` if the password matches, `Ok(false)` if it does not, and
    /// an error if the stored hash could not be parsed.
    pub fn verify_password(hashed_password: String, password_to_verify: String) -> CasResult<bool> {
        let parsed_hash =
            PasswordHash::new(&hashed_password).map_err(|_| CasError::PasswordHashingFailed)?;
        Ok(Scrypt
            .verify_password(password_to_verify.as_bytes(), &parsed_hash)
            .is_ok())
    }
}
