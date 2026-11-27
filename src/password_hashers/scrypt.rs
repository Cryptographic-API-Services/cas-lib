




use scrypt::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Scrypt, Params
};

use crate::error::{CasError, CasResult};

/// Length, in bytes, of the hash output written into the PHC string.
const OUTPUT_LENGTH: usize = 32;

/// The smallest `cpu_memory_cost` (log₂ N) accepted when hashing.
pub const MIN_LOG_N: u8 = 10;
/// The largest `cpu_memory_cost` (log₂ N) accepted when hashing or found in a stored
/// hash being verified. With [`MAX_BLOCK_SIZE`] that is 128 · 32 · 2^20 bytes = 4 GiB.
pub const MAX_LOG_N: u8 = 20;
/// The largest `block_size` (`r`) accepted when hashing or verifying. The smallest is 1.
pub const MAX_BLOCK_SIZE: u32 = 32;
/// The largest `parallelism` (`p`) accepted when hashing or verifying. The smallest is 1.
pub const MAX_PARALLELISM: u32 = 16;

pub struct CASScrypt;

impl CASScrypt {
    /// Hashes a password using Scrypt with custom params.
    /// Parameters:
    /// - password_to_hash: The password to be hashed.
    /// - cpu_memory_cost: log₂ of the Scrypt parameter `N`, the work factor, from
    ///   [`MIN_LOG_N`] (10) to [`MAX_LOG_N`] (20).
    /// - block_size: `r` parameter: resource usage, from 1 to [`MAX_BLOCK_SIZE`] (32).
    /// - parallelism: `p` parameter: parallelization, from 1 to [`MAX_PARALLELISM`] (16).
    ///
    /// Memory use is about 128 · r · N bytes. Returns [`CasError::InvalidParameters`]
    /// for a parameter outside its range, so a caller-chosen cost can't exhaust memory.
    pub fn hash_password_customized(password_to_hash: String, cpu_memory_cost: u8, block_size: u32, parallelism: u32) -> CasResult<String> {
        if !(MIN_LOG_N..=MAX_LOG_N).contains(&cpu_memory_cost)
            || !(1..=MAX_BLOCK_SIZE).contains(&block_size)
            || !(1..=MAX_PARALLELISM).contains(&parallelism)
        {
            return Err(CasError::InvalidParameters);
        }
        let params = Params::new_with_output_len(cpu_memory_cost, block_size, parallelism, OUTPUT_LENGTH)
            .map_err(|_| CasError::InvalidParameters)?;
        // Draws a 16-byte salt from the OS RNG; an RNG failure is an error, not a panic.
        Ok(Scrypt::new_with_params(params)
            .hash_password(password_to_hash.as_bytes())
            .map_err(|_| CasError::PasswordHashingFailed)?
            .to_string())
    }

    /// Hashes a password using Scrypt.
    /// Returns the hashed password as a string.
    pub fn hash_password(password_to_hash: String) -> CasResult<String> {
        // log₂ N = 17, r = 8, p = 1 (the OWASP recommendation, scrypt's default before
        // 0.12 too), pinned here so a later `scrypt` release can't change it.
        let params = Params::new_with_output_len(17, 8, 1, OUTPUT_LENGTH)
            .map_err(|_| CasError::InvalidParameters)?;
        Ok(Scrypt::new_with_params(params)
            .hash_password(password_to_hash.as_bytes())
            .map_err(|_| CasError::PasswordHashingFailed)?
            .to_string())
    }

    /// Verifies a password against a hashed password using Scrypt.
    /// Returns `Ok(true)` if the password matches and `Ok(false)` if it does not.
    ///
    /// The cost parameters come from the stored hash, so they are checked against the
    /// same upper bounds as hashing before any work is done. Returns
    /// [`CasError::InvalidParameters`] if the hash exceeds [`MAX_LOG_N`],
    /// [`MAX_BLOCK_SIZE`] or [`MAX_PARALLELISM`], and
    /// [`CasError::PasswordHashingFailed`] if it could not be parsed. Hashes below
    /// [`MIN_LOG_N`] still verify, so older hashes keep working.
    pub fn verify_password(hashed_password: String, password_to_verify: String) -> CasResult<bool> {
        let parsed_hash =
            PasswordHash::new(&hashed_password).map_err(|_| CasError::PasswordHashingFailed)?;
        let params =
            Params::try_from(&parsed_hash).map_err(|_| CasError::PasswordHashingFailed)?;
        if params.log_n() > MAX_LOG_N || params.r() > MAX_BLOCK_SIZE || params.p() > MAX_PARALLELISM {
            return Err(CasError::InvalidParameters);
        }
        Ok(Scrypt::new()
            .verify_password(password_to_verify.as_bytes(), &parsed_hash)
            .is_ok())
    }
}
