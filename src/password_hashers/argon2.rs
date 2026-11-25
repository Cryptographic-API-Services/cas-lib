use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier, Params
};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{CasError, CasResult};

/// The smallest `memory_cost`, in MiB, [`CASArgon::hash_password_parameters`] accepts
/// (the OWASP minimum for Argon2id).
pub const MIN_MEMORY_COST_MIB: u32 = 19;
/// The largest `memory_cost`, in MiB, accepted when hashing or found in a stored hash
/// being verified: 4 GiB.
pub const MAX_MEMORY_COST_MIB: u32 = 4096;
/// The smallest iteration count accepted when hashing.
pub const MIN_ITERATIONS: u32 = 1;
/// The largest iteration count accepted when hashing or verifying.
pub const MAX_ITERATIONS: u32 = 10;
/// The smallest degree of parallelism accepted when hashing.
pub const MIN_PARALLELISM: u32 = 1;
/// The largest degree of parallelism accepted when hashing or verifying.
pub const MAX_PARALLELISM: u32 = 16;

pub struct CASArgon;

impl CASArgon {

    /// Hashes a password using Argon2id with custom parameters.
    /// Returns the hashed password as a PHC string.
    /// Parameters:
    /// - memory_cost: Memory cost in **mebibytes (MiB)**, from [`MIN_MEMORY_COST_MIB`]
    ///   (19) to [`MAX_MEMORY_COST_MIB`] (4096). It is converted to the KiB value Argon2
    ///   uses, so `64` means 64 MiB.
    /// - iterations: Number of iterations, from [`MIN_ITERATIONS`] (1) to
    ///   [`MAX_ITERATIONS`] (10).
    /// - parallelism: Degree of parallelism, from [`MIN_PARALLELISM`] (1) to
    ///   [`MAX_PARALLELISM`] (16).
    /// - password_to_hash: The password to be hashed.
    ///
    /// Returns [`CasError::InvalidParameters`] for a parameter outside its range, so a
    /// caller-chosen cost can't exhaust memory or tie up a thread for hours.
    pub fn hash_password_parameters(memory_cost: u32, iterations: u32, parallelism: u32, password_to_hash: String) -> CasResult<String> {
        if !(MIN_MEMORY_COST_MIB..=MAX_MEMORY_COST_MIB).contains(&memory_cost)
            || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
            || !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&parallelism)
        {
            return Err(CasError::InvalidParameters);
        }
        // MiB -> KiB. A plain multiply wraps in release builds (4_194_305 MiB becomes
        // 1 MiB) and panics in debug builds, so check it.
        let memory_cost_kib = memory_cost
            .checked_mul(1024)
            .ok_or(CasError::InvalidParameters)?;
        let params = Params::new(memory_cost_kib, iterations, parallelism, None)
            .map_err(|_| CasError::InvalidParameters)?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let hash = argon2
            .hash_password(password_to_hash.as_bytes(), &salt)
            .map_err(|_| CasError::PasswordHashingFailed)?;
        Ok(hash.to_string())
    }
    /// Derives a 128-bit AES key from a password using Argon2.
    /// Returns the derived key as a vector of bytes.
    ///
    /// The returned key is secret and owned by the caller, who must zeroize it when done
    /// (FFI layers: before freeing it). See the crate-level docs.
    pub fn derive_aes_128_key(password: Vec<u8>) -> CasResult<Vec<u8>> {
        let password = Zeroizing::new(password);
        let mut rng = OsRng;
        let mut salt: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut salt);

        let mut key = Zeroizing::new(vec![0u8; 16]);
        Argon2::default()
            .hash_password_into(password.as_ref(), &salt, &mut key)
            .map_err(|_| CasError::PasswordHashingFailed)?;
        // Hand the buffer to the caller without leaving an unzeroed copy behind.
        Ok(std::mem::take(&mut *key))
    }

    /// Derives a 256-bit AES key from a password using Argon2.
    /// Returns the derived key as a vector of bytes.
    ///
    /// The returned key is secret and owned by the caller, who must zeroize it when done
    /// (FFI layers: before freeing it). See the crate-level docs.
    pub fn derive_aes_256_key(password: Vec<u8>) -> CasResult<Vec<u8>> {
        let password = Zeroizing::new(password);
        let mut rng = OsRng;
        let mut salt: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut salt);

        let mut key = Zeroizing::new(vec![0u8; 32]);
        Argon2::default()
            .hash_password_into(password.as_ref(), &salt, &mut key)
            .map_err(|_| CasError::PasswordHashingFailed)?;
        // Hand the buffer to the caller without leaving an unzeroed copy behind.
        Ok(std::mem::take(&mut *key))
    }

    /// Hashes a password using Argon2.
    /// Returns the hashed password as a string.
    pub fn hash_password(password_to_hash: String) -> CasResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hashed_password = argon2
            .hash_password(password_to_hash.as_bytes(), &salt)
            .map_err(|_| CasError::PasswordHashingFailed)?
            .to_string();
        Ok(hashed_password)
    }

    /// Verifies a password against a hashed password using Argon2.
    /// Returns `Ok(true)` if the password matches and `Ok(false)` if it does not.
    ///
    /// The cost parameters come from the stored hash, so they are checked against the
    /// same upper bounds as hashing before any work is done: a hash from an untrusted
    /// source can't make this call allocate up to 4 TiB or run for hours. Returns
    /// [`CasError::InvalidParameters`] if the hash exceeds [`MAX_MEMORY_COST_MIB`],
    /// [`MAX_ITERATIONS`] or [`MAX_PARALLELISM`], and
    /// [`CasError::PasswordHashingFailed`] if it could not be parsed. Hashes below the
    /// hashing minimums still verify, so older hashes keep working.
    pub fn verify_password(hashed_password: String, password_to_verify: String) -> CasResult<bool> {
        let hashed_password =
            PasswordHash::new(&hashed_password).map_err(|_| CasError::PasswordHashingFailed)?;
        let params =
            Params::try_from(&hashed_password).map_err(|_| CasError::PasswordHashingFailed)?;
        if params.m_cost() > MAX_MEMORY_COST_MIB * 1024
            || params.t_cost() > MAX_ITERATIONS
            || params.p_cost() > MAX_PARALLELISM
        {
            return Err(CasError::InvalidParameters);
        }
        Ok(Argon2::default()
            .verify_password(password_to_verify.as_bytes(), &hashed_password)
            .is_ok())
    }
}
