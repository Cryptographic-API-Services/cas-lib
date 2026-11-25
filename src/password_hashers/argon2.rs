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

/// Argon2id memory cost, in KiB, of the AES key derivation functions: 19 MiB. With
/// [`KDF_ITERATIONS`] and [`KDF_PARALLELISM`] this is the OWASP minimum for Argon2id and
/// the `argon2` crate's current default. The values are fixed here rather than taken
/// from `Argon2::default()`, so a later `argon2` release can't change the key derived
/// from a stored salt.
pub const KDF_MEMORY_COST_KIB: u32 = 19 * 1024;
/// Argon2id iteration count of the AES key derivation functions.
pub const KDF_ITERATIONS: u32 = 2;
/// Argon2id degree of parallelism of the AES key derivation functions.
pub const KDF_PARALLELISM: u32 = 1;
/// Length, in bytes, of the salt [`CASArgon::generate_salt`] returns.
pub const KDF_SALT_LENGTH: usize = 16;
/// The shortest salt, in bytes, the `derive_aes_*_key_with_salt` functions accept.
pub const MIN_SALT_LENGTH: usize = 16;

/// Argon2id (v0x13) with the fixed `KDF_*` parameters, writing `key_len` bytes.
fn derive_key(password: Vec<u8>, salt: &[u8], key_len: usize) -> CasResult<Vec<u8>> {
    let password = Zeroizing::new(password);
    if salt.len() < MIN_SALT_LENGTH {
        return Err(CasError::InvalidParameters);
    }
    let params = Params::new(KDF_MEMORY_COST_KIB, KDF_ITERATIONS, KDF_PARALLELISM, Some(key_len))
        .map_err(|_| CasError::InvalidParameters)?;
    let mut key = Zeroizing::new(vec![0u8; key_len]);
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_ref(), salt, &mut key)
        .map_err(|_| CasError::PasswordHashingFailed)?;
    // Hand the buffer to the caller without leaving an unzeroed copy behind.
    Ok(std::mem::take(&mut *key))
}

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
    /// Generates a random [`KDF_SALT_LENGTH`]-byte salt for
    /// [`derive_aes_128_key_with_salt`](Self::derive_aes_128_key_with_salt) and
    /// [`derive_aes_256_key_with_salt`](Self::derive_aes_256_key_with_salt).
    ///
    /// The salt is not secret. Store it next to whatever the key protects, and pass
    /// it back with the same password to re-derive the same key.
    pub fn generate_salt() -> Vec<u8> {
        let mut salt = vec![0u8; KDF_SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Derives a 128-bit AES key from a password and salt with Argon2id.
    ///
    /// The same password and salt always give the same key. Use
    /// [`generate_salt`](Self::generate_salt) for a new key, and store the salt to
    /// re-derive it. The cost parameters are fixed: see [`KDF_MEMORY_COST_KIB`].
    ///
    /// Returns [`CasError::InvalidParameters`] if `salt` is shorter than
    /// [`MIN_SALT_LENGTH`] bytes.
    ///
    /// The returned key is secret and owned by the caller, who must zeroize it when done
    /// (FFI layers: before freeing it). See the crate-level docs.
    pub fn derive_aes_128_key_with_salt(password: Vec<u8>, salt: Vec<u8>) -> CasResult<Vec<u8>> {
        derive_key(password, &salt, 16)
    }

    /// Derives a 256-bit AES key from a password and salt with Argon2id.
    ///
    /// The same password and salt always give the same key. Use
    /// [`generate_salt`](Self::generate_salt) for a new key, and store the salt to
    /// re-derive it. The cost parameters are fixed: see [`KDF_MEMORY_COST_KIB`].
    ///
    /// Returns [`CasError::InvalidParameters`] if `salt` is shorter than
    /// [`MIN_SALT_LENGTH`] bytes.
    ///
    /// The returned key is secret and owned by the caller, who must zeroize it when done
    /// (FFI layers: before freeing it). See the crate-level docs.
    pub fn derive_aes_256_key_with_salt(password: Vec<u8>, salt: Vec<u8>) -> CasResult<Vec<u8>> {
        derive_key(password, &salt, 32)
    }

    /// Derives a 128-bit AES key from a password using Argon2, with a random salt that
    /// is **not returned**: the same password never gives the same key again, so this is
    /// a slow random-key generator, not a password-based KDF.
    ///
    /// The returned key is secret and owned by the caller, who must zeroize it when done
    /// (FFI layers: before freeing it). See the crate-level docs.
    #[deprecated(
        since = "0.6.0",
        note = "the salt is discarded, so the key can't be re-derived; use `generate_salt` and `derive_aes_128_key_with_salt`"
    )]
    pub fn derive_aes_128_key(password: Vec<u8>) -> CasResult<Vec<u8>> {
        derive_key(password, &Self::generate_salt(), 16)
    }

    /// Derives a 256-bit AES key from a password using Argon2, with a random salt that
    /// is **not returned**: the same password never gives the same key again, so this is
    /// a slow random-key generator, not a password-based KDF.
    ///
    /// The returned key is secret and owned by the caller, who must zeroize it when done
    /// (FFI layers: before freeing it). See the crate-level docs.
    #[deprecated(
        since = "0.6.0",
        note = "the salt is discarded, so the key can't be re-derived; use `generate_salt` and `derive_aes_256_key_with_salt`"
    )]
    pub fn derive_aes_256_key(password: Vec<u8>) -> CasResult<Vec<u8>> {
        derive_key(password, &Self::generate_salt(), 32)
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
