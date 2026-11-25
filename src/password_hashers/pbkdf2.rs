use argon2::password_hash::SaltString;
use pbkdf2::pbkdf2_hmac_array;
use rand::rngs::OsRng;
use sha3::Sha3_256;

use super::cas_password_hasher::Pbkdf2Result;
use crate::error::{CasError, CasResult};

/// The smallest iteration count `derivation` and `derivation_with_salt` accept.
///
/// This matches the OWASP recommendation for PBKDF2-HMAC-SHA256; the same
/// floor is applied to the HMAC-SHA3-256 PRF used here.
pub const MIN_ITERATIONS: u32 = 600_000;

/// The shortest salt, in bytes, `derivation_with_salt` accepts.
pub const MIN_SALT_LENGTH: usize = 16;

/// Derives a 256-bit key using PBKDF2-HMAC-SHA3-256 with a freshly generated salt.
/// Returns the derived key and salt as a Pbkdf2Result; store both the salt and the
/// iteration count so the key can be re-derived with `derivation_with_salt`.
///
/// Returns `CasError::InvalidParameters` if `number_of_iterations` is below
/// [`MIN_ITERATIONS`].
pub fn derivation(password_vec: Vec<u8>, number_of_iterations: u32) -> CasResult<Pbkdf2Result> {
    // Use Argon 2 salt and return the salt to the user so they can reuse it.
    let salt = SaltString::generate(&mut OsRng);
    let salt = salt.as_str().as_bytes().to_vec();
    let key = derivation_with_salt(password_vec, number_of_iterations, salt.clone())?;
    Ok(Pbkdf2Result {
        password: key,
        salt,
    })
}

/// Derives a 256-bit key using PBKDF2-HMAC-SHA3-256 with the given salt.
/// Returns the derived key as a vector of bytes.
///
/// Returns `CasError::InvalidParameters` if `number_of_iterations` is below
/// [`MIN_ITERATIONS`] or `salt` is shorter than [`MIN_SALT_LENGTH`] bytes.
pub fn derivation_with_salt(password_vec: Vec<u8>, number_of_iterations: u32, salt: Vec<u8>) -> CasResult<Vec<u8>> {
    if number_of_iterations < MIN_ITERATIONS || salt.len() < MIN_SALT_LENGTH {
        return Err(CasError::InvalidParameters);
    }
    let key = pbkdf2_hmac_array::<Sha3_256, 32>(&password_vec, &salt, number_of_iterations).to_vec();
    Ok(key)
}
