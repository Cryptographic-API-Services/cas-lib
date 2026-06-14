

use bcrypt::{hash, verify, DEFAULT_COST};

use crate::error::{CasError, CasResult};

pub struct CASBCrypt;

impl CASBCrypt {
    /// Hashes a password using bcrypt with a customized cost.
    /// Parameters:
    /// - password_to_hash: The password to be hashed.
    /// - cost: The cost parameter for bcrypt (default is 12 and max is 31).
    /// Returns the hashed password as a string.
    pub fn hash_password_customized(password_to_hash: String, cost: u32) -> CasResult<String> {
        hash(password_to_hash, cost).map_err(|_| CasError::PasswordHashingFailed)
    }

    /// Hashes a password using bcrypt.
    /// Returns the hashed password as a string.
    pub fn hash_password(password_to_hash: String) -> CasResult<String> {
        hash(password_to_hash, DEFAULT_COST).map_err(|_| CasError::PasswordHashingFailed)
    }

    /// Verifies a password against a hashed password using bcrypt.
    /// Returns `Ok(true)` if the password matches, `Ok(false)` if it does not, and
    /// an error if the stored hash could not be parsed.
    pub fn verify_password(hashed_password: String, password_to_verify: String) -> CasResult<bool> {
        verify(password_to_verify, &hashed_password).map_err(|_| CasError::PasswordHashingFailed)
    }
}
