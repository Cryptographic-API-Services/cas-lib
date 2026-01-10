

use bcrypt::{hash, verify, DEFAULT_COST};

pub struct CASBCrypt;

impl CASBCrypt {
    /// Hashes a password using bcrypt with a customized cost.
    /// Parameters:
    /// - password_to_hash: The password to be hashed.
    /// - cost: The cost parameter for bcrypt (default is 12 and max is 31).
    /// Returns the hashed password as a string.
    pub fn hash_password_customized(password_to_hash: String, cost: u32) -> String {
        return hash(password_to_hash, cost).unwrap();
    }

    /// Hashes a password using bcrypt.
    /// Returns the hashed password as a string.
    pub fn hash_password(password_to_hash: String) -> String {
        return hash(password_to_hash, DEFAULT_COST).unwrap();
    }

    /// Verifies a password against a hashed password using bcrypt.
    /// Returns true if the password matches the hashed password, false otherwise.
    pub fn verify_password(hashed_password: String, password_to_verify: String) -> bool {
        return verify(password_to_verify, &hashed_password).unwrap();
    }
}
