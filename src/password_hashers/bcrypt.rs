use bcrypt::{hash, verify, DEFAULT_COST};


pub struct CASBCrypt;

impl CASBCrypt {
    /// Hashes a password using bcrypt.
    /// Returns the hashed password as a string.
    fn hash_password(password_to_hash: String) -> String {
        return hash(password_to_hash, DEFAULT_COST).unwrap();
    }

    /// Hashes a password using bcrypt with a specified strength (cost).
    /// Strength must be between 4 and 31.
    fn hash_password_with_strength(password_to_hash: String, strength: u32) -> String {
        if (strength < 4) || (strength > 31) {
            panic!("Bcrypt strength must be between 4 and 31");
        }
        return hash(password_to_hash, strength).unwrap();
    }   

    /// Verifies a password against a hashed password using bcrypt.
    /// Returns true if the password matches the hashed password, false otherwise.
    fn verify_password(hashed_password: String, password_to_verify: String) -> bool {
        return verify(password_to_verify, &hashed_password).unwrap();
    }
}
