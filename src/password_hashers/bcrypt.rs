

use std::str::FromStr;

use bcrypt::{hash, verify, HashParts, DEFAULT_COST};

use crate::error::{CasError, CasResult};

/// The longest password, in bytes, that bcrypt can hash without discarding input.
///
/// bcrypt keys its cipher with at most 72 bytes. Longer passwords used to be
/// truncated silently, so two passwords sharing their first 72 bytes produced
/// the same hash. They are now rejected with [`CasError::InvalidParameters`].
/// The limit counts UTF-8 bytes, not characters.
pub const BCRYPT_MAX_PASSWORD_BYTES: usize = 72;

/// The smallest cost [`CASBCrypt::hash_password_customized`] accepts.
pub const BCRYPT_MIN_COST: u32 = 10;
/// The largest cost accepted when hashing or found in a stored hash being verified.
/// Each step doubles the work; 16 is already about 64× the default (12), and the
/// bcrypt maximum of 31 is hours of CPU in one call.
pub const BCRYPT_MAX_COST: u32 = 16;

pub struct CASBCrypt;

impl CASBCrypt {
    /// Rejects passwords that bcrypt would truncate.
    ///
    /// The upstream `bcrypt::non_truncating_hash` also counts the NUL terminator
    /// it appends, so it rejects a password of exactly 72 bytes. bcrypt itself
    /// (OpenBSD, Go's `x/crypto/bcrypt`) accepts 72 bytes and drops only the
    /// terminator, so the limit is enforced here and `bcrypt::hash` / `verify`
    /// never see an input they would cut short. This also keeps hashes created
    /// by earlier versions of this crate verifiable.
    fn check_password_length(password: &str) -> CasResult<()> {
        if password.len() > BCRYPT_MAX_PASSWORD_BYTES {
            return Err(CasError::InvalidParameters);
        }
        Ok(())
    }

    /// Hashes a password using bcrypt with a customized cost.
    /// Parameters:
    /// - password_to_hash: The password to be hashed, at most
    ///   [`BCRYPT_MAX_PASSWORD_BYTES`] (72) bytes of UTF-8.
    /// - cost: The cost parameter, from [`BCRYPT_MIN_COST`] (10) to
    ///   [`BCRYPT_MAX_COST`] (16). The default used by [`Self::hash_password`] is 12.
    /// Returns the hashed password as a string.
    ///
    /// Returns [`CasError::InvalidParameters`] if the cost is outside that range or the
    /// password is longer than 72 bytes; it is never truncated.
    pub fn hash_password_customized(password_to_hash: String, cost: u32) -> CasResult<String> {
        if !(BCRYPT_MIN_COST..=BCRYPT_MAX_COST).contains(&cost) {
            return Err(CasError::InvalidParameters);
        }
        Self::check_password_length(&password_to_hash)?;
        hash(password_to_hash, cost).map_err(|_| CasError::PasswordHashingFailed)
    }

    /// Hashes a password using bcrypt with the default cost (12).
    /// The password must be at most [`BCRYPT_MAX_PASSWORD_BYTES`] (72) bytes of UTF-8.
    /// Returns the hashed password as a string.
    ///
    /// Returns [`CasError::InvalidParameters`] if the password is longer than
    /// 72 bytes; it is never truncated.
    pub fn hash_password(password_to_hash: String) -> CasResult<String> {
        Self::check_password_length(&password_to_hash)?;
        hash(password_to_hash, DEFAULT_COST).map_err(|_| CasError::PasswordHashingFailed)
    }

    /// Verifies a password against a hashed password using bcrypt.
    /// Returns `Ok(true)` if the password matches and `Ok(false)` if it does not.
    ///
    /// Returns [`CasError::InvalidParameters`] if the password is longer than
    /// [`BCRYPT_MAX_PASSWORD_BYTES`] (72) bytes, so a long password can never
    /// match a hash of its first 72 bytes, and [`CasError::PasswordHashingFailed`]
    /// if the stored hash could not be parsed. Hashes of passwords up to 72 bytes
    /// created by earlier versions of this crate still verify.
    ///
    /// The cost comes from the stored hash, so it is checked first: a hash with a
    /// cost above [`BCRYPT_MAX_COST`] returns [`CasError::InvalidParameters`] instead
    /// of running for hours. Costs below [`BCRYPT_MIN_COST`] still verify, so older
    /// hashes keep working.
    pub fn verify_password(hashed_password: String, password_to_verify: String) -> CasResult<bool> {
        let parts = HashParts::from_str(&hashed_password).map_err(|_| CasError::PasswordHashingFailed)?;
        if parts.get_cost() > BCRYPT_MAX_COST {
            return Err(CasError::InvalidParameters);
        }
        Self::check_password_length(&password_to_verify)?;
        verify(password_to_verify, &hashed_password).map_err(|_| CasError::PasswordHashingFailed)
    }
}
