use std::fmt;

/// The unified error type returned by all fallible `cas-lib` operations.
///
/// Every cryptographic operation that can fail returns [`CasResult`] instead of
/// panicking. This is important for FFI consumers: a panic unwinding across the
/// FFI boundary is undefined behavior and typically aborts the host process. A
/// malformed key, a tampered ciphertext, or a failed authentication tag are all
/// recoverable conditions and are reported through this enum.
///
/// # ABI stability contract
///
/// The downstream FFI binding crates (`cas-core-lib`, `cas-typescript-sdk`)
/// surface each variant to their callers as the stable numeric code returned by
/// [`CasError::error_code`]. Those numbers are part of the ABI contract with
/// every consumer SDK, so this enum is **append-only**:
///
/// - Never remove, rename, or renumber an existing variant.
/// - Add new variants only at the end, and give them the next free code in
///   [`CasError::error_code`].
///
/// The `error_code_contract_is_stable` test in this module pins the mapping so
/// an accidental reorder or removal fails CI here rather than silently breaking
/// a consumer's error handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasError {
    /// A provided key had an invalid length or could not be parsed.
    InvalidKey,
    /// A provided nonce/IV had an invalid length.
    InvalidNonce,
    /// A provided signature had an invalid length or could not be parsed.
    InvalidSignature,
    /// Input bytes could not be decoded into the expected type.
    InvalidInput,
    /// PEM/DER decoding or encoding of a key failed.
    InvalidPemKey,
    /// Invalid algorithm parameters were supplied (e.g. an RSA key size that is
    /// too small, or out-of-range password-hashing parameters).
    InvalidParameters,
    /// AEAD encryption failed.
    EncryptionFailed,
    /// AEAD decryption failed or the authentication tag did not verify.
    DecryptionFailed,
    /// A signing operation failed.
    SigningFailed,
    /// Key generation failed.
    KeyGenerationFailed,
    /// Password hashing or verification setup failed.
    PasswordHashingFailed,
    /// Compression or decompression failed.
    CompressionFailed,
}

impl fmt::Display for CasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            CasError::InvalidKey => "invalid key: wrong length or could not be parsed",
            CasError::InvalidNonce => "invalid nonce: wrong length",
            CasError::InvalidSignature => "invalid signature: wrong length or could not be parsed",
            CasError::InvalidInput => "invalid input: could not be decoded",
            CasError::InvalidPemKey => "invalid PEM key: could not be decoded or encoded",
            CasError::InvalidParameters => "invalid algorithm parameters",
            CasError::EncryptionFailed => "encryption failed",
            CasError::DecryptionFailed => "decryption failed or authentication tag mismatch",
            CasError::SigningFailed => "signing failed",
            CasError::KeyGenerationFailed => "key generation failed",
            CasError::PasswordHashingFailed => "password hashing failed",
            CasError::CompressionFailed => "compression or decompression failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for CasError {}

impl CasError {
    /// Maps this error to the stable numeric code surfaced through the FFI by
    /// the downstream binding crates. `0` is reserved for success and is never
    /// returned here.
    ///
    /// These values are part of the ABI contract described on [`CasError`]; see
    /// the type-level documentation before changing them.
    pub fn error_code(&self) -> i32 {
        match self {
            CasError::InvalidKey => 1,
            CasError::InvalidNonce => 2,
            CasError::InvalidSignature => 3,
            CasError::InvalidInput => 4,
            CasError::InvalidPemKey => 5,
            CasError::InvalidParameters => 6,
            CasError::EncryptionFailed => 7,
            CasError::DecryptionFailed => 8,
            CasError::SigningFailed => 9,
            CasError::KeyGenerationFailed => 10,
            CasError::PasswordHashingFailed => 11,
            CasError::CompressionFailed => 12,
        }
    }
}

/// The result type returned by all fallible `cas-lib` operations.
pub type CasResult<T> = Result<T, CasError>;

#[cfg(test)]
mod tests {
    use super::CasError;

    /// Golden test pinning the FFI error-code contract. If you are changing this
    /// test you are changing the ABI surfaced by every downstream SDK — make
    /// sure that is intentional and that `cas-core-lib` / `cas-typescript-sdk`
    /// are updated in lockstep.
    #[test]
    fn error_code_contract_is_stable() {
        let expected: &[(CasError, i32)] = &[
            (CasError::InvalidKey, 1),
            (CasError::InvalidNonce, 2),
            (CasError::InvalidSignature, 3),
            (CasError::InvalidInput, 4),
            (CasError::InvalidPemKey, 5),
            (CasError::InvalidParameters, 6),
            (CasError::EncryptionFailed, 7),
            (CasError::DecryptionFailed, 8),
            (CasError::SigningFailed, 9),
            (CasError::KeyGenerationFailed, 10),
            (CasError::PasswordHashingFailed, 11),
            (CasError::CompressionFailed, 12),
        ];

        for (error, code) in expected {
            assert_eq!(
                error.error_code(),
                *code,
                "error code for {error:?} changed; this breaks the FFI ABI contract"
            );
        }

        // Compile-time guard against a variant being added (or removed) without
        // updating the contract above: this match is intentionally exhaustive
        // with no wildcard arm, so a new `CasError` variant fails to compile
        // here until it is added to `expected` and to the downstream SDK
        // mappings.
        fn assert_all_variants_covered(error: &CasError) {
            match error {
                CasError::InvalidKey
                | CasError::InvalidNonce
                | CasError::InvalidSignature
                | CasError::InvalidInput
                | CasError::InvalidPemKey
                | CasError::InvalidParameters
                | CasError::EncryptionFailed
                | CasError::DecryptionFailed
                | CasError::SigningFailed
                | CasError::KeyGenerationFailed
                | CasError::PasswordHashingFailed
                | CasError::CompressionFailed => {}
            }
        }
        let _ = assert_all_variants_covered;
    }
}
