use std::fmt;

/// The unified error type returned by all fallible `cas-lib` operations.
///
/// Every cryptographic operation that can fail returns [`CasResult`] instead of
/// panicking. This is important for FFI consumers: a panic unwinding across the
/// FFI boundary is undefined behavior and typically aborts the host process. A
/// malformed key, a tampered ciphertext, or a failed authentication tag are all
/// recoverable conditions and are reported through this enum.
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

/// The result type returned by all fallible `cas-lib` operations.
pub type CasResult<T> = Result<T, CasError>;
