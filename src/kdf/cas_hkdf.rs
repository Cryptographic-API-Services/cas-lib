use crate::error::CasResult;

/// HKDF (RFC 5869): HMAC-based extract-and-expand key derivation.
///
/// HKDF turns input keying material that is secret but not necessarily uniform
/// (a Diffie-Hellman or KEM shared secret, or several of them concatenated)
/// into one or more independent keys. It is **not** a password hash: it does no
/// stretching, so use [`crate::password_hashers`] for passwords.
///
/// - [`extract`](CASHKDF::extract) condenses the input keying material and an
///   optional salt into a pseudorandom key (PRK) of the hash's output length.
/// - [`expand`](CASHKDF::expand) derives `length` bytes from a PRK for the
///   purpose named by `info`. Call it once per key with a distinct `info` to
///   derive several unrelated keys from one PRK.
/// - [`derive`](CASHKDF::derive) is `extract` followed by one `expand`.
///
/// An empty `salt` means "no salt", which RFC 5869 defines as a salt of
/// `HashLen` zero bytes. The PRK and every derived key are secrets returned as
/// plain `Vec<u8>`: the caller must zeroize them (see the crate docs).
pub trait CASHKDF {
    /// The hash's output length in bytes: the PRK length, and the minimum PRK
    /// length [`expand`](CASHKDF::expand) accepts.
    const HASH_LEN: usize;

    /// The most bytes [`expand`](CASHKDF::expand) can derive: `255 * HASH_LEN`.
    const MAX_OUTPUT_LEN: usize = 255 * Self::HASH_LEN;

    /// HKDF-Extract: returns the `HASH_LEN`-byte pseudorandom key for `ikm`
    /// and `salt`. `ikm` is zeroized before returning.
    fn extract(salt: Vec<u8>, ikm: Vec<u8>) -> Vec<u8>;

    /// HKDF-Expand: derives `length` bytes of output keying material from `prk`,
    /// bound to `info`. `prk` is zeroized before returning.
    ///
    /// Returns [`CasError::InvalidKey`](crate::error::CasError::InvalidKey) if
    /// `prk` is shorter than `HASH_LEN`, and
    /// [`CasError::InvalidParameters`](crate::error::CasError::InvalidParameters)
    /// if `length` is 0 or greater than `MAX_OUTPUT_LEN`.
    fn expand(prk: Vec<u8>, info: Vec<u8>, length: usize) -> CasResult<Vec<u8>>;

    /// HKDF-Extract followed by HKDF-Expand: derives `length` bytes from `ikm`,
    /// `salt` and `info`. `ikm` is zeroized before returning.
    ///
    /// Returns [`CasError::InvalidParameters`](crate::error::CasError::InvalidParameters)
    /// if `length` is 0 or greater than `MAX_OUTPUT_LEN`.
    fn derive(salt: Vec<u8>, ikm: Vec<u8>, info: Vec<u8>, length: usize) -> CasResult<Vec<u8>>;
}

/// HKDF with HMAC-SHA-256 (32-byte PRK, up to 8160 bytes of output).
pub struct CASHkdfSha256;

/// HKDF with HMAC-SHA-512 (64-byte PRK, up to 16320 bytes of output).
pub struct CASHkdfSha512;
