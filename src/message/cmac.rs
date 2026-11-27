use crate::error::CasResult;

/// Cipher-based Message Authentication Code (CMAC, NIST SP 800-38B; also known
/// as OMAC1, RFC 4493 for AES-128).
///
/// Implemented by [`CMACAES128`](super::cas_cmac::CMACAES128) and
/// [`CMACAES256`](super::cas_cmac::CMACAES256). The tag is always the full
/// 16-byte AES block: truncated tags are neither produced nor accepted.
pub trait CASCMAC {
    /// Computes the CMAC tag of `message` under `key`.
    ///
    /// Returns `CasError::InvalidKey` if `key` is not the cipher's key length.
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>>;

    /// Verifies `signature` (the tag) against the CMAC of `message` under `key`
    /// in constant time.
    ///
    /// Returns `Ok(true)` if the tag is valid, `Ok(false)` if it is not (including
    /// a tag of the wrong length), and `CasError::InvalidKey` if `key` is not the
    /// cipher's key length.
    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool>;
}
