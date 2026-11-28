//! Types shared by the ECDSA and ECDH APIs of the [`ecc`](crate::ecc) module.

use std::fmt;

use zeroize::Zeroize;

/// An elliptic-curve key pair, PEM-encoded, as returned by
/// [`CASEcdsa::generate_key_pair`](super::cas_ecdsa::CASEcdsa::generate_key_pair)
/// and [`CASEcdh::generate_key_pair`](super::cas_ecdh::CASEcdh::generate_key_pair).
///
/// - `private_key` is a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) and is
///   secret: the caller owns it and must zeroize it when done (FFI layers:
///   before freeing it). See the crate-level docs.
/// - `public_key` is an SPKI PEM (`-----BEGIN PUBLIC KEY-----`) holding the
///   uncompressed point.
///
/// ECDSA and ECDH keys have the same encoding, so an ECDSA key pair parses as
/// an ECDH key pair of the same curve and vice versa. Don't use one key for
/// both: generate a separate key pair for each purpose.
///
/// `Debug` redacts `private_key`. The struct implements [`Zeroize`] but does
/// not zeroize on drop, so the fields can be moved out (see
/// [`pqc::cas_pqc`](crate::pqc::cas_pqc) for the same design).
#[derive(Clone)]
pub struct EcKeyPair {
    /// PKCS#8 PEM private key. Secret.
    pub private_key: String,
    /// SPKI PEM public key.
    pub public_key: String,
}

impl fmt::Debug for EcKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcKeyPair")
            .field("private_key", &format_args!("[REDACTED; {} bytes]", self.private_key.len()))
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl Zeroize for EcKeyPair {
    fn zeroize(&mut self) {
        self.private_key.zeroize();
        self.public_key.zeroize();
    }
}
