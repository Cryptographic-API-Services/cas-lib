//! Result types for the post-quantum (`pqc`) module.
//!
//! The structs that carry secret key material or shared secrets do not derive
//! `Debug`: their manual `Debug` impls print `[REDACTED; N bytes]` in place of
//! the secret field, so `{:?}` in a log cannot leak a private key. They also
//! implement [`Zeroize`] so a caller can wipe them explicitly.
//!
//! They deliberately do **not** zeroize on drop. A `Drop` impl would stop
//! callers (including the FFI binding crates) from moving the `Vec<u8>` fields
//! out of the struct. Like every other secret this crate returns, the fields are
//! plain `Vec<u8>` that the caller owns and must zeroize when it is done with
//! them; see the crate-level documentation.

use std::fmt;

use zeroize::Zeroize;

/// Formats a secret field without revealing its contents.
struct Redacted(usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED; {} bytes]", self.0)
    }
}

/// An ML-KEM-1024 key pair. `secret_key` is secret; zeroize it when done.
#[repr(C)]
#[derive(Clone)]
pub struct MlKemKeyPair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl fmt::Debug for MlKemKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKemKeyPair")
            .field("secret_key", &Redacted(self.secret_key.len()))
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl Zeroize for MlKemKeyPair {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
        self.public_key.zeroize();
    }
}

/// The result of ML-KEM-1024 encapsulation. `shared_secret` is secret; zeroize
/// it when done.
#[repr(C)]
#[derive(Clone)]
pub struct MlKemEncapResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl fmt::Debug for MlKemEncapResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKemEncapResult")
            .field("ciphertext", &self.ciphertext)
            .field("shared_secret", &Redacted(self.shared_secret.len()))
            .finish()
    }
}

impl Zeroize for MlKemEncapResult {
    fn zeroize(&mut self) {
        self.ciphertext.zeroize();
        self.shared_secret.zeroize();
    }
}

/// An ML-KEM shared secret. `shared_secret` is secret; zeroize it when done.
#[repr(C)]
#[derive(Clone)]
pub struct MlKemSharedSecret {
    pub shared_secret: Vec<u8>,
}

impl fmt::Debug for MlKemSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKemSharedSecret")
            .field("shared_secret", &Redacted(self.shared_secret.len()))
            .finish()
    }
}

impl Zeroize for MlKemSharedSecret {
    fn zeroize(&mut self) {
        self.shared_secret.zeroize();
    }
}

/// An SLH-DSA key pair. `signing_key` is secret; zeroize it when done.
#[repr(C)]
#[derive(Clone)]
pub struct SlhDsaKeyPair {
    pub signing_key: Vec<u8>,
    pub verification_key: Vec<u8>,
}

impl fmt::Debug for SlhDsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlhDsaKeyPair")
            .field("signing_key", &Redacted(self.signing_key.len()))
            .field("verification_key", &self.verification_key)
            .finish()
    }
}

impl Zeroize for SlhDsaKeyPair {
    fn zeroize(&mut self) {
        self.signing_key.zeroize();
        self.verification_key.zeroize();
    }
}

/// An ML-DSA key pair. `signing_key` is secret; zeroize it when done.
#[repr(C)]
#[derive(Clone)]
pub struct MlDsaKeyPair {
    pub signing_key: Vec<u8>,
    pub verification_key: Vec<u8>,
}

impl fmt::Debug for MlDsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaKeyPair")
            .field("signing_key", &Redacted(self.signing_key.len()))
            .field("verification_key", &self.verification_key)
            .finish()
    }
}

impl Zeroize for MlDsaKeyPair {
    fn zeroize(&mut self) {
        self.signing_key.zeroize();
        self.verification_key.zeroize();
    }
}
