//! `cas-lib` wraps RustCrypto and Dalek-Cryptography behind a unified API for
//! FFI consumers.
//!
//! # Secret key material
//!
//! The crate zeroizes the intermediate secret buffers it allocates itself: the
//! HKDF-derived AES keys, the [`kdf`] output buffers, the Argon2-derived AES
//! keys, and the fixed-size copies of X25519 and Ed25519 secret keys. Those same
//! functions (and the [`kdf`] functions, for their `ikm` and `prk` arguments)
//! also zeroize the secret `Vec<u8>` argument they take by value. Other functions do not yet
//! zeroize their secret arguments.
//!
//! Secrets this crate **returns** (generated or derived keys, private keys,
//! shared secrets) are plain `Vec<u8>` (or `Vec<u8>` fields of a result
//! struct) owned by the caller. The crate cannot zeroize them for you: the
//! caller, and in particular every FFI binding layer, must zero the buffer
//! before it is freed, e.g. with [`zeroize::Zeroize::zeroize`] or by wrapping
//! it in [`zeroize::Zeroizing`]. The result structs in [`pqc::cas_pqc`]
//! implement [`zeroize::Zeroize`] and redact their secret fields in `Debug`.

pub mod error;

pub mod password_hashers {
    pub mod argon2;
    pub mod bcrypt;
    pub mod cas_password_hasher;
    pub mod scrypt;
    pub mod pbkdf2;
}

pub mod hashers {
    pub mod blake2;
    pub mod cas_hasher;
    pub mod sha;
    pub mod sha2;
}

pub mod kdf {
    pub mod cas_hkdf;
    pub mod hkdf;
}

pub mod key_exchange {
    pub mod cas_key_exchange;
    pub mod x25519;
}

pub mod symmetric {
    pub(crate) mod aead_helpers;
    pub mod aes;
    pub mod aes_gcm_siv;
    pub mod aes_kw;
    pub mod chacha20poly1305;
    pub mod cas_symmetric_encryption;
}

pub mod asymmetric {
    pub mod cas_rsa;
    pub mod types;
}

pub mod sponges {
    pub mod cas_ascon_aead;
    pub mod ascon_aead;
}

pub mod message {
    pub mod hmac;
    pub mod cas_hmac;
    pub mod cmac;
    pub mod cas_cmac;
}

pub mod signatures {
    pub mod ed25519;
    pub mod cas_ed25519;
}

pub mod compression {
    pub mod zstd;
}

pub mod hybrid {
    pub mod hpke;
    pub mod cas_hybrid;
}

pub mod pqc {
    pub mod ml_kem;
    pub mod cas_pqc;
    pub mod slh_dsa;
    pub mod ml_dsa;
}