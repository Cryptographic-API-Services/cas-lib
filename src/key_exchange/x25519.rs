

use hkdf::Hkdf;
use sha2_hkdf::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{CasError, CasResult};
use super::cas_key_exchange::CASKeyExchange;

pub struct X25519SecretPublicKeyResult {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub struct X25519;

impl CASKeyExchange for X25519 {
    /// Generates a secret key and public key using X25519.
    /// Returns a result containing the secret key and public key as vectors of bytes.
    ///
    /// `secret_key` is secret and owned by the caller, who must zeroize it when done
    /// (FFI layers: before freeing it). See the crate-level docs.
    fn generate_secret_and_public_key() -> X25519SecretPublicKeyResult {
        let secret_key = StaticSecret::random();
        let public_key = PublicKey::from(&secret_key);
        let result = X25519SecretPublicKeyResult {
            secret_key: secret_key.as_bytes().to_vec(),
            public_key: public_key.as_bytes().to_vec(),
        };
        result
    }

    /// Performs a Diffie-Hellman key exchange using the provided secret key and user's public key.
    /// Returns the 32-byte shared secret.
    /// The secret key and user's public key are expected to be in byte array format.
    ///
    /// Returns [`CasError::InvalidKey`] if either input is not 32 bytes long, or if the
    /// peer's public key is a low-order point. Such a key forces the all-zero shared
    /// secret whatever our secret key is, so the exchange would "succeed" with a value
    /// an attacker knows (`SharedSecret::was_contributory` is false).
    ///
    /// Don't use the shared secret as a key directly: derive one with the
    /// `key_from_x25519_shared_secret` function of the cipher you'll use, or use
    /// `hybrid::hpke`, which does both steps.
    ///
    /// The returned shared secret is owned by the caller, who must zeroize it when done
    /// (FFI layers: before freeing it). See the crate-level docs.
    fn diffie_hellman(my_secret_key: Vec<u8>, users_public_key: Vec<u8>) -> CasResult<Vec<u8>> {
        let my_secret_key = Zeroizing::new(my_secret_key);
        let mut secret_key_bytes = Zeroizing::new([0u8; 32]);
        if my_secret_key.len() != secret_key_bytes.len() {
            return Err(CasError::InvalidKey);
        }
        secret_key_bytes.copy_from_slice(&my_secret_key);
        let public_key_bytes: [u8; 32] =
            users_public_key.try_into().map_err(|_| CasError::InvalidKey)?;

        // `StaticSecret` and `SharedSecret` zeroize themselves on drop.
        let secret_key = StaticSecret::from(*secret_key_bytes);
        let public_key = PublicKey::from(public_key_bytes);
        let shared_secret = secret_key.diffie_hellman(&public_key);
        if !shared_secret.was_contributory() {
            return Err(CasError::InvalidKey);
        }
        Ok(shared_secret.as_bytes().to_vec())
    }
}

/// HKDF `info` prefixes for the X25519-to-symmetric-key helpers: one per algorithm and
/// key size, so keys derived from the same shared secret for different ciphers are
/// unrelated (#112).
pub(crate) const KDF_LABEL_AES_256_GCM: &[u8] = b"cas-lib/v1/x25519-hkdf-sha256/aes-256-gcm";
pub(crate) const KDF_LABEL_AES_128_GCM: &[u8] = b"cas-lib/v1/x25519-hkdf-sha256/aes-128-gcm";
pub(crate) const KDF_LABEL_AES_256_GCM_SIV: &[u8] = b"cas-lib/v1/x25519-hkdf-sha256/aes-256-gcm-siv";
pub(crate) const KDF_LABEL_AES_128_GCM_SIV: &[u8] = b"cas-lib/v1/x25519-hkdf-sha256/aes-128-gcm-siv";

/// Derives a `key_len`-byte symmetric key from an X25519 shared secret with
/// HKDF-SHA256, bound to the algorithm (`label`) and to both parties' public keys.
///
/// `info = label || 0x00 || min(pk_a, pk_b) || max(pk_a, pk_b)`. Sorting the public keys
/// lets both peers pass them in either order and still derive the same key.
///
/// Returns [`CasError::InvalidKey`] if the shared secret or either public key is not
/// 32 bytes, or if the shared secret is all zeros (the result of a low-order public key).
pub(crate) fn derive_key_from_x25519_shared_secret(
    shared_secret: Vec<u8>,
    public_key_a: Vec<u8>,
    public_key_b: Vec<u8>,
    label: &[u8],
    key_len: usize,
) -> CasResult<Vec<u8>> {
    let shared_secret = Zeroizing::new(shared_secret);
    if shared_secret.len() != 32 || public_key_a.len() != 32 || public_key_b.len() != 32 {
        return Err(CasError::InvalidKey);
    }
    if bool::from(shared_secret.ct_eq(&[0u8; 32])) {
        return Err(CasError::InvalidKey);
    }

    let (low, high) = if public_key_a <= public_key_b {
        (&public_key_a, &public_key_b)
    } else {
        (&public_key_b, &public_key_a)
    };
    let mut info = Vec::with_capacity(label.len() + 1 + 64);
    info.extend_from_slice(label);
    info.push(0);
    info.extend_from_slice(low);
    info.extend_from_slice(high);

    let hk = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut key = Zeroizing::new(vec![0u8; key_len]);
    hk.expand(&info, &mut key)
        .map_err(|_| CasError::KeyGenerationFailed)?;
    // Hand the buffer to the caller without leaving an unzeroed copy behind.
    Ok(std::mem::take(&mut *key))
}
