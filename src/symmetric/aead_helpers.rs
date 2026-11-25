//! Shared AEAD plumbing used by every AEAD in the crate (AES-GCM, AES-GCM-SIV,
//! ChaCha20-Poly1305 and Ascon-AEAD128). All of them are built on the same
//! `aead` 0.5 traits, so one generic implementation covers key/nonce length
//! checks, associated data, and the `seal` / `open` framing.

use aes_gcm::aead::{generic_array::typenum::Unsigned, Aead, AeadCore, KeyInit, Nonce, Payload};
use rand::{rngs::OsRng, RngCore};

use crate::error::{CasError, CasResult};

/// The nonce length of `A`, in bytes.
pub(crate) const fn nonce_len<A: AeadCore>() -> usize {
    A::NonceSize::USIZE
}

fn cipher<A: KeyInit>(key: &[u8]) -> CasResult<A> {
    A::new_from_slice(key).map_err(|_| CasError::InvalidKey)
}

/// Encrypts `plaintext` under a caller-supplied nonce, binding `aad`.
/// Returns `ciphertext || tag`.
pub(crate) fn encrypt_with_aad<A: Aead + KeyInit>(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> CasResult<Vec<u8>> {
    let cipher = cipher::<A>(key)?;
    if nonce.len() != nonce_len::<A>() {
        return Err(CasError::InvalidNonce);
    }
    cipher
        .encrypt(Nonce::<A>::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CasError::EncryptionFailed)
}

/// Decrypts `ciphertext || tag` under a caller-supplied nonce, checking `aad`.
pub(crate) fn decrypt_with_aad<A: Aead + KeyInit>(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> CasResult<Vec<u8>> {
    let cipher = cipher::<A>(key)?;
    if nonce.len() != nonce_len::<A>() {
        return Err(CasError::InvalidNonce);
    }
    cipher
        .decrypt(Nonce::<A>::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CasError::DecryptionFailed)
}

/// Encrypts `plaintext` under a fresh random nonce drawn from `OsRng` and
/// returns `nonce || ciphertext || tag`. `None` AAD is the same as empty AAD.
pub(crate) fn seal<A: Aead + KeyInit>(
    key: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> CasResult<Vec<u8>> {
    // Check the key before drawing a nonce, so a bad key fails cleanly.
    let cipher = cipher::<A>(key)?;
    let mut nonce = Nonce::<A>::default();
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad: aad.unwrap_or_default() })
        .map_err(|_| CasError::EncryptionFailed)?;
    let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Splits `nonce || ciphertext || tag` produced by [`seal`] and decrypts it.
///
/// A blob shorter than a nonce plus a tag cannot be a sealed message and is
/// rejected with [`CasError::InvalidInput`] before any slicing happens.
pub(crate) fn open<A: Aead + KeyInit>(
    key: &[u8],
    sealed: &[u8],
    aad: Option<&[u8]>,
) -> CasResult<Vec<u8>> {
    let cipher = cipher::<A>(key)?;
    let nonce_len = nonce_len::<A>();
    if sealed.len() < nonce_len + A::TagSize::USIZE {
        return Err(CasError::InvalidInput);
    }
    let (nonce, ciphertext) = sealed.split_at(nonce_len);
    cipher
        .decrypt(
            Nonce::<A>::from_slice(nonce),
            Payload { msg: ciphertext, aad: aad.unwrap_or_default() },
        )
        .map_err(|_| CasError::DecryptionFailed)
}
