//! Shared AEAD plumbing used by every AEAD in the crate (AES-GCM, AES-GCM-SIV,
//! ChaCha20-Poly1305 and Ascon-AEAD128). All of them are built on the same
//! `aead` 0.6 traits, so one generic implementation covers key/nonce length
//! checks, associated data, and the `seal` / `open` framing.

use std::mem::MaybeUninit;

use aes_gcm::aead::{array::{typenum::Unsigned, Array}, Aead, AeadCore, KeyInit, Nonce, Payload};
use zeroize::Zeroizing;

use crate::error::{CasError, CasResult};

/// The nonce length of `A`, in bytes.
pub(crate) const fn nonce_len<A: AeadCore>() -> usize {
    A::NonceSize::USIZE
}

fn cipher<A: KeyInit>(key: &[u8]) -> CasResult<A> {
    A::new_from_slice(key).map_err(|_| CasError::InvalidKey)
}

/// Returns `N` bytes from the operating system's random number generator
/// (`getrandom`), for keys and caller-managed nonces.
///
/// The bytes are drawn into an uninitialised `[MaybeUninit<u8>; N]` with
/// `getrandom::fill_uninit`, and only the initialised slice it returns is
/// copied out. Filling a zeroed buffer instead would read to CodeQL as a
/// hard-coded key or nonce (`rust/hard-coded-cryptographic-value`). The stack
/// buffer is zeroized on drop, so the returned `Vec` is the only copy; when it
/// is a key, it is owned by the caller, who must zeroize it when done.
///
/// # Panics
///
/// Panics if the operating system's random number generator fails, like
/// `get_ed25519_key_pair`.
pub(crate) fn random_bytes<const N: usize>() -> Vec<u8> {
    let mut buf = Zeroizing::new([MaybeUninit::<u8>::uninit(); N]);
    getrandom::fill_uninit(&mut *buf)
        .expect("getrandom failure: the OS random number generator is unavailable")
        .to_vec()
}

/// Parses a caller-supplied nonce, rejecting one of the wrong length.
fn nonce<A: AeadCore>(nonce: &[u8]) -> CasResult<&Nonce<A>> {
    <&Nonce<A>>::try_from(nonce).map_err(|_| CasError::InvalidNonce)
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
    let nonce = self::nonce::<A>(nonce)?;
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
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
    let nonce = self::nonce::<A>(nonce)?;
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CasError::DecryptionFailed)
}

/// Encrypts `plaintext` under a fresh random nonce drawn from the operating
/// system's random number generator (`getrandom`) and returns
/// `nonce || ciphertext || tag`. `None` AAD is the same as empty AAD.
///
/// The nonce is drawn into an uninitialised buffer, for the same CodeQL reason
/// as [`random_bytes`]. If the OS RNG fails, this returns
/// [`CasError::EncryptionFailed`] instead of panicking.
pub(crate) fn seal<A: Aead + KeyInit>(
    key: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> CasResult<Vec<u8>> {
    // Check the key before drawing a nonce, so a bad key fails cleanly.
    let cipher = cipher::<A>(key)?;
    let mut nonce_buf = Array::<MaybeUninit<u8>, A::NonceSize>::uninit();
    let nonce = getrandom::fill_uninit(&mut nonce_buf).map_err(|_| CasError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            self::nonce::<A>(nonce)?,
            Payload { msg: plaintext, aad: aad.unwrap_or_default() },
        )
        .map_err(|_| CasError::EncryptionFailed)?;
    let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
    sealed.extend_from_slice(nonce);
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
            self::nonce::<A>(nonce)?,
            Payload { msg: ciphertext, aad: aad.unwrap_or_default() },
        )
        .map_err(|_| CasError::DecryptionFailed)
}
