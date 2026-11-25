use crate::error::CasResult;

pub trait CASAES256Encryption {
    fn generate_key() -> Vec<u8>;
    /// Encrypts `plaintext` under `nonce`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce, and it must never be used twice with the
    /// same key. Reusing an AES-GCM nonce reveals the XOR of the two plaintexts
    /// and lets an attacker recover the authentication key and forge messages.
    /// Prefer [`CASAeadSeal::seal`], which draws a fresh nonce for every call.
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce`.
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>>;
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Generates a random nonce from `OsRng`. Use each nonce for one message only.
    fn generate_nonce() -> Vec<u8>;
    fn key_from_vec(key_slice: Vec<u8>) -> CasResult<Vec<u8>>;
}

pub trait CASAES128Encryption {
    fn generate_key() -> Vec<u8>;
    /// Encrypts `plaintext` under `nonce`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce, and it must never be used twice with the
    /// same key. Reusing an AES-GCM nonce reveals the XOR of the two plaintexts
    /// and lets an attacker recover the authentication key and forge messages.
    /// Prefer [`CASAeadSeal::seal`], which draws a fresh nonce for every call.
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce`.
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>>;
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Generates a random nonce from `OsRng`. Use each nonce for one message only.
    fn generate_nonce() -> Vec<u8>;
    fn key_from_vec(key_slice: Vec<u8>) -> CasResult<Vec<u8>>;
}

pub trait CASAES256AadEncryption {
    /// Encrypts `plaintext` under `nonce` and binds `aad`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce, and it must never be used twice with the
    /// same key. Reusing an AES-GCM nonce reveals the XOR of the two plaintexts
    /// and lets an attacker recover the authentication key and forge messages.
    /// Prefer [`CASAeadSeal::seal`], which draws a fresh nonce for every call.
    fn encrypt_plaintext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce` and checks `aad`.
    fn decrypt_ciphertext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
}

pub trait CASAES128AadEncryption {
    /// Encrypts `plaintext` under `nonce` and binds `aad`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce, and it must never be used twice with the
    /// same key. Reusing an AES-GCM nonce reveals the XOR of the two plaintexts
    /// and lets an attacker recover the authentication key and forge messages.
    /// Prefer [`CASAeadSeal::seal`], which draws a fresh nonce for every call.
    fn encrypt_plaintext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce` and checks `aad`.
    fn decrypt_ciphertext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
}

pub trait CASAES256SIVEncryption {
    fn generate_key() -> Vec<u8>;
    /// Encrypts `plaintext` under `nonce`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce. AES-GCM-SIV is nonce-misuse resistant:
    /// reusing a nonce with the same key only reveals whether two messages
    /// (and their AAD) were identical, but it still leaks that, so use a fresh
    /// nonce per message. Prefer [`CASAeadSeal::seal`], which draws one for you.
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce`.
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>>;
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Generates a random nonce from `OsRng`. Use each nonce for one message only.
    fn generate_nonce() -> Vec<u8>;
    fn key_from_vec(key_slice: Vec<u8>) -> CasResult<Vec<u8>>;
}

pub trait CASAES128SIVEncryption {
    fn generate_key() -> Vec<u8>;
    /// Encrypts `plaintext` under `nonce`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce. AES-GCM-SIV is nonce-misuse resistant:
    /// reusing a nonce with the same key only reveals whether two messages
    /// (and their AAD) were identical, but it still leaks that, so use a fresh
    /// nonce per message. Prefer [`CASAeadSeal::seal`], which draws one for you.
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce`.
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>>;
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Generates a random nonce from `OsRng`. Use each nonce for one message only.
    fn generate_nonce() -> Vec<u8>;
    fn key_from_vec(key_slice: Vec<u8>) -> CasResult<Vec<u8>>;
}

pub trait CASAES256KeyWrap {
    fn generate_kek() -> Vec<u8>;
    fn wrap_key(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>>;
    fn unwrap_key(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>>;
    fn wrap_key_with_padding(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>>;
    fn unwrap_key_with_padding(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>>;
}

pub trait CASAES128KeyWrap {
    fn generate_kek() -> Vec<u8>;
    fn wrap_key(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>>;
    fn unwrap_key(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>>;
    fn wrap_key_with_padding(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> CasResult<Vec<u8>>;
    fn unwrap_key_with_padding(kek: Vec<u8>, wrapped_key: Vec<u8>) -> CasResult<Vec<u8>>;
}

pub trait Chacha20Poly1305Encryption {
    fn generate_key() -> Vec<u8>;
    /// Encrypts `plaintext` under `nonce`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce, and it must never be used twice with the
    /// same key. Reusing a ChaCha20-Poly1305 nonce reveals the XOR of the two
    /// plaintexts and the Poly1305 key, which lets an attacker forge messages.
    /// Prefer [`CASAeadSeal::seal`], which draws a fresh nonce for every call.
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce`.
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Generates a random nonce from `OsRng`. Use each nonce for one message only.
    fn generate_nonce() -> Vec<u8>;
}

/// AES-256-GCM-SIV with additional authenticated data (AAD).
///
/// The AAD is not encrypted, but it is bound to the authentication tag:
/// decryption only succeeds when the same AAD is supplied.
pub trait CASAES256SIVAadEncryption {
    /// Encrypts `plaintext` under `nonce` and binds `aad`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce. AES-GCM-SIV is nonce-misuse resistant:
    /// reusing a nonce with the same key only reveals whether two messages
    /// (and their AAD) were identical, but it still leaks that, so use a fresh
    /// nonce per message. Prefer [`CASAeadSeal::seal`], which draws one for you.
    fn encrypt_plaintext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce` and checks `aad`.
    fn decrypt_ciphertext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
}

/// AES-128-GCM-SIV with additional authenticated data (AAD).
///
/// The AAD is not encrypted, but it is bound to the authentication tag:
/// decryption only succeeds when the same AAD is supplied.
pub trait CASAES128SIVAadEncryption {
    /// Encrypts `plaintext` under `nonce` and binds `aad`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce. AES-GCM-SIV is nonce-misuse resistant:
    /// reusing a nonce with the same key only reveals whether two messages
    /// (and their AAD) were identical, but it still leaks that, so use a fresh
    /// nonce per message. Prefer [`CASAeadSeal::seal`], which draws one for you.
    fn encrypt_plaintext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce` and checks `aad`.
    fn decrypt_ciphertext_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
}

/// ChaCha20-Poly1305 with additional authenticated data (AAD).
///
/// The AAD is not encrypted, but it is bound to the authentication tag:
/// decryption only succeeds when the same AAD is supplied.
pub trait Chacha20Poly1305AadEncryption {
    /// Encrypts `plaintext` under `nonce` and binds `aad`, returning `ciphertext || tag`.
    ///
    /// # Nonce reuse
    ///
    /// The caller supplies the nonce, and it must never be used twice with the
    /// same key. Reusing a ChaCha20-Poly1305 nonce reveals the XOR of the two
    /// plaintexts and the Poly1305 key, which lets an attacker forge messages.
    /// Prefer [`CASAeadSeal::seal`], which draws a fresh nonce for every call.
    fn encrypt_plaintext_with_aad(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
    /// Decrypts `ciphertext || tag` under `nonce` and checks `aad`.
    fn decrypt_ciphertext_with_aad(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
}

/// Nonce-managing AEAD encryption, implemented by every AEAD in the crate:
/// [`CASAES128`](super::aes::CASAES128), [`CASAES256`](super::aes::CASAES256),
/// [`CASAES128SIV`](super::aes_gcm_siv::CASAES128SIV),
/// [`CASAES256SIV`](super::aes_gcm_siv::CASAES256SIV),
/// [`CASChacha20Poly1305`](super::chacha20poly1305::CASChacha20Poly1305) and
/// [`AsconAead`](crate::sponges::ascon_aead::AsconAead).
///
/// `seal` draws a fresh nonce from `OsRng` for every call and returns
/// `nonce || ciphertext || tag`; `open` splits that blob apart again. The caller
/// never handles a nonce, so it cannot reuse one by mistake. This is the
/// recommended way to encrypt with this crate.
///
/// A random nonce is safe for up to about 2^32 messages under one key for the
/// 96-bit-nonce ciphers (AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305); rotate the
/// key well before that. Ascon-AEAD128's 128-bit nonce has a far larger margin.
pub trait CASAeadSeal {
    /// Length in bytes of the nonce that prefixes every sealed blob.
    const NONCE_LEN: usize;

    /// Encrypts `plaintext` under a freshly generated random nonce and returns
    /// `nonce || ciphertext || tag`.
    ///
    /// `aad` is optional additional authenticated data: it is not encrypted or
    /// stored in the output, but the same value must be passed to [`open`](Self::open).
    /// `None` is the same as empty AAD.
    ///
    /// Returns [`CasError::InvalidKey`](crate::error::CasError::InvalidKey) if
    /// the key has the wrong length.
    fn seal(key: Vec<u8>, plaintext: Vec<u8>, aad: Option<Vec<u8>>) -> CasResult<Vec<u8>>;

    /// Decrypts a `nonce || ciphertext || tag` blob produced by [`seal`](Self::seal).
    ///
    /// Returns [`CasError::InvalidKey`](crate::error::CasError::InvalidKey) if
    /// the key has the wrong length,
    /// [`CasError::InvalidInput`](crate::error::CasError::InvalidInput) if the
    /// blob is too short to hold a nonce and a tag, and
    /// [`CasError::DecryptionFailed`](crate::error::CasError::DecryptionFailed)
    /// if the ciphertext, tag or AAD do not authenticate.
    fn open(key: Vec<u8>, sealed: Vec<u8>, aad: Option<Vec<u8>>) -> CasResult<Vec<u8>>;
}
