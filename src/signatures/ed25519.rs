use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ed25519_dalek::Signature;
use zeroize::Zeroizing;

use crate::error::{CasError, CasResult};
use crate::signatures::cas_ed25519::Ed25519ByteKeyPair;
use super::cas_ed25519::Ed25519ByteSignature;

/// Copies a caller-supplied 32-byte Ed25519 secret key into a buffer that is
/// zeroized on drop, and zeroizes the caller's `Vec` as well.
/// `SigningKey` itself zeroizes on drop (ed25519-dalek's `zeroize` feature).
fn secret_key_bytes(key_pair: Vec<u8>) -> CasResult<Zeroizing<[u8; 32]>> {
    let key_pair = Zeroizing::new(key_pair);
    let mut bytes = Zeroizing::new([0u8; 32]);
    if key_pair.len() != bytes.len() {
        return Err(CasError::InvalidKey);
    }
    bytes.copy_from_slice(&key_pair);
    Ok(bytes)
}

/// Generates a new Ed25519 key pair.
/// Returns the key pair as a vector of bytes.
///
/// `key_pair` is the secret key, owned by the caller, who must zeroize it when done
/// (FFI layers: before freeing it). See the crate-level docs.
///
/// # Panics
///
/// Panics if the operating system's random number generator (`getrandom`)
/// fails, like x25519-dalek's `StaticSecret::random`.
pub fn get_ed25519_key_pair() -> Ed25519ByteKeyPair {
    // The secret key is 32 bytes from the OS RNG, exactly what
    // `SigningKey::generate` does, but drawn into a buffer that is zeroized on
    // drop (`generate` leaves its copy on the stack).
    let mut secret_key = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *secret_key).expect("getrandom failure");
    let keypair = SigningKey::from_bytes(&secret_key);
    let keypair_vec = keypair.as_bytes().to_vec();
    let public_key = keypair.verifying_key().as_bytes().to_vec();
    return Ed25519ByteKeyPair {
        key_pair: keypair_vec,
        public_key
    };
}

/// Signs a message using the provided Ed25519 key pair.
/// Returns the signature and public key as an Ed25519ByteSignature, or an error
/// if the key pair is not 32 bytes long.
pub fn ed25519_sign_with_key_pair(key_pair: Vec<u8>, message_to_sign: Vec<u8>) -> CasResult<Ed25519ByteSignature> {
    let key_pair_bytes = secret_key_bytes(key_pair)?;

    let keypair = SigningKey::from_bytes(&key_pair_bytes);
    let signature = keypair.sign(&message_to_sign);
    let signature_bytes = signature.to_bytes().to_vec();
    let public_keypair_vec = keypair.verifying_key().as_bytes().to_vec();
    Ok(Ed25519ByteSignature {
        public_key: public_keypair_vec,
        signature: signature_bytes
    })
}

/// Verifies a signature using the provided Ed25519 key pair.
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is not, and
/// an error if the key pair or signature has an invalid length.
/// The key pair is expected to be in byte array format.
/// Uses strict verification (rejects small-order R and weak keys), exactly
/// like `ed25519_verify_with_public_key`.
pub fn ed25519_verify_with_key_pair(key_pair: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> CasResult<bool> {
    let key_pair_bytes = secret_key_bytes(key_pair)?;
    let signature_bytes: [u8; 64] = signature.try_into().map_err(|_| CasError::InvalidSignature)?;

    let keypair = SigningKey::from_bytes(&key_pair_bytes);
    let signature = Signature::from_bytes(&signature_bytes);
    Ok(keypair.verifying_key().verify_strict(&message, &signature).is_ok())
}

/// Verifies a signature using the provided public key.
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is not, and
/// an error if the public key or signature has an invalid length or could not be parsed.
/// The public key and signature are expected to be in byte array format.
pub fn ed25519_verify_with_public_key(public_key: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> CasResult<bool> {
    let public_key_bytes: [u8; 32] = public_key.try_into().map_err(|_| CasError::InvalidKey)?;
    let signature_bytes: [u8; 64] = signature.try_into().map_err(|_| CasError::InvalidSignature)?;

    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| CasError::InvalidKey)?;
    let signature_parsed = Signature::from_bytes(&signature_bytes);
    Ok(verifying_key
        .verify_strict(&message, &signature_parsed)
        .is_ok())
}
