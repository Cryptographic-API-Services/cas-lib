extern crate ed25519_dalek;
extern crate rand;



use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ed25519_dalek::Signature;
use rand::rngs::OsRng;

use crate::error::{CasError, CasResult};
use crate::signatures::cas_ed25519::Ed25519ByteKeyPair;
use super::cas_ed25519::Ed25519ByteSignature;

/// Generates a new Ed25519 key pair.
/// Returns the key pair as a vector of bytes.
pub fn get_ed25519_key_pair() -> Ed25519ByteKeyPair {
    let mut csprng = OsRng;
    let keypair = SigningKey::generate(&mut csprng);
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
    let key_pair_bytes: [u8; 32] = key_pair.try_into().map_err(|_| CasError::InvalidKey)?;

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
pub fn ed25519_verify_with_key_pair(key_pair: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> CasResult<bool> {
    let key_pair_bytes: [u8; 32] = key_pair.try_into().map_err(|_| CasError::InvalidKey)?;
    let signature_bytes: [u8; 64] = signature.try_into().map_err(|_| CasError::InvalidSignature)?;

    let keypair = SigningKey::from_bytes(&key_pair_bytes);
    let signature = Signature::from_bytes(&signature_bytes);
    Ok(keypair.verify(&message, &signature).is_ok())
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
