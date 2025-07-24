extern crate ed25519_dalek;
extern crate rand;

use std::sync::mpsc;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ed25519_dalek::Signature;
use rand::rngs::OsRng;

use super::cas_ed25519::Ed25519ByteSignature;

/// Generates a new Ed25519 key pair.
/// Returns the key pair as a vector of bytes.
pub fn get_ed25519_key_pair() -> Vec<u8> {
    let mut csprng = OsRng;
    let keypair = SigningKey::generate(&mut csprng);
    let keypair_vec = keypair.as_bytes().to_vec();
    keypair_vec
}

/// Generates a new Ed25519 key pair on the threadpool.
/// Returns the key pair as a vector of bytes.
pub fn get_ed25519_key_pair_threadpool() -> Vec<u8> {
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = get_ed25519_key_pair();
        sender.send(result).unwrap();
    });
    let result = receiver.recv().unwrap();
    result
}

/// Signs a message using the provided Ed25519 key pair.
/// Returns the signature and public key as an Ed25519ByteSignature.
pub fn ed25519_sign_with_key_pair(key_pair: Vec<u8>, message_to_sign: Vec<u8>) -> Ed25519ByteSignature {
    let mut key_pair_box = Box::new([0u8; 32]);
    key_pair_box.copy_from_slice(&key_pair);

    let keypair = SigningKey::from_bytes(&*key_pair_box);
    let signature = keypair.sign(&message_to_sign);
    let signature_bytes = signature.to_bytes().to_vec();
    let public_keypair_vec = keypair.verifying_key().as_bytes().to_vec();
    let result = Ed25519ByteSignature {
        public_key: public_keypair_vec,
        signature: signature_bytes
    };
    result
}

/// Signs a message using the provided Ed25519 key pair on the threadpool.
/// Returns the signature and public key as an Ed25519ByteSignature.
pub fn ed25519_sign_with_key_pair_threadpool(key_pair: Vec<u8>, message_to_sign: Vec<u8>) -> Ed25519ByteSignature {
    let (sender, receiver) = mpsc::channel(); 
    rayon::spawn(move || {
        let result = ed25519_sign_with_key_pair(key_pair, message_to_sign);
        sender.send(result).unwrap();
    });
    let result = receiver.recv().unwrap();
    result
}

/// Verifies a signature using the provided Ed25519 key pair.
/// Returns true if the signature is valid, false otherwise.
/// The key pair is expected to be in byte array format.
pub fn ed25519_verify_with_key_pair(key_pair: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> bool {
    let mut key_pair_box = Box::new([0u8; 32]);
    key_pair_box.copy_from_slice(&key_pair);
    let mut signature_box = Box::new([0u8; 64]);
    signature_box.copy_from_slice(&signature);

    let keypair = SigningKey::from_bytes(&*key_pair_box);
    let signature = Signature::from_bytes(&*signature_box);
    return keypair.verify(&message, &signature).is_ok();
}

/// Verifies a signature using the provided Ed25519 key pair on the threadpool.
/// Returns true if the signature is valid, false otherwise.
/// The key pair is expected to be in byte array format.
pub fn ed25519_verify_with_key_pair_threadpool(key_pair: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> bool {
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = ed25519_verify_with_key_pair(key_pair, signature, message);
        sender.send(result).unwrap();
    });
    let result = receiver.recv().unwrap();
    result
}

/// Verifies a signature using the provided public key.
/// Returns true if the signature is valid, false otherwise.
/// The public key and signature are expected to be in byte array format.
pub fn ed25519_verify_with_public_key(public_key: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> bool {
    let mut public_key_box = Box::new([0u8; 32]);
    public_key_box.copy_from_slice(&public_key);
    let mut signature_box = Box::new([0u8; 64]);
    signature_box.copy_from_slice(&signature);


    let verifying_key = VerifyingKey::from_bytes(&*public_key_box).unwrap();
    let signature_parsed = Signature::from_bytes(&*signature_box);
    return verifying_key
        .verify_strict(&message, &signature_parsed)
        .is_ok();
}

/// Verifies a signature using the provided public key on the threadpool.
/// Returns true if the signature is valid, false otherwise.
/// The public key and signature are expected to be in byte array format.
pub fn ed25519_verify_with_public_key_threadpool(public_key: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> bool {
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = ed25519_verify_with_public_key(public_key, signature, message);
        sender.send(result).unwrap();
    });
    let result = receiver.recv().unwrap();
    result
}