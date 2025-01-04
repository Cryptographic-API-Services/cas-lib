extern crate ed25519_dalek;
extern crate rand;

use std::sync::mpsc;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ed25519_dalek::Signature;
use rand::rngs::OsRng;

use super::cas_ed25519::Ed25519ByteSignature;

pub fn get_ed25519_key_pair() -> [u8; 32] {
    let mut csprng = OsRng;
    let keypair = SigningKey::generate(&mut csprng);
    let keypair_vec = keypair.to_bytes();
    keypair_vec 
}

pub fn get_ed25519_key_pair_threadpool() -> [u8; 32] {
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = get_ed25519_key_pair();
        sender.send(result);
    });
    let result = receiver.recv().unwrap();
    result
}

pub fn ed25519_sign_with_key_pair(key_pair: [u8; 32], message_to_sign: &[u8]) -> Ed25519ByteSignature {
    let keypair = SigningKey::from_bytes(&key_pair);
    let signature = keypair.sign(&message_to_sign);
    let signature_bytes = signature.to_bytes();
    let public_keypair_vec = keypair.verifying_key().to_bytes();
    let result = Ed25519ByteSignature {
        public_key: public_keypair_vec,
        signature: signature_bytes
    };
    result
}

pub fn ed25519_sign_with_key_pair_threadpool(key_pair: [u8; 32], message_to_sign: &[u8]) -> Ed25519ByteSignature {
    let (sender, receiver) = mpsc::channel();
    let message_to_sign_clone = message_to_sign.to_vec(); 
    rayon::spawn(move || {
        let result = ed25519_sign_with_key_pair(key_pair, &message_to_sign_clone);
        sender.send(result);
    });
    let result = receiver.recv().unwrap();
    result
}


pub fn ed25519_verify_with_key_pair(key_pair: [u8; 32], signature: [u8; 64], message: &[u8]) -> bool {
    let keypair = SigningKey::from_bytes(&key_pair);
    let signature = Signature::from_bytes(&signature);
    return keypair.verify(&message, &signature).is_ok();
}

pub fn ed25519_verify_with_key_pair_threadpool(key_pair: [u8; 32], signature: [u8; 64], message: &[u8]) -> bool {
    let (sender, receiver) = mpsc::channel();
    let message_clone = message.to_vec();
    rayon::spawn(move || {
        let result = ed25519_verify_with_key_pair(key_pair, signature, &message_clone);
        sender.send(result);
    });
    let result = receiver.recv().unwrap();
    result
}

pub fn ed25519_verify_with_public_key(public_key: [u8; 32], signature: [u8; 64], message: &[u8]) -> bool {
    let verifying_key = VerifyingKey::from_bytes(&public_key).unwrap();
    let signature_parsed = Signature::from_bytes(&signature);
    return verifying_key
        .verify_strict(&message, &signature_parsed)
        .is_ok();
}

pub fn ed25519_verify_with_public_key_threadpool(public_key: [u8; 32], signature: [u8; 64], message: &[u8]) -> bool {
    let (sender, receiver) = mpsc::channel();
    let message_clone = message.to_vec();
    rayon::spawn(move || {
        let result = ed25519_verify_with_public_key(public_key, signature, &message_clone);
        sender.send(result);
    });
    let result = receiver.recv().unwrap();
    result
}