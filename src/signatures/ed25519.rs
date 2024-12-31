extern crate ed25519_dalek;
extern crate rand;

use std::sync::mpsc;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ed25519_dalek::Signature;
use rand::rngs::OsRng;

use super::cas_ed25519::Ed25519ByteSignature;

pub fn get_ed25519_key_pair() -> Vec<u8> {
    let mut csprng = OsRng;
    let keypair = SigningKey::generate(&mut csprng);
    let keypair_vec = keypair.to_bytes().to_vec();
    keypair_vec
}

pub fn get_ed25519_key_pair_threadpool() -> Vec<u8> {
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = get_ed25519_key_pair();
        sender.send(result);
    });
    let result = receiver.recv().unwrap();
    result
}

pub fn ed25519_sign_with_key_pair(key_pair: Vec<u8>, message_to_sign: Vec<u8>) -> Ed25519ByteSignature {
    let mut key_pair_bytes: [u8; 32] = [0u8; 32];
    key_pair_bytes.copy_from_slice(&key_pair);
    let keypair = SigningKey::from_bytes(&key_pair_bytes);

    let signature = keypair.sign(&message_to_sign);
    let signature_bytes = signature.to_bytes().to_vec();
    let public_keypair_vec = keypair.verifying_key().as_bytes().to_vec();


    let result = Ed25519ByteSignature {
        public_key: public_keypair_vec,
        signature: signature_bytes
    };
    result
}

pub fn ed25519_sign_with_key_pair_threadpool(key_pair: Vec<u8>, message_to_sign: Vec<u8>) -> Ed25519ByteSignature {
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = ed25519_sign_with_key_pair(key_pair, message_to_sign);
        sender.send(result);
    });
    let result = receiver.recv().unwrap();
    result
}


pub fn ed25519_verify_with_key_pair(key_pair: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> bool {
    let mut key_pair_array = [0u8; 32];
    key_pair_array.copy_from_slice(&key_pair);
    let keypair = SigningKey::from_bytes(&key_pair_array);

    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature);
    let signature = Signature::from_bytes(&signature_array);

    return keypair.verify(&message, &signature).is_ok();
}

pub fn ed25519_verify_with_key_pair_threadpool(key_pair: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> bool {
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = ed25519_verify_with_key_pair(key_pair, signature, message);
        sender.send(result);
    });
    let result = receiver.recv().unwrap();
    result
}

pub fn ed25519_verify_with_public_key(public_key: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> bool {
    let mut public_key_array = [0u8; 32];
    public_key_array.copy_from_slice(&public_key);
    let verifying_key = VerifyingKey::from_bytes(&public_key_array).unwrap();

    let mut signature_parsed = [0u8; 64];
    signature_parsed.copy_from_slice(&signature);
    let signature_parsed = Signature::from_bytes(&signature_parsed);


    return verifying_key
        .verify_strict(&message, &signature_parsed)
        .is_ok();
}

pub fn ed25519_verify_with_public_key_threadpool(public_key: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> bool {
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = ed25519_verify_with_public_key(public_key, signature, message);
        sender.send(result);
    });
    let result = receiver.recv().unwrap();
    result
}