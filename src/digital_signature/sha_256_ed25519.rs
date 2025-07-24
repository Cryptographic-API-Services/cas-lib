use std::sync::mpsc;

use sha3::{Digest, Sha3_256};

use crate::signatures::ed25519::{ed25519_sign_with_key_pair, ed25519_verify_with_public_key, get_ed25519_key_pair};

use super::cas_digital_signature_rsa::{
    ED25519DigitalSignature, SHAED25519DalekDigitalSignatureResult,
};

pub struct SHA256ED25519DigitalSignature;

impl ED25519DigitalSignature for SHA256ED25519DigitalSignature {
    /// Creates a digital signature using SHA-256 as the hashing algorithm and Ed25519-Dalek as the signing algorithm.
    fn digital_signature_ed25519(data_to_sign: Vec<u8>) -> SHAED25519DalekDigitalSignatureResult {
        let mut hasher = Sha3_256::new();
        hasher.update(data_to_sign);
        let sha_hasher_result = hasher.finalize();
        let sha_hash_bytes = sha_hasher_result.to_vec();
        let key_pair = get_ed25519_key_pair();
        let signature = ed25519_sign_with_key_pair(key_pair, sha_hash_bytes);
        let result = SHAED25519DalekDigitalSignatureResult {
            public_key: signature.public_key,
            signature: signature.signature,
        };
        result
    }

    /// Verifys a digital signature using SHA-256 as the hashing algorithm and Ed25519-Dalek as the verification algorithm.
    fn digital_signature_ed25519_verify(
        public_key: Vec<u8>,
        data_to_verify: Vec<u8>,
        signature: Vec<u8>
    ) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(data_to_verify);
        let sha_hasher_result = hasher.finalize();
        let sha_hash_bytes = sha_hasher_result.to_vec();
        return ed25519_verify_with_public_key(public_key, signature, sha_hash_bytes);
    }
    
    /// Creates a digital signature using SHA-256 as the hashing algorithm and Ed25519-Dalek as the signing algorithm on the threadpool.
    fn digital_signature_ed25519_threadpool(data_to_sign: Vec<u8>) -> SHAED25519DalekDigitalSignatureResult {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = Self::digital_signature_ed25519(data_to_sign);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Verifys a digital signature using SHA-256 as the hashing algorithm and Ed25519-Dalek as the verification algorithm on the threadpool.
    fn digital_signature_ed25519_verify_threadpool(public_key: Vec<u8>, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = Self::digital_signature_ed25519_verify(public_key, data_to_verify, signature);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
}
