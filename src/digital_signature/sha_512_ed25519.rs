use std::sync::mpsc;

use sha3::{Digest, Sha3_512};

use crate::signatures::ed25519::{ed25519_sign_with_key_pair, ed25519_verify_with_public_key, ed25519_verify_with_public_key_threadpool, get_ed25519_key_pair};

use super::cas_digital_signature_rsa::{
    ED25519DigitalSignature, SHAED25519DalekDigitalSignatureResult,
};

pub struct SHA512ED25519DigitalSignature;

impl ED25519DigitalSignature for SHA512ED25519DigitalSignature {
    fn digital_signature_ed25519(
        data_to_sign: &[u8],
    ) -> SHAED25519DalekDigitalSignatureResult {
        let mut hasher = Sha3_512::new();
        hasher.update(data_to_sign);
        let sha_hasher_result = hasher.finalize();
        let sha_hash_bytes = sha_hasher_result.as_slice();
        let key_pair: [u8; 32] = get_ed25519_key_pair();

        let signature = ed25519_sign_with_key_pair(key_pair, sha_hash_bytes);
        let result = SHAED25519DalekDigitalSignatureResult {
            public_key: signature.public_key,
            signature: signature.signature,
        };
        result
    }

    fn digital_signature_ed25519_verify(
        public_key: [u8; 32],
        data_to_verify: &[u8],
        signature: [u8; 64],
    ) -> bool {
        let mut hasher = Sha3_512::new();
        hasher.update(data_to_verify);
        let sha_hasher_result = hasher.finalize();
        let sha_hash_bytes = sha_hasher_result.as_slice();
        return ed25519_verify_with_public_key(public_key, signature, sha_hash_bytes);
    }
    
    fn digital_signature_ed25519_threadpool(data_to_sign: &[u8]) -> SHAED25519DalekDigitalSignatureResult {
        let (sender, receiver) = mpsc::channel();
        let data_clone = data_to_sign.to_vec();
        rayon::spawn(move || {
            let result = <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(&data_clone);
            sender.send(result);
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    fn digital_signature_ed25519_verify_threadpool(public_key: [u8; 32], data_to_verify: &[u8], signature: [u8; 64]) -> bool {
        let (sender, receiver) = mpsc::channel();
        let data_to_verify_clone = data_to_verify.to_vec();
        rayon::spawn(move || {
            let result = <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519_verify(public_key, &data_to_verify_clone, signature);
            sender.send(result);
        });
        let result = receiver.recv().unwrap();
        result
    }
}