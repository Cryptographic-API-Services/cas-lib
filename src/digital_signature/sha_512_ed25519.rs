use sha3::{Digest, Sha3_512};

use crate::signatures::ed25519::{ed25519_sign_with_key_pair, ed25519_verify_with_public_key, get_ed25519_key_pair};

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
}