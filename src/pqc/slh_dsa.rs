use rand;
use signature::*;
use slh_dsa::*;

use crate::pqc::cas_pqc::SlhDsaKeyPair;
pub fn generate_signing_and_verification_key() -> SlhDsaKeyPair {
    let mut rng = rand::rngs::OsRng;
    let sk = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = sk.verifying_key();
    let vk_bytes = verifying_key.to_bytes();
    SlhDsaKeyPair {
        signing_key: sk.to_bytes().to_vec(),
        verification_key: vk_bytes.to_vec(),
    }
}

pub fn sign_message(message: Vec<u8>, signing_key: Vec<u8>) -> Vec<u8> {
    let key = SigningKey::<Shake128f>::try_from(signing_key.as_slice()).unwrap();
    let signature: Signature<Shake128f> = key.sign(&message);
    signature.to_bytes().to_vec()
}

pub fn verify_signature(message: Vec<u8>, signature: Vec<u8>, verification_key: Vec<u8>) -> bool {
    let vk  = VerifyingKey::<Shake128f>::try_from(verification_key.as_slice()).unwrap();
    let sig = Signature::<Shake128f>::try_from(signature.as_slice()).unwrap();
    vk.verify(&message, &sig).is_ok()
}
