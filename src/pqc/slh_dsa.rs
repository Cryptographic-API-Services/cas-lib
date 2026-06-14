use rand;
use signature::*;
use slh_dsa::*;

use crate::error::{CasError, CasResult};
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

/// Signs a message with an SLH-DSA signing key.
/// Returns an error if the signing key could not be parsed.
pub fn sign_message(message: Vec<u8>, signing_key: Vec<u8>) -> CasResult<Vec<u8>> {
    let key = SigningKey::<Shake128f>::try_from(signing_key.as_slice())
        .map_err(|_| CasError::InvalidKey)?;
    let signature: Signature<Shake128f> = key.sign(&message);
    Ok(signature.to_bytes().to_vec())
}

/// Verifies an SLH-DSA signature.
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is not, and
/// an error if the verification key or signature could not be parsed.
pub fn verify_signature(message: Vec<u8>, signature: Vec<u8>, verification_key: Vec<u8>) -> CasResult<bool> {
    let vk = VerifyingKey::<Shake128f>::try_from(verification_key.as_slice())
        .map_err(|_| CasError::InvalidKey)?;
    let sig = Signature::<Shake128f>::try_from(signature.as_slice())
        .map_err(|_| CasError::InvalidSignature)?;
    Ok(vk.verify(&message, &sig).is_ok())
}
