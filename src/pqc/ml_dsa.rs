use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa65, Signature, SignatureEncoding, SigningKey,
    Signer, Verifier, VerifyingKey,
};

use crate::error::{CasError, CasResult};
use crate::pqc::cas_pqc::MlDsaKeyPair;

/// Generates an ML-DSA-65 (FIPS 204) signing/verification key pair.
///
/// The signing key is serialized as its 32-byte seed, which is the preferred
/// representation for ML-DSA private keys.
pub fn generate_signing_and_verification_key() -> MlDsaKeyPair {
    let signing_key = SigningKey::<MlDsa65>::generate();
    let verifying_key = signing_key.verifying_key();
    MlDsaKeyPair {
        signing_key: signing_key.to_bytes().to_vec(),
        verification_key: verifying_key.to_bytes().to_vec(),
    }
}

/// Signs a message with an ML-DSA-65 signing key (deterministic variant, empty context).
/// Returns an error if the signing key could not be parsed.
pub fn sign_message(message: Vec<u8>, signing_key: Vec<u8>) -> CasResult<Vec<u8>> {
    let key = SigningKey::<MlDsa65>::new_from_slice(signing_key.as_slice())
        .map_err(|_| CasError::InvalidKey)?;
    let signature: Signature<MlDsa65> = key.try_sign(&message).map_err(|_| CasError::SigningFailed)?;
    Ok(signature.to_vec())
}

/// Verifies an ML-DSA-65 signature.
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is not, and
/// an error if the verification key or signature could not be parsed.
pub fn verify_signature(message: Vec<u8>, signature: Vec<u8>, verification_key: Vec<u8>) -> CasResult<bool> {
    let vk = VerifyingKey::<MlDsa65>::new_from_slice(verification_key.as_slice())
        .map_err(|_| CasError::InvalidKey)?;
    let sig = Signature::<MlDsa65>::try_from(signature.as_slice())
        .map_err(|_| CasError::InvalidSignature)?;
    Ok(vk.verify(&message, &sig).is_ok())
}
