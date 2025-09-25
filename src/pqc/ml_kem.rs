use ml_kem::kem::{DecapsulationKey, EncapsulationKey, Encapsulate, Decapsulate};
use ml_kem::*;
use rand::rngs::OsRng;

use crate::pqc::cas_pqc::{MlKemEncapResult, MlKemKeyPair};

/// ML-KEM-1024 (Kyber-1024) byte lengths (public API sanity checks)
const MLKEM1024_PUBLIC_KEY_LEN: usize = 1568;
const MLKEM1024_SECRET_KEY_LEN: usize = 3168;
const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;

#[derive(Debug)]
pub enum MlKemError {
    BadPublicKeyLength,
    BadSecretKeyLength,
    BadCiphertextLength,
    DecodeFailed,
}

pub type MlKemResult<T> = Result<T, MlKemError>;

/// Generate (secret/decapsulation key, public/encapsulation key)
pub fn ml_kem_1024_generate() -> MlKemKeyPair {
    let mut rng = OsRng;
    let (dk, ek) = MlKem1024::generate(&mut rng);
    MlKemKeyPair {
        secret_key: dk.as_bytes().to_vec(),
        public_key: ek.as_bytes().to_vec(),
    }
}

/// Encapsulate to a public key -> (ciphertext, shared_secret)
pub fn ml_kem_1024_encapsulate(public_key: Vec<u8>) -> MlKemResult<MlKemEncapResult> {
    if public_key.len() != MLKEM1024_PUBLIC_KEY_LEN {
        return Err(MlKemError::BadPublicKeyLength);
    }
    let ek_bytes: Encoded<EncapsulationKey<MlKem1024Params>> =
        public_key.as_slice().try_into().map_err(|_| MlKemError::DecodeFailed)?;
    let ek = EncapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(&ek_bytes);
    let mut rng = OsRng;
    let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| MlKemError::DecodeFailed)?;
    Ok(MlKemEncapResult {
        ciphertext: ct.as_slice().to_vec(),
        shared_secret: ss.as_slice().to_vec(),
    })
}

/// Decapsulate a ciphertext with the secret key -> shared_secret
pub fn ml_kem_1024_decapsulate(secret_key: Vec<u8>, ciphertext: Vec<u8>) -> MlKemResult<Vec<u8>> {
    if secret_key.len() != MLKEM1024_SECRET_KEY_LEN {
        return Err(MlKemError::BadSecretKeyLength);
    }
    if ciphertext.len() != MLKEM1024_CIPHERTEXT_LEN {
        return Err(MlKemError::BadCiphertextLength);
    }

    let dk_bytes: Encoded<DecapsulationKey<MlKem1024Params>> =
        secret_key.as_slice().try_into().map_err(|_| MlKemError::DecodeFailed)?;
    let dk = DecapsulationKey::<MlKem1024Params>::from_bytes(&dk_bytes);

    let ct: Ciphertext<MlKem1024> =
        ciphertext.as_slice().try_into().map_err(|_| MlKemError::DecodeFailed)?;

    let ss = dk.decapsulate(&ct).map_err(|_| MlKemError::DecodeFailed)?;
    Ok(ss.to_vec())
}