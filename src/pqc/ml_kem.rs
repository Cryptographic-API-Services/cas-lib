use ml_kem::kem::{DecapsulationKey, EncapsulationKey, Encapsulate, Decapsulate};
use ml_kem::*;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};

use crate::error::{CasError, CasResult};
use crate::pqc::cas_pqc::{MlKemEncapResult, MlKemKeyPair};

/// ML-KEM-1024 (Kyber-1024) byte lengths (public API sanity checks)
const MLKEM1024_PUBLIC_KEY_LEN: usize = 1568;
const MLKEM1024_SECRET_KEY_LEN: usize = 3168;
const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;
/// Length of the byte-encoded polynomial vector at the start of an encapsulation
/// key (384 * k bytes, k = 4); the remaining 32 bytes are the seed `rho`.
const MLKEM1024_ENCODED_VECTOR_LEN: usize = 1536;
/// Offset of the encapsulation key embedded in a decapsulation key, which is
/// laid out as `dk_pke (1536) || ek (1568) || H(ek) (32) || z (32)`.
const MLKEM1024_DK_EK_OFFSET: usize = 1536;
/// The ML-KEM field modulus.
const MLKEM_Q: u16 = 3329;

/// FIPS 203 section 7.2 encapsulation key check (modulus check): every 12-bit
/// coefficient of the encoded polynomial vector must be reduced modulo q. The
/// `ml-kem` crate does not perform this check when decoding a key.
fn encapsulation_key_is_valid(public_key: &[u8]) -> bool {
    public_key[..MLKEM1024_ENCODED_VECTOR_LEN].chunks_exact(3).all(|chunk| {
        let low = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0f) << 8);
        let high = u16::from(chunk[1] >> 4) | (u16::from(chunk[2]) << 4);
        low < MLKEM_Q && high < MLKEM_Q
    })
}

/// FIPS 203 section 7.3 decapsulation key check (hash check): the hash stored
/// in the key must equal SHA3-256 of the encapsulation key embedded in it. The
/// `ml-kem` crate does not perform this check when decoding a key.
fn decapsulation_key_is_valid(secret_key: &[u8]) -> bool {
    let hash_offset = MLKEM1024_DK_EK_OFFSET + MLKEM1024_PUBLIC_KEY_LEN;
    let embedded_key = &secret_key[MLKEM1024_DK_EK_OFFSET..hash_offset];
    let stored_hash = &secret_key[hash_offset..hash_offset + 32];
    Sha3_256::digest(embedded_key).as_slice() == stored_hash
}

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
///
/// Returns [`CasError::InvalidKey`] if the key has the wrong length or fails the
/// FIPS 203 encapsulation key check.
pub fn ml_kem_1024_encapsulate(public_key: Vec<u8>) -> CasResult<MlKemEncapResult> {
    if public_key.len() != MLKEM1024_PUBLIC_KEY_LEN {
        return Err(CasError::InvalidKey);
    }
    if !encapsulation_key_is_valid(&public_key) {
        return Err(CasError::InvalidKey);
    }
    let ek_bytes: Encoded<EncapsulationKey<MlKem1024Params>> =
        public_key.as_slice().try_into().map_err(|_| CasError::InvalidKey)?;
    let ek = EncapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(&ek_bytes);
    let mut rng = OsRng;
    let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| CasError::EncryptionFailed)?;
    Ok(MlKemEncapResult {
        ciphertext: ct.as_slice().to_vec(),
        shared_secret: ss.as_slice().to_vec(),
    })
}

/// Decapsulate a ciphertext with the secret key -> shared_secret
///
/// Returns [`CasError::InvalidKey`] if the key has the wrong length or fails the
/// FIPS 203 decapsulation key check.
pub fn ml_kem_1024_decapsulate(secret_key: Vec<u8>, ciphertext: Vec<u8>) -> CasResult<Vec<u8>> {
    if secret_key.len() != MLKEM1024_SECRET_KEY_LEN {
        return Err(CasError::InvalidKey);
    }
    if ciphertext.len() != MLKEM1024_CIPHERTEXT_LEN {
        return Err(CasError::InvalidInput);
    }
    if !decapsulation_key_is_valid(&secret_key) {
        return Err(CasError::InvalidKey);
    }

    let dk_bytes: Encoded<DecapsulationKey<MlKem1024Params>> =
        secret_key.as_slice().try_into().map_err(|_| CasError::InvalidKey)?;
    let dk = DecapsulationKey::<MlKem1024Params>::from_bytes(&dk_bytes);

    let ct: Ciphertext<MlKem1024> =
        ciphertext.as_slice().try_into().map_err(|_| CasError::InvalidInput)?;

    let ss = dk.decapsulate(&ct).map_err(|_| CasError::DecryptionFailed)?;
    Ok(ss.to_vec())
}
