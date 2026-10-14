

use super::cas_hasher::CASHasher;
use sha2::{Digest, Sha256, Sha512};
pub struct CASSHA2;

impl CASHasher for CASSHA2 {
    /// Hashes data using the SHA2-512 algorithm.
    /// Returns the hash as a vector of bytes.
    fn hash_512(data_to_hash: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(data_to_hash);
        let result = hasher.finalize();
        return result.to_vec();
    }

    /// Verifies a hash using the SHA2-512 algorithm.
    /// Returns true if the hash matches the data, false otherwise.
    fn verify_512(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let mut hasher = Sha512::new();
        hasher.update(data_to_verify);
        let result = hasher.finalize();
        return hash_to_verify.eq(&result.to_vec());
    }

    /// Hashes data using the SHA2-256 algorithm.
    /// Returns the hash as a vector of bytes.
    fn hash_256(data_to_hash: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data_to_hash);
        let result = hasher.finalize();
        return result.to_vec();
    }

    /// Verifies a hash using the SHA2-256 algorithm.
    /// Returns true if the hash matches the data, false otherwise.
    fn verify_256(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(data_to_verify);
        let result = hasher.finalize();
        return hash_to_verify.eq(&result.to_vec());
    }
}
