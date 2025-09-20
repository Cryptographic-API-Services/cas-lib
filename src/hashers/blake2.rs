

use super::cas_hasher::CASHasher;
use blake2::{Blake2b512, Blake2s256, Digest};

pub struct CASBlake2;

impl CASHasher for CASBlake2 {
    /// Hashes data using the Blake2b-512 algorithm.
    /// Returns the hash as a vector of bytes.
    fn hash_512(data_to_hash: Vec<u8>) -> Vec<u8> {
        let mut hasher = Blake2b512::new();
        hasher.update(data_to_hash);
        let result = hasher.finalize();
        return result.to_vec();
    }

    /// Verifies a hash using the Blake2b-512 algorithm.
    /// Returns true if the hash matches the data, false otherwise.
    fn verify_512(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let mut hasher = Blake2b512::new();
        hasher.update(data_to_verify);
        let result = hasher.finalize();
        return hash_to_verify.eq(&result.to_vec());
    }

    /// Hashes data using the Blake2s-256 algorithm.
    /// Returns the hash as a vector of bytes.
    fn hash_256(data_to_hash: Vec<u8>) -> Vec<u8> {
        let mut hasher = Blake2s256::new();
        hasher.update(data_to_hash);
        let result = hasher.finalize();
        return result.to_vec();
    }

    /// Verifies a hash using the Blake2s-256 algorithm.
    /// Returns true if the hash matches the data, false otherwise.
    fn verify_256(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let mut hasher = Blake2s256::new();
        hasher.update(data_to_verify);
        let result = hasher.finalize();
        return hash_to_verify.eq(&result.to_vec());
    }
}