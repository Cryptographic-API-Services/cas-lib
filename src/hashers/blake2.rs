use std::sync::mpsc;

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
    
    /// Hashes data using the Blake2b-512 algorithm on the threadpool.
    /// Returns the hash as a vector of bytes.
    fn hash_512_threadpool(data_to_hash: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = <CASBlake2 as CASHasher>::hash_512(data_to_hash);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Verifies a hash using the Blake2b-512 algorithm on the threadpool.
    /// Returns true if the hash matches the data, false otherwise.
    fn verify_512_threadpool(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = <CASBlake2 as CASHasher>::verify_512(hash_to_verify, data_to_verify);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Hashes data using the Blake2s-256 algorithm on the threadpool.
    /// Returns the hash as a vector of bytes.
    fn hash_256_threadpool(data_to_hash: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = <CASBlake2 as CASHasher>::hash_256(data_to_hash);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Verifies a hash using the Blake2s-256 algorithm on the threadpool.
    /// Returns true if the hash matches the data, false otherwise.
    fn verify_256_threadpool(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = <CASBlake2 as CASHasher>::verify_256(hash_to_verify, data_to_verify);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
}