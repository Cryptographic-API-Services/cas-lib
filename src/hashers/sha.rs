use std::sync::mpsc;

use super::cas_hasher::CASHasher;
use sha3::{Digest, Sha3_256, Sha3_512};
pub struct CASSHA;

impl CASHasher for CASSHA {
    fn hash_512(data_to_hash: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha3_512::new();
        hasher.update(data_to_hash);
        let result = hasher.finalize();
        return result.to_vec();
    }

    fn verify_512(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let mut hasher = Sha3_512::new();
        hasher.update(data_to_verify);
        let result = hasher.finalize();
        return hash_to_verify.eq(&result.to_vec());
    }

    fn hash_256(data_to_hash: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(data_to_hash);
        let result = hasher.finalize();
        return result.to_vec();
    }

    fn verify_256(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(data_to_verify);
        let result = hasher.finalize();
        return hash_to_verify.eq(&result.to_vec());
    }
    
    fn hash_512_threadpool(data_to_hash: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = <CASSHA as CASHasher>::hash_512(data_to_hash);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    fn verify_512_threadpool(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = <CASSHA as CASHasher>::verify_512(hash_to_verify, data_to_verify);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    fn hash_256_threadpool(data_to_hash: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = <CASSHA as CASHasher>::hash_256(data_to_hash);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    fn verify_256_threadpool(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = <CASSHA as CASHasher>::verify_256(hash_to_verify, data_to_verify);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
}