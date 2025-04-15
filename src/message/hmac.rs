use std::sync::mpsc;

use super::cas_hmac::CASHMAC;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
pub struct HMAC;

impl CASHMAC for HMAC {
    fn sign(key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&message);
        let result = mac.finalize().into_bytes().to_vec();
        result
    }

    fn sign_threadpool(key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = Self::sign(key, message);
            sender.send(result);
        });
        let result = receiver.recv().unwrap();
        result
    }

    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&message);
        return mac.verify_slice(&signature).is_ok();
    }

    fn verify_threadpool(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = Self::verify(key, message, signature);
            sender.send(result);
        });
        let result = receiver.recv().unwrap();
        result
    }
}
