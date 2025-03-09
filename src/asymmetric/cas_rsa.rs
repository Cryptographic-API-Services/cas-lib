use std::sync::mpsc;

use rand::rngs::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    RsaPublicKey,
};
use rsa::{Pkcs1v15Sign, RsaPrivateKey};

use super::types::{CASRSAEncryption, RSAKeyPairResult};

pub struct CASRSA;

impl CASRSAEncryption for CASRSA {
    fn generate_rsa_keys(key_size: usize) -> RSAKeyPairResult {
        let mut rng: OsRng = OsRng;
        let private_key: RsaPrivateKey =
            RsaPrivateKey::new(&mut rng, key_size).expect("failed to generate a key");
        let public_key: RsaPublicKey = private_key.to_public_key();
        let result = RSAKeyPairResult {
            public_key: public_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .unwrap()
                .to_string(),
            private_key: private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
        };
        result
    }

    fn generate_rsa_keys_threadpool(key_size: usize) -> RSAKeyPairResult {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let mut rng: OsRng = OsRng;
            let private_key: RsaPrivateKey =
                RsaPrivateKey::new(&mut rng, key_size).expect("failed to generate a key");
            let public_key: RsaPublicKey = private_key.to_public_key();
            let thread_result = RSAKeyPairResult {
                private_key: private_key
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .unwrap()
                    .to_string(),
                public_key: public_key
                    .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                    .unwrap()
                    .to_string(),
            };
            sender.send(thread_result);
        });
        let thread_result: RSAKeyPairResult = receiver.recv().unwrap();
        thread_result
    }

    fn sign(private_key: String, hash: Vec<u8>) -> Vec<u8> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key).unwrap();
        let signed_data = private_key
            .sign(Pkcs1v15Sign::new_unprefixed(), &hash)
            .unwrap();
        signed_data
    }

    fn sign_threadpool(private_key: String, hash: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let signed_data = Self::sign(private_key, hash);
            sender.send(signed_data);
        });
        let signed_data = receiver.recv().unwrap();
        signed_data
    }

    fn verify(public_key: String, hash: Vec<u8>, signature: Vec<u8>) -> bool {
        let public_key = RsaPublicKey::from_pkcs1_pem(&public_key).unwrap();
        let verified = public_key.verify(Pkcs1v15Sign::new_unprefixed(), &hash, &signature);
        if verified.is_err() == false {
            return true;
        } else {
            return false;
        }
    }

    fn verify_threadpool(public_key: String, hash: Vec<u8>, signed_text: Vec<u8>) -> bool {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let verified = Self::verify(public_key, hash, signed_text);
            sender.send(verified);
        });
        let verified = receiver.recv().unwrap();
        verified
    }
}