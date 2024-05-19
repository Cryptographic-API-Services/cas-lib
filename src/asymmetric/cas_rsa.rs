use std::{ffi::CString, sync::mpsc};

use rand::rngs::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    RsaPublicKey,
};
use rsa::{Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey};

use super::{cas_asymmetric_encryption::CASRSAEncryption, types::RSAKeyPairResult};

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
    fn encrypt_plaintext(public_key: String, plaintext: Vec<u8>) -> Vec<u8> {
        let public_key = RsaPublicKey::from_pkcs1_pem(&public_key).unwrap();
        let mut rng = rand::thread_rng();
        let ciphertext = public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, &plaintext)
            .unwrap();
        ciphertext
    }

    fn encrypt_plaintext_threadpool(public_key: String, plaintext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let public_key = RsaPublicKey::from_pkcs1_pem(public_key.as_str()).unwrap();
            let mut rng = rand::thread_rng();
            let encrypted_bytes = public_key
                .encrypt(&mut rng, Pkcs1v15Encrypt, &plaintext)
                .unwrap();
            sender.send(encrypted_bytes);
        });
        let mut encrypted_bytes = receiver.recv().unwrap();
        encrypted_bytes
    }

    fn decrypt_ciphertext(private_key: String, ciphertext: Vec<u8>) -> Vec<u8> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key).unwrap();
        let plaintext = private_key.decrypt(Pkcs1v15Encrypt, &ciphertext).unwrap();
        plaintext
    }

    fn decrypt_ciphertext_threadpool(private_key: String, ciphertext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key).unwrap();
            let decrypted_bytes = private_key
                .decrypt(Pkcs1v15Encrypt, &ciphertext)
                .expect("failed to decrypt");
            sender.send(decrypted_bytes);
        });
        let mut decrypted_bytes = receiver.recv().unwrap();
        decrypted_bytes
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
            let private_key =
                RsaPrivateKey::from_pkcs8_pem(&private_key).expect("failed to generate a key");
            let signed_data = private_key
                .sign(Pkcs1v15Sign::new_unprefixed(), &hash)
                .unwrap();
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
            let public_key = RsaPublicKey::from_pkcs1_pem(&public_key).unwrap();
            let verified = public_key.verify(
                Pkcs1v15Sign::new_unprefixed(),
                &hash,
                &signed_text,
            );
            sender.send(verified.is_err());
        });
        let result = receiver.recv().unwrap();
        result
    }
}
