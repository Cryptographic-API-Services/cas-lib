use std::sync::mpsc;

use aes_gcm::Key;

use rand::rngs::OsRng;
use rand::RngCore;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
};

use super::cas_symmetric_encryption::{AesKeyFromX25519SharedSecret, CASAES128Encryption, CASAES256Encryption};
pub struct CASAES128;
pub struct CASAES256;

impl CASAES256Encryption for CASAES256 {
    fn generate_key() -> [u8; 32] {
        return Aes256Gcm::generate_key(&mut OsRng).into();
    }

    fn generate_key_threadpool() -> [u8; 32] {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let thread_result = Self::generate_key();
            sender.send(thread_result);
        });
        let result = receiver.recv().unwrap();
        result
    }

    fn encrypt_plaintext(aes_key: [u8; 32], nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        ciphertext
    }

    fn encrypt_plaintext_threadpool(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let key = GenericArray::from_slice(&aes_key);
            let cipher = Aes256Gcm::new(&key);
            let nonce = Nonce::from_slice(&nonce);
            let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
            sender.send(ciphertext);
        });
        let result = receiver.recv().unwrap();
        result
    }

    fn decrypt_ciphertext(aes_key: [u8; 32], nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    fn decrypt_ciphertext_threadpool(aes_key: [u8; 32], nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let key = GenericArray::from_slice(&aes_key);
            let cipher = Aes256Gcm::new(&key);
            let nonce = Nonce::from_slice(&nonce);
            let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
            sender.send(plaintext);
        });
        let result = receiver.recv().unwrap();
        result
    }

    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret {
        let aes_key = Key::<Aes256Gcm>::from_slice(&shared_secret);
        let mut aes_nonce: [u8; 12] = Default::default();
        aes_nonce.copy_from_slice(&shared_secret[..12]);
        let result = AesKeyFromX25519SharedSecret {
            aes_key: aes_key.to_vec(),
            aes_nonce: aes_nonce.to_vec(),
        };
        result
    }

    fn key_from_x25519_shared_secret_threadpool(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let aes_key = Key::<Aes256Gcm>::from_slice(&shared_secret);
            let mut aes_nonce: [u8; 12] = Default::default();
            aes_nonce.copy_from_slice(&shared_secret[..12]);
            let result = AesKeyFromX25519SharedSecret {
                aes_key: aes_key.to_vec(),
                aes_nonce: aes_nonce.to_vec(),
            };
            sender.send(result);
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    fn generate_nonce() -> Vec<u8> {
        let rng = &mut OsRng;
        let mut random_bytes = Vec::with_capacity(12);
        random_bytes.resize(12, 0);
        rng.fill_bytes(&mut random_bytes);
        random_bytes
    }

    fn generate_nonce_threadpool() -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let rng = &mut OsRng;
            let mut random_bytes = Vec::with_capacity(12);
            random_bytes.resize(12, 0);
            rng.fill_bytes(&mut random_bytes);
            sender.send(random_bytes);
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    fn key_from_vec(key_slice: Vec<u8>) -> Vec<u8> {
        let result = Key::<Aes256Gcm>::from_slice(&key_slice).to_vec();
        result
    }

    fn key_from_vec_threadpool(key_slice: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = Key::<Aes256Gcm>::from_slice(&key_slice).to_vec();
            sender.send(result);
        });
        let result = receiver.recv().unwrap();
        result
    }
}

impl CASAES128Encryption for CASAES128 {
    fn generate_key() -> [u8; 16] {
        return Aes128Gcm::generate_key(&mut OsRng).into();
    }

    fn generate_key_threadpool() -> [u8; 16] {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let key = Self::generate_key();
            sender.send(key);
        });
        let result = receiver.recv().unwrap();
        result
    }

    fn encrypt_plaintext(aes_key: [u8; 16], nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        ciphertext
    }

    fn encrypt_plaintext_threadpool(aes_key: [u8; 16], nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let ciphertext = Self::encrypt_plaintext(aes_key, nonce, plaintext);
            sender.send(ciphertext);
        });
        let result = receiver.recv().unwrap();
        result
    }

    fn decrypt_ciphertext(aes_key: [u8; 16], nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    fn decrypt_ciphertext_threadpool(aes_key: [u8; 16], nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let plaintext = Self::decrypt_ciphertext(aes_key, nonce, ciphertext);
            sender.send(plaintext);
        });
        let result = receiver.recv().unwrap();
        result
    }

    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret {
        let mut aes_key: [u8; 16] = Default::default();
        aes_key.copy_from_slice(&shared_secret[..16]);
        let aes_key_slice = Key::<Aes128Gcm>::from_slice(&aes_key);
        let mut aes_nonce: [u8; 12] = Default::default();
        aes_nonce.copy_from_slice(&shared_secret[..12]);
        let result = AesKeyFromX25519SharedSecret {
            aes_key: aes_key_slice.to_vec(),
            aes_nonce: aes_nonce.to_vec(),
        };
        result
    }

    fn key_from_x25519_shared_secret_threadpool(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let mut aes_key: [u8; 16] = Default::default();
            aes_key.copy_from_slice(&shared_secret[..16]);
            let aes_key_slice = Key::<Aes128Gcm>::from_slice(&aes_key);
            let mut aes_nonce: [u8; 12] = Default::default();
            aes_nonce.copy_from_slice(&shared_secret[..12]);
            let result = AesKeyFromX25519SharedSecret {
                aes_key: aes_key_slice.to_vec(),
                aes_nonce: aes_nonce.to_vec(),
            };
            sender.send(result);
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    fn generate_nonce() -> Vec<u8> {
        let rng = &mut OsRng;
        let mut random_bytes = Vec::with_capacity(12);
        random_bytes.resize(12, 0);
        rng.fill_bytes(&mut random_bytes);
        random_bytes
    }

    fn generate_nonce_threadpool() -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let rng = &mut OsRng;
            let mut random_bytes = Vec::with_capacity(12);
            random_bytes.resize(12, 0);
            rng.fill_bytes(&mut random_bytes);
            sender.send(random_bytes);
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    fn key_from_vec(key_slice: Vec<u8>) -> Vec<u8> {
        let result = Key::<Aes128Gcm>::from_slice(&key_slice).to_vec();
        result
    }

    fn key_from_vec_threadpool(key_slice: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            sender.send(Key::<Aes128Gcm>::from_slice(&key_slice).to_vec());
        });
        let result = receiver.recv().unwrap();
        result
    }
}