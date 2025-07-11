
use std::sync::mpsc;

use aes_gcm::AeadCore;
use ascon_aead::{aead::{generic_array::GenericArray, Aead, KeyInit, OsRng}, Ascon128};

use super::cas_ascon_aead::{CASAsconAead};
pub struct AsconAead;

impl CASAsconAead for AsconAead {
    /// Encrypts with AscondAead
    fn encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        if key.len() != 16 || nonce.len() != 16 {
            panic!("Key and nonce must be 16 bytes long");
        }
        let key_generic_array = GenericArray::from_slice(&key);
        let nonce_generic_array = GenericArray::from_slice(&nonce);
        let cipher = Ascon128::new(key_generic_array);
        let ciphertext = cipher.encrypt(&nonce_generic_array, plaintext.as_ref()).unwrap();
        ciphertext
    }

    /// Encrypts with AscondAead on the threadpool
    fn encrypt_threadpool(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        if key.len() != 16 || nonce.len() != 16 {
            panic!("Key and nonce must be 16 bytes long");
        }
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let ciphertext = Self::encrypt(key, nonce, plaintext);
            sender.send(ciphertext).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Decrypts with AscondAead 
    fn decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        if key.len() != 16 || nonce.len() != 16 {
            panic!("Key and nonce must be 16 bytes long");
        }
        let key_generic_array = GenericArray::from_slice(&key);
        let nonce_generic_array = GenericArray::from_slice(&nonce);
        let cipher = Ascon128::new(key_generic_array);
        let plaintext = cipher.decrypt(&nonce_generic_array, ciphertext.as_ref()).unwrap();
        plaintext
    }

    /// Decrypts with AscondAead on the threadpool
    fn decrypt_threadpool(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        if key.len() != 16 || nonce.len() != 16 {
            panic!("Key and nonce must be 16 bytes long");
        }
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let plaintext = Self::decrypt(key, nonce, ciphertext);
            sender.send(plaintext).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Generates a 16-byte key for Ascon Aead
    fn generate_key() -> Vec<u8> {
        return Ascon128::generate_key(&mut OsRng).to_vec();
    }

    /// Generates a 16-byte key for Ascon Aead on the threadpool
    fn generate_key_threadpool() -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let key = Self::generate_key();
            sender.send(key).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Generates a Ascon Aead nonce
    fn generate_nonce() -> Vec<u8> {
        return Ascon128::generate_nonce(&mut OsRng).to_vec();
    }

    /// Generates a Ascon Aead nonce on the threadpool
    fn generate_nonce_threadpool() -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let key = <AsconAead as CASAsconAead>::generate_nonce();
            sender.send(key).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
}