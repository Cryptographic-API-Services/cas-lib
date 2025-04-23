
use std::sync::mpsc;

use aes_gcm::AeadCore;
use ascon_aead::{aead::{generic_array::GenericArray, Aead, KeyInit, OsRng}, Ascon128};

use super::cas_ascon_aead::{CASAsconAead};
pub struct AsconAead;

impl CASAsconAead for AsconAead {
    /// Encrypts with AscondAead
    fn encrypt(key: [u8; 16], nonce: [u8; 16], plaintext: Vec<u8>) -> Vec<u8> {
        let key_generic_array = GenericArray::from_slice(&key);
        let nonce_generic_array = GenericArray::from_slice(&nonce);
        let cipher = Ascon128::new(key_generic_array);
        let ciphertext = cipher.encrypt(&nonce_generic_array, plaintext.as_ref()).unwrap();
        ciphertext
    }

    /// Encrypts with AscondAead on the threadpool
    fn encrypt_threadpool(key: [u8; 16], nonce: [u8; 16], plaintext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let ciphertext = Self::encrypt(key, nonce, plaintext);
            sender.send(ciphertext).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Decrypts with AscondAead 
    fn decrypt(key: [u8; 16], nonce: [u8; 16], ciphertext: Vec<u8>) -> Vec<u8> {
        let key_generic_array = GenericArray::from_slice(&key);
        let nonce_generic_array = GenericArray::from_slice(&nonce);
        let cipher = Ascon128::new(key_generic_array);
        let plaintext = cipher.decrypt(&nonce_generic_array, ciphertext.as_ref()).unwrap();
        plaintext
    }

    /// Decrypts with AscondAead on the threadpool
    fn decrypt_threadpool(key: [u8; 16], nonce: [u8; 16], ciphertext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let plaintext = Self::decrypt(key, nonce, ciphertext);
            sender.send(plaintext).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Generates a 16-byte key for Ascon Aead
    fn generate_key() -> [u8; 16] {
        return Ascon128::generate_key(&mut OsRng).into();
    }

    /// Generates a 16-byte key for Ascon Aead on the threadpool
    fn generate_key_threadpool() -> [u8; 16] {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let key = Self::generate_key();
            sender.send(key).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Generates a Ascon Aead nonce
    fn generate_nonce() -> [u8; 16] {
        return Ascon128::generate_nonce(&mut OsRng).into();
    }

    /// Generates a Ascon Aead nonce on the threadpool
    fn generate_nonce_threadpool() -> [u8; 16] {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let key = <AsconAead as CASAsconAead>::generate_nonce();
            sender.send(key).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
}