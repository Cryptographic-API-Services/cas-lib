use std::sync::mpsc;

use aes_gcm::Key;

use rand::rngs::OsRng;
use rand::RngCore;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
};

use super::cas_symmetric_encryption::{Aes128KeyFromX25519SharedSecret, Aes256KeyFromX25519SharedSecret, CASAES128Encryption, CASAES256Encryption};
pub struct CASAES128;
pub struct CASAES256;

impl CASAES256Encryption for CASAES256 {
    /// Generates an AES 256 32-bit Key
    fn generate_key() -> [u8; 32] {
        return Aes256Gcm::generate_key(&mut OsRng).into();
    }

    /// Generates an AES 256 32-bit Key on the threadpool
    fn generate_key_threadpool() -> [u8; 32] {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let thread_result = Self::generate_key();
            sender.send(thread_result);
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Encrypts with AES-256-GCM taking an aes_key and aes_nonce
    fn encrypt_plaintext(aes_key: [u8; 32], nonce: [u8; 12], plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        ciphertext
    }

    /// Encrypts with AES-256-GCM taking an aes_key and aes_nonce on the threadpool
    fn encrypt_plaintext_threadpool(aes_key: [u8; 32], nonce: [u8; 12], plaintext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let ciphertext = Self::encrypt_plaintext(aes_key, nonce, plaintext);
            sender.send(ciphertext);
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Decrypts with AES-256-GCM taking an aes_key and aes_nonce
    fn decrypt_ciphertext(aes_key: [u8; 32], nonce: [u8; 12], ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    /// Encrypts with AES-256-GCM taking an aes_key and aes_nonce on the threadpool
    fn decrypt_ciphertext_threadpool(aes_key: [u8; 32], nonce: [u8; 12], ciphertext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let plaintext = Self::decrypt_ciphertext(aes_key, nonce, ciphertext);
            sender.send(plaintext);
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Creates an AES-256 key 32-byte key from an X25519 Shared Secret
    fn key_from_x25519_shared_secret(shared_secret: [u8; 32]) -> Aes256KeyFromX25519SharedSecret {
        let aes_key = (*Key::<Aes256Gcm>::from_slice(&shared_secret)).into();
        let mut aes_nonce: [u8; 12] = Default::default();
        aes_nonce.copy_from_slice(&shared_secret[..12]);
        let result = Aes256KeyFromX25519SharedSecret {
            aes_key: aes_key,
            aes_nonce: aes_nonce,
        };
        result
    }

    /// Creates an AES-256 key 32-byte key from an X25519 Shared Secret on the threadpool
    fn key_from_x25519_shared_secret_threadpool(shared_secret: [u8; 32]) -> Aes256KeyFromX25519SharedSecret {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = Self::key_from_x25519_shared_secret(shared_secret);
            sender.send(result);
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Generates an AES nonce
    fn generate_nonce() -> [u8; 12] {
        let mut bytes = [0u8; 12];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    /// Generates an AES nonce on the threadpool
    fn generate_nonce_threadpool() -> [u8; 12] {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let random_bytes = Self::generate_nonce();
            sender.send(random_bytes);
        });
        let result = receiver.recv().unwrap();
        result
    }
}

impl CASAES128Encryption for CASAES128 {
    /// Generates an AES-128 16-byte key
    fn generate_key() -> [u8; 16] {
        return Aes128Gcm::generate_key(&mut OsRng).into();
    }

    /// Generates an AES-128 16-byte key on the threadpool
    fn generate_key_threadpool() -> [u8; 16] {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let key = Self::generate_key();
            sender.send(key);
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Encrypts with AES-128-GCM taking an aes_key and aes_nonce
    fn encrypt_plaintext(aes_key: [u8; 16], nonce: [u8; 12], plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap().into();
        ciphertext
    }

    /// Encrypts with AES-128-GCM taking an aes_key and aes_nonce on the threadpool
    fn encrypt_plaintext_threadpool(aes_key: [u8; 16], nonce: [u8; 12], plaintext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let ciphertext = Self::encrypt_plaintext(aes_key, nonce, plaintext);
            sender.send(ciphertext);
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Decrypts with AES-128-GCM taking an aes_key and aes_nonce
    fn decrypt_ciphertext(aes_key: [u8; 16], nonce: [u8; 12], ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    /// Decrypts with AES-128-GCM taking an aes_key and aes_nonce on the threadpool
    fn decrypt_ciphertext_threadpool(aes_key: [u8; 16], nonce: [u8; 12], ciphertext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let plaintext = Self::decrypt_ciphertext(aes_key, nonce, ciphertext);
            sender.send(plaintext);
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Generates an AES-128 16-byte key from an X25519 shared secret
    fn key_from_x25519_shared_secret(shared_secret: [u8; 32]) -> Aes128KeyFromX25519SharedSecret {
        let mut aes_key: [u8; 16] = Default::default();
        aes_key.copy_from_slice(&shared_secret[..16]);
        let aes_key_slice: [u8; 16] = (*Key::<Aes128Gcm>::from_slice(&aes_key)).into();
        let mut aes_nonce: [u8; 12] = Default::default();
        aes_nonce.copy_from_slice(&shared_secret[..12]);
        let result = Aes128KeyFromX25519SharedSecret {
            aes_key: aes_key_slice,
            aes_nonce: aes_nonce,
        };
        result
    }

    /// Generates an AES-128 16-byte key from an X25519 shared secret on the threadpool
    fn key_from_x25519_shared_secret_threadpool(shared_secret: [u8; 32]) -> Aes128KeyFromX25519SharedSecret {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = Self::key_from_x25519_shared_secret(shared_secret);
            sender.send(result);
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Generates an AES nonce
    fn generate_nonce() -> [u8; 12] {
        let mut bytes = [0u8; 12];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    /// Generates an AES nonce on the threadpool
    fn generate_nonce_threadpool() -> [u8; 12] {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let random_bytes = Self::generate_nonce();
            sender.send(random_bytes);
        });
        let result = receiver.recv().unwrap();
        result
    }
}