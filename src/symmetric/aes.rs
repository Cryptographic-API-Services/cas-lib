use std::sync::mpsc;

use aes_gcm::Key;

use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
};
use sha2::Sha256;

use super::cas_symmetric_encryption::{Aes128KeyFromX25519SharedSecret, Aes256KeyFromX25519SharedSecret, CASAES128Encryption, CASAES256Encryption};
pub struct CASAES128;
pub struct CASAES256;

impl CASAES256Encryption for CASAES256 {

    /// Generates an AES256 key from a vector
    fn key_from_vec(key_slice: Vec<u8>) -> Vec<u8> {
        let result = Key::<Aes256Gcm>::from_slice(&key_slice).to_vec();
        result
    }

    /// Generates an AES256 key from a vector on the threadpool
    fn key_from_vec_threadpool(key_slice: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = Key::<Aes256Gcm>::from_slice(&key_slice).to_vec();
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Generates an AES 256 32-bit Key
    fn generate_key() -> Vec<u8> {
        return Aes256Gcm::generate_key(&mut OsRng).to_vec();
    }

    /// Generates an AES 256 32-bit Key on the threadpool
    fn generate_key_threadpool() -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let thread_result = Self::generate_key();
            sender.send(thread_result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Encrypts with AES-256-GCM taking an aes_key and aes_nonce
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        ciphertext
    }

    /// Encrypts with AES-256-GCM taking an aes_key and aes_nonce on the threadpool
    fn encrypt_plaintext_threadpool(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let ciphertext = Self::encrypt_plaintext(aes_key, nonce, plaintext);
            sender.send(ciphertext).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Decrypts with AES-256-GCM taking an aes_key and aes_nonce
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    /// Encrypts with AES-256-GCM taking an aes_key and aes_nonce on the threadpool
    fn decrypt_ciphertext_threadpool(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let plaintext = Self::decrypt_ciphertext(aes_key, nonce, ciphertext);
            sender.send(plaintext).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Creates an AES-256 key 32-byte key from an X25519 Shared Secret
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> Aes256KeyFromX25519SharedSecret {
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut aes_key    = Box::new([0u8; 32]);
        let mut aes_nonce = Box::new([0u8; 12]);
        hk.expand(b"aes key", &mut *aes_key).unwrap();
        hk.expand(b"nonce",   &mut *aes_nonce).unwrap();
        let result = Aes256KeyFromX25519SharedSecret {
            aes_key: aes_key.to_vec(),
            aes_nonce: aes_nonce.to_vec(),
        };
        result
    }

    /// Creates an AES-256 key 32-byte key from an X25519 Shared Secret on the threadpool
    fn key_from_x25519_shared_secret_threadpool(shared_secret: Vec<u8>) -> Aes256KeyFromX25519SharedSecret {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = Self::key_from_x25519_shared_secret(shared_secret);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Generates an AES nonce
    fn generate_nonce() -> Vec<u8> {
        let mut bytes = [0u8; 12];
        OsRng.fill_bytes(&mut bytes);
        bytes.to_vec()
    }

    /// Generates an AES nonce on the threadpool
    fn generate_nonce_threadpool() -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let random_bytes = Self::generate_nonce();
            sender.send(random_bytes).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
}

impl CASAES128Encryption for CASAES128 {

    /// Generates an AES128 key from a vector
    fn key_from_vec(key_slice: Vec<u8>) -> Vec<u8> {
        let result = Key::<Aes128Gcm>::from_slice(&key_slice).to_vec();
        result
    }

    /// Generates an AES128 key from a vector on the threadpool
    fn key_from_vec_threadpool(key_slice: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = Key::<Aes128Gcm>::from_slice(&key_slice).to_vec();
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Generates an AES-128 16-byte key
    fn generate_key() -> Vec<u8> {
        return Aes128Gcm::generate_key(&mut OsRng).to_vec();
    }

    /// Generates an AES-128 16-byte key on the threadpool
    fn generate_key_threadpool() -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let key = Self::generate_key();
            sender.send(key).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Encrypts with AES-128-GCM taking an aes_key and aes_nonce
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap().into();
        ciphertext
    }

    /// Encrypts with AES-128-GCM taking an aes_key and aes_nonce on the threadpool
    fn encrypt_plaintext_threadpool(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let ciphertext = Self::encrypt_plaintext(aes_key, nonce, plaintext);
            sender.send(ciphertext).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Decrypts with AES-128-GCM taking an aes_key and aes_nonce
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    /// Decrypts with AES-128-GCM taking an aes_key and aes_nonce on the threadpool
    fn decrypt_ciphertext_threadpool(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let plaintext = Self::decrypt_ciphertext(aes_key, nonce, ciphertext);
            sender.send(plaintext).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }

    /// Generates an AES-128 16-byte key from an X25519 shared secret
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> Aes128KeyFromX25519SharedSecret {
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut aes_key    = Box::new([0u8; 16]);
        let mut aes_nonce = Box::new([0u8; 12]);
        hk.expand(b"aes key", &mut *aes_key).unwrap();
        hk.expand(b"nonce",   &mut *aes_nonce).unwrap();
        let result = Aes128KeyFromX25519SharedSecret {
            aes_key: aes_key.to_vec(),
            aes_nonce: aes_nonce.to_vec(),
        };
        result
    }

    /// Generates an AES-128 16-byte key from an X25519 shared secret on the threadpool
    fn key_from_x25519_shared_secret_threadpool(shared_secret: Vec<u8>) -> Aes128KeyFromX25519SharedSecret {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let result = Self::key_from_x25519_shared_secret(shared_secret);
            sender.send(result).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
    
    /// Generates an AES nonce
    fn generate_nonce() -> Vec<u8> {
        let mut bytes = [0u8; 12];
        OsRng.fill_bytes(&mut bytes);
        bytes.to_vec()
    }

    /// Generates an AES nonce on the threadpool
    fn generate_nonce_threadpool() -> Vec<u8> {
        let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let random_bytes = Self::generate_nonce();
            sender.send(random_bytes).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
    }
}