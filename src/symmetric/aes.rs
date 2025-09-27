use aes_gcm::{AeadCore, Key};

use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
};
use sha2::Sha256;

use super::cas_symmetric_encryption::{CASAES128Encryption, CASAES256Encryption};
pub struct CASAES128;
pub struct CASAES256;

impl CASAES256Encryption for CASAES256 {

    /// Generates an AES256 key from a vector
    fn key_from_vec(key_slice: Vec<u8>) -> Vec<u8> {
        let result = Key::<Aes256Gcm>::from_slice(&key_slice).to_vec();
        result
    }

    /// Generates an AES 256 32-bit Key
    fn generate_key() -> Vec<u8> {
        return Aes256Gcm::generate_key(&mut OsRng).to_vec();
    }


    /// Encrypts with AES-256-GCM taking an aes_key and aes_nonce
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        ciphertext
    }


    /// Decrypts with AES-256-GCM taking an aes_key and aes_nonce
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    /// Creates an AES-256 key 32-byte key from an X25519 Shared Secret
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut aes_key: Box<[u8; 32]> = Box::new([0u8; 32]);
        hk.expand(b"aes key", &mut *aes_key).unwrap();
        aes_key.to_vec()
    }

    
    /// Generates an AES nonce
    fn generate_nonce() -> Vec<u8> {
        let mut rng = OsRng;
        Aes256Gcm::generate_nonce(&mut rng).to_vec()
    }
}

impl CASAES128Encryption for CASAES128 {

    /// Generates an AES128 key from a vector
    fn key_from_vec(key_slice: Vec<u8>) -> Vec<u8> {
        let result = Key::<Aes128Gcm>::from_slice(&key_slice).to_vec();
        result
    }

    

    /// Generates an AES-128 16-byte key
    fn generate_key() -> Vec<u8> {
        return Aes128Gcm::generate_key(&mut OsRng).to_vec();
    }

    

    /// Encrypts with AES-128-GCM taking an aes_key and aes_nonce
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap().into();
        ciphertext
    }

    

    /// Decrypts with AES-128-GCM taking an aes_key and aes_nonce
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    

    /// Generates an AES-128 16-byte key from an X25519 shared secret
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut aes_key = Box::new([0u8; 16]);
        hk.expand(b"aes key", &mut *aes_key).unwrap();
        aes_key.to_vec()
    }

    
    
    /// Generates an AES nonce
    fn generate_nonce() -> Vec<u8> {
        let mut rng = OsRng;
        Aes128Gcm::generate_nonce(&mut rng).to_vec()
    }

    
}