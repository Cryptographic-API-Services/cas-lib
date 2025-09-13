use aes_gcm::aead::Aead;
use aes_gcm::{AeadCore, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::symmetric::cas_symmetric_encryption::Chacha20Poly1305Encryption;


pub struct CASChacha20Poly1305;

impl Chacha20Poly1305Encryption for CASChacha20Poly1305 {
    
    fn generate_key() -> Vec<u8> {
        ChaCha20Poly1305::generate_key(&mut OsRng).to_vec()
    }

    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = Key::from_slice(&aes_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&nonce);
        cipher.encrypt(nonce, plaintext.as_ref()).expect("encryption failed")
    }

    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = Key::from_slice(&aes_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&nonce);
        cipher.decrypt(nonce, ciphertext.as_ref()).expect("decryption failed")
    }

    fn generate_nonce() -> Vec<u8> {
        ChaCha20Poly1305::generate_nonce(&mut OsRng).to_vec()
    }
}