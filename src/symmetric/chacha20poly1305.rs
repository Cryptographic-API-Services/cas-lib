use rand::RngCore;
use aes_gcm::{aead::Aead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit};
use rand::rngs::OsRng;

use crate::symmetric::cas_symmetric_encryption::Chacha20Poly1305Encryption;


pub struct CASChacha20Poly1305;

impl Chacha20Poly1305Encryption for CASChacha20Poly1305 {
    
    fn generate_key() -> Vec<u8> {
        ChaCha20Poly1305::generate_key(&mut OsRng).to_vec()
    }

    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = Key::from_slice(aes_key.as_slice());
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(nonce.as_slice());
        cipher.encrypt(nonce, plaintext.as_ref()).expect("encryption failed")
    }

    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = Key::from_slice(aes_key.as_slice());
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(nonce.as_slice());
        cipher.decrypt(nonce, ciphertext.as_ref()).expect("decryption failed")
    }

    fn generate_nonce() -> Vec<u8> {
        let mut nonce = [0u8; 12]; // ChaCha20Poly1305 uses 96-bit (12-byte) nonces
        OsRng.fill_bytes(&mut nonce);
        nonce.to_vec()
    }
}