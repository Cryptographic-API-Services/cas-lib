use aes_gcm::{aead::Aead, aes::cipher::crypto_common::Generate};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit};

use crate::symmetric::cas_symmetric_encryption::Chacha20Poly1305Encryption;


pub struct CASChacha20Poly1305;

impl Chacha20Poly1305Encryption for CASChacha20Poly1305 {
    
    fn generate_key() -> Vec<u8> {
       Key::generate().to_vec()
    }

    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = Key::try_from(aes_key.as_slice()).unwrap();
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::try_from(nonce.as_slice()).unwrap();
        cipher.encrypt(&nonce, plaintext.as_ref()).expect("encryption failed")
    }

    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = Key::try_from(aes_key.as_slice()).unwrap();
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::try_from(nonce.as_slice()).unwrap();
        cipher.decrypt(&nonce, ciphertext.as_ref()).expect("decryption failed")
    }

    fn generate_nonce() -> Vec<u8> {
        Nonce::try_generate().unwrap().to_vec()
    }
}