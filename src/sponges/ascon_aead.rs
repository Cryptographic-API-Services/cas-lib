


use aes_gcm::AeadCore;
use ascon_aead::{aead::{generic_array::GenericArray, Aead, KeyInit, OsRng}, AsconAead128 as Ascon128};

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
    
    /// Generates a 16-byte key for Ascon Aead
    fn generate_key() -> Vec<u8> {
        return Ascon128::generate_key(&mut OsRng).to_vec();
    }
    
    /// Generates a Ascon Aead nonce
    fn generate_nonce() -> Vec<u8> {
        return Ascon128::generate_nonce(&mut OsRng).to_vec();
    }
}