use ascon_aead::{AsconAead128 as Ascon128, Key, AsconAead128Nonce, aead::{Aead, KeyInit}};
use rand::{rngs::OsRng, RngCore};

use super::cas_ascon_aead::{CASAsconAead};
pub struct AsconAead;

impl CASAsconAead for AsconAead {   
    /// Encrypts with AscondAead
    fn encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        if key.len() != 16 || nonce.len() != 16 {
            panic!("Key and nonce must be 16 bytes long");
        }
        let key_array: [u8; 16] = key.try_into().unwrap();
        let key_generic_array = Key::<Ascon128>::from(key_array);
        let nonce_array: [u8; 16] = nonce.try_into().unwrap();
        let nonce_generic_array = AsconAead128Nonce::from(nonce_array);
        let cipher = Ascon128::new(&key_generic_array);
        let ciphertext = cipher.encrypt(&nonce_generic_array, plaintext.as_ref()).unwrap();
        ciphertext
    }

    /// Decrypts with AscondAead 
    fn decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        if key.len() != 16 || nonce.len() != 16 {
            panic!("Key and nonce must be 16 bytes long");
        }
        let key_array: [u8; 16] = key.try_into().unwrap();
        let key_generic_array = Key::<Ascon128>::from(key_array);
        let nonce_array: [u8; 16] = nonce.try_into().unwrap();
        let nonce_generic_array = AsconAead128Nonce::from(nonce_array);
        let cipher = Ascon128::new(&key_generic_array);
        let plaintext = cipher.decrypt(&nonce_generic_array, ciphertext.as_ref()).unwrap();
        plaintext
    }
    
    /// Generates a 16-byte key for Ascon Aead
    fn generate_key() -> Vec<u8> {
        let mut key_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut key_bytes);
        return Key::<Ascon128>::from(key_bytes).to_vec();
    }
    
    /// Generates a Ascon Aead nonce
    fn generate_nonce() -> Vec<u8> {
        let mut nonce_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_bytes);
        return AsconAead128Nonce::from(nonce_bytes).to_vec();
    }
}