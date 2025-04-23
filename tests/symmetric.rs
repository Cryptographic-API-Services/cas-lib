use std::{fs::{File}, io::Write, path::Path};

use cas_lib::symmetric::{aes::CASAES256, cas_symmetric_encryption::CASAES256Encryption};

#[cfg(test)]
mod tests {
    use cas_lib::{key_exchange::{cas_key_exchange::CASKeyExchange, x25519::X25519}, symmetric::{aes::CASAES128, cas_symmetric_encryption::CASAES128Encryption}};

    use super::*;
    #[test]
    fn test_aes_256() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let aes_nonce = <CASAES256 as CASAES256Encryption>::generate_nonce();
        let aes_key = <CASAES256 as CASAES256Encryption>::generate_key();
        let encrypted_bytes = <CASAES256 as CASAES256Encryption>::encrypt_plaintext(aes_key, aes_nonce, file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes).unwrap();

        let decrypted_bytes = <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(aes_key, aes_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    fn test_aes256_x25519_diffie_hellman() {
        let bob_public = <X25519 as CASKeyExchange>::generate_secret_and_public_key();
        let alice_public = <X25519 as CASKeyExchange>::generate_secret_and_public_key();

        let bob_shared_secret = <X25519 as CASKeyExchange>::diffie_hellman(bob_public.secret_key, alice_public.public_key);
        let alice_shared_secret = <X25519 as CASKeyExchange>::diffie_hellman(alice_public.secret_key, bob_public.public_key);

        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let alice_key = <CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(bob_shared_secret);
        let encrypted_bytes = <CASAES256 as CASAES256Encryption>::encrypt_plaintext(alice_key.aes_key, alice_key.aes_nonce, file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes).unwrap();

        let bob_key = <CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(alice_shared_secret);
        let decrypted_bytes = <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(bob_key.aes_key, bob_key.aes_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }
    
    #[test]
    fn test_aes_128() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let aes_nonce = <CASAES128 as CASAES128Encryption>::generate_nonce();
        let aes_key = <CASAES128 as CASAES128Encryption>::generate_key();
        let encrypted_bytes = <CASAES128 as CASAES128Encryption>::encrypt_plaintext(aes_key, aes_nonce, file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes).unwrap();


        let decrypted_bytes = <CASAES128 as CASAES128Encryption>::decrypt_ciphertext(aes_key, aes_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    fn test_aes128_x25519_diffie_hellman() {
        let bob_public = <X25519 as CASKeyExchange>::generate_secret_and_public_key();
        let alice_public = <X25519 as CASKeyExchange>::generate_secret_and_public_key();

        let bob_shared_secret = <X25519 as CASKeyExchange>::diffie_hellman(bob_public.secret_key, alice_public.public_key);
        let alice_shared_secret = <X25519 as CASKeyExchange>::diffie_hellman(alice_public.secret_key, bob_public.public_key);

        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let alice_key = <CASAES128 as CASAES128Encryption>::key_from_x25519_shared_secret(bob_shared_secret);
        let encrypted_bytes = <CASAES128 as CASAES128Encryption>::encrypt_plaintext(alice_key.aes_key, alice_key.aes_nonce, file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes).unwrap();

        let bob_key = <CASAES128 as CASAES128Encryption>::key_from_x25519_shared_secret(alice_shared_secret);
        let decrypted_bytes = <CASAES128 as CASAES128Encryption>::decrypt_ciphertext(bob_key.aes_key, bob_key.aes_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }
}