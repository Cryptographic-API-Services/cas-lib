#[cfg(test)]
mod password_hashers {
    use std::path::Path;
    use cas_lib::{password_hashers::argon2::CASArgon, symmetric::{aes::{CASAES128, CASAES256}, cas_symmetric_encryption::{CASAES128Encryption, CASAES256Encryption}}};
    
    #[test]
    pub fn argon2_derive_aes_128_and_encrypt() {
        let password = b"BadPassword"; // do not use this as a password.
        let key = CASArgon::derive_aes_128_key(password);
        let nonce = CASAES128::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let encrypted = CASAES128::encrypt_plaintext(key, nonce.clone(), file_bytes.clone());
        let decrypted = CASAES128::decrypt_ciphertext(key, nonce, encrypted);
        assert_eq!(file_bytes, decrypted);
    }

    #[test]
    pub fn argon2_derive_aes_256_and_encrypt() {
        let password = b"BadPassword"; // do not use this as a password.
        let key = CASArgon::derive_aes_256_key(password);
        let nonce = CASAES128::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let encrypted = CASAES256::encrypt_plaintext(key, nonce.clone(), file_bytes.clone());
        let decrypted = CASAES256::decrypt_ciphertext(key, nonce, encrypted);
        assert_eq!(file_bytes, decrypted);
    }
}