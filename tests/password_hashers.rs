#[cfg(test)]
mod password_hashers {
    use std::path::Path;
    use cas_lib::{password_hashers::{argon2::CASArgon, bcrypt::CASBCrypt, scrypt::CASScrypt}, symmetric::{aes::{CASAES128, CASAES256}, cas_symmetric_encryption::{CASAES128Encryption, CASAES256Encryption}}};
    
    #[test]
    pub fn argon2_hash_with_parameters() {
        let password = "BadPassword".to_string();
        let hash = CASArgon::hash_password_parameters(1024, 5, 5, password.clone());
        let verification = CASArgon::verify_password(hash, password);
        assert_eq!(true, verification);
    }

    #[test]
    pub fn argon2_derive_aes_128_and_encrypt() {
        let password = b"BadPassword".to_vec(); // do not use this as a password.
        let key = CASArgon::derive_aes_128_key(password);
        let nonce = CASAES128::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let encrypted = CASAES128::encrypt_plaintext(key.clone(), nonce.clone(), file_bytes.clone());
        let decrypted = CASAES128::decrypt_ciphertext(key, nonce, encrypted);
        assert_eq!(file_bytes, decrypted);
    }

    #[test]
    pub fn argon2_derive_aes_256_and_encrypt() {
        let password = b"BadPassword".to_vec(); // do not use this as a password.
        let key = CASArgon::derive_aes_256_key(password);
        let nonce = CASAES128::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let encrypted = CASAES256::encrypt_plaintext(key.clone(), nonce.clone(), file_bytes.clone());
        let decrypted = CASAES256::decrypt_ciphertext(key, nonce, encrypted);
        assert_eq!(file_bytes, decrypted);
    }

    #[test]
    pub fn argon2_hash_password() {
        let password = "BadPassword".to_string();
        let hash = CASArgon::hash_password(password.clone());
        let verification = CASArgon::verify_password(hash, password);
        assert_eq!(true, verification);
    }

    #[test]
    pub fn scrypt_hash_password() {
        let password = "DoNotUseThisPassword".to_string();
        let hash = CASScrypt::hash_password(password.clone());
        let verification = CASScrypt::verify_password(hash, password);
        assert_eq!(true, verification);
    }

    #[test]
    pub fn scrypt_hash_password_customized() {
        let password = "DoNotUseThisPassword".to_string();
        let hash = CASScrypt::hash_password_customized(password.clone(), 17, 8, 1);
        let verification = CASScrypt::verify_password(hash, password);  
        assert_eq!(true, verification);
    }

    #[test]
    pub fn bcrypt_hash_password() {
        let password = "DoNotUseThisPassword".to_string();
        let hash = CASBCrypt::hash_password(password.clone());
        let verification = CASBCrypt::verify_password(hash, password);
        assert_eq!(true, verification);
    }


}