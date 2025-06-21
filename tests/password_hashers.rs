#[cfg(test)]
mod password_hashers {
    use std::path::Path;
    use cas_lib::{password_hashers::{argon2::CASArgon, bcrypt::CASBCrypt, cas_password_hasher::CASPasswordHasher, scrypt::CASScrypt}, symmetric::{aes::{CASAES128, CASAES256}, cas_symmetric_encryption::{CASAES128Encryption, CASAES256Encryption}}};
    
    #[test]
    pub fn argon2_derive_aes_128_and_encrypt() {
        let password = b"BadPassword"; // do not use this as a password.
        let key = CASArgon::derive_aes_128_key(password);
        let nonce = CASAES128::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let encrypted = CASAES128::encrypt_plaintext(key, nonce, file_bytes.clone());
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

        let encrypted = CASAES256::encrypt_plaintext(key, nonce, file_bytes.clone());
        let decrypted = CASAES256::decrypt_ciphertext(key, nonce, encrypted);
        assert_eq!(file_bytes, decrypted);
    }

    #[test]
    pub fn argon2_derive_aes_128_and_encrypt_threadpool() {
        let password = b"BadPassword"; // do not use this as a password.
        let key = CASArgon::derive_aes_128_key(password);
        let nonce = CASAES128::generate_nonce_threadpool();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let encrypted = CASAES128::encrypt_plaintext_threadpool(key, nonce, file_bytes.clone());
        let decrypted = CASAES128::decrypt_ciphertext_threadpool(key, nonce, encrypted);
        assert_eq!(file_bytes, decrypted);
    }

    #[test]
    pub fn argon2_derive_aes_256_and_encrypt_threadpool() {
        let password = b"BadPassword"; // do not use this as a password.
        let key = CASArgon::derive_aes_256_key(password);
        let nonce = CASAES128::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let encrypted = CASAES256::encrypt_plaintext(key, nonce, file_bytes.clone());
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
    pub fn argon2_hash_password_threadpool() {
        let password = "BadPassword".to_string();
        let hash = CASArgon::hash_password_threadpool(password.clone());
        let verification = CASArgon::verify_password_threadpool(hash, password);
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
    pub fn scrypt_hash_password_threadpool() {
        let password = "DoNotUseThisPassword".to_string();
        let hash = CASScrypt::hash_password_threadpool(password.clone());
        let verification = CASScrypt::verify_password_threadpool(hash, password);
        assert_eq!(true, verification);
    }

    #[test]
    pub fn bcrypt_hash_password() {
        let password = "DoNotUseThisPassword".to_string();
        let hash = CASBCrypt::hash_password(password.clone());
        let verification = CASBCrypt::verify_password(hash, password);
        assert_eq!(true, verification);
    }

    #[test]
    pub fn bcrypt_hash_password_threadpool() {
        let password = "DoNotUseThisPassword".to_string();
        let hash = CASBCrypt::hash_password_threadpool(password.clone());
        let verification = CASBCrypt::verify_password_threadpool(hash, password);
        assert_eq!(true, verification);
    }


}