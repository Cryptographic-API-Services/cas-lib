#[cfg(test)]
mod password_hashers {
    use std::path::Path;
    use cas_lib::{
        password_hashers::{argon2::CASArgon, bcrypt::CASBCrypt, pbkdf2, scrypt::CASScrypt},
        symmetric::{
            aes::{CASAES128, CASAES256},
            cas_symmetric_encryption::{CASAES128Encryption, CASAES256Encryption},
        },
    };
    
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

    #[test]
    pub fn bcrypt_hash_password_customized() {
        let password = "DoNotUseThisPassword".to_string();
        let hash = CASBCrypt::hash_password_customized(password.clone(), 12);
        let verification = CASBCrypt::verify_password(hash, password);
        assert_eq!(true, verification);
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let hex = hex.trim();
        assert_eq!(hex.len() % 2, 0, "hex input must have an even number of characters");

        let mut out = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex digit");
            out.push(byte);
        }

        out
    }

    macro_rules! pbkdf2_vectors {
        ($($password:expr, $salt:expr, $rounds:expr, $expected_hex:expr;)*) => {
            $(
                let derived = pbkdf2::derivation_with_salt($password.to_vec(), $rounds, $salt.to_vec());
                assert_eq!(
                    derived,
                    hex_to_bytes($expected_hex),
                    "PBKDF2-SHA3 mismatch for password {:?}, salt {:?}, iterations {}",
                    $password,
                    $salt,
                    $rounds
                );
            )*
        };
    }

    #[test]
    pub fn pbkdf2_sha3_rfc6070_style_vectors() {
        pbkdf2_vectors!(
            b"password", b"salt", 1, "94613f3ee2ea730e0b06754f3fc816d4f87c9be9cbd8556b5d59b52330e333a8";
            b"password", b"salt", 2, "4c915baedd1773383e77fcfe38114ca7514010adec24b47290ec170208423f76";
            b"password", b"salt", 4096, "778b6e237a0f49621549ff70d218d2080756b9fb38d71b5d7ef447fa2254af61";
            b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
                "7aef8f1ad8c7f12205334f624d4af9e2863121618f7a0b3209bef3934801c39f";
            b"pass\0word", b"sa\0lt", 4096, "98e5503130ffdd69603da78cbb12e9becb948efa1445a639569cc1b042e643fd";
        );
    }

    #[test]
    pub fn pbkdf2_derivation_round_trip_reuses_salt() {
        let password = b"BadPassword".to_vec();
        let rounds = 8_192;
        let result = pbkdf2::derivation(password.clone(), rounds);

        assert_eq!(result.password.len(), 32);
        assert!(!result.salt.is_empty());

        let recomputed = pbkdf2::derivation_with_salt(password, rounds, result.salt.clone());
        assert_eq!(recomputed, result.password);
    }
}
