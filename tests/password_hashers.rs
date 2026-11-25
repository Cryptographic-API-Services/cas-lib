#[cfg(test)]
mod password_hashers {
    use std::path::Path;
    use cas_lib::{
        error::CasError,
        password_hashers::{
            argon2::CASArgon,
            bcrypt::{CASBCrypt, BCRYPT_MAX_PASSWORD_BYTES},
            pbkdf2,
            scrypt::CASScrypt,
        },
        symmetric::{
            aes::{CASAES128, CASAES256},
            cas_symmetric_encryption::{CASAES128Encryption, CASAES256Encryption},
        },
    };
    
    #[test]
    pub fn argon2_hash_with_parameters() {
        let password = "BadPassword".to_string();
        let hash = CASArgon::hash_password_parameters(1024, 5, 5, password.clone()).unwrap();
        let verification = CASArgon::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn argon2_derive_aes_128_and_encrypt() {
        let password = b"BadPassword".to_vec(); // do not use this as a password.
        let key = CASArgon::derive_aes_128_key(password).unwrap();
        let nonce = CASAES128::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let encrypted = CASAES128::encrypt_plaintext(key.clone(), nonce.clone(), file_bytes.clone()).unwrap();
        let decrypted = CASAES128::decrypt_ciphertext(key, nonce, encrypted).unwrap();
        assert_eq!(file_bytes, decrypted);
    }

    #[test]
    pub fn argon2_derive_aes_256_and_encrypt() {
        let password = b"BadPassword".to_vec(); // do not use this as a password.
        let key = CASArgon::derive_aes_256_key(password).unwrap();
        let nonce = CASAES128::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let encrypted = CASAES256::encrypt_plaintext(key.clone(), nonce.clone(), file_bytes.clone()).unwrap();
        let decrypted = CASAES256::decrypt_ciphertext(key, nonce, encrypted).unwrap();
        assert_eq!(file_bytes, decrypted);
    }

    #[test]
    pub fn argon2_hash_password() {
        let password = "BadPassword".to_string();
        let hash = CASArgon::hash_password(password.clone()).unwrap();
        let verification = CASArgon::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn scrypt_hash_password() {
        let password = "DoNotUseThisPassword".to_string();
        let hash = CASScrypt::hash_password(password.clone()).unwrap();
        let verification = CASScrypt::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn scrypt_hash_password_customized() {
        let password = "DoNotUseThisPassword".to_string();
        let hash = CASScrypt::hash_password_customized(password.clone(), 17, 8, 1).unwrap();
        let verification = CASScrypt::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn bcrypt_hash_password() {
        let password = "DoNotUseThisPassword".to_string();
        let hash = CASBCrypt::hash_password(password.clone()).unwrap();
        let verification = CASBCrypt::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn bcrypt_hash_password_customized() {
        let password = "DoNotUseThisPassword".to_string();
        let hash = CASBCrypt::hash_password_customized(password.clone(), 12).unwrap();
        let verification = CASBCrypt::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn bcrypt_accepts_72_byte_password() {
        let password = "x".repeat(BCRYPT_MAX_PASSWORD_BYTES);
        assert_eq!(password.len(), 72);
        let hash = CASBCrypt::hash_password_customized(password.clone(), 4).unwrap();
        assert!(CASBCrypt::verify_password(hash.clone(), password).unwrap());
        // Changing the last of the 72 bytes changes the result: no byte is dropped.
        let last_byte_differs = format!("{}y", "x".repeat(71));
        assert!(!CASBCrypt::verify_password(hash, last_byte_differs).unwrap());
    }

    #[test]
    pub fn bcrypt_accepts_72_byte_multibyte_password() {
        // 24 three-byte characters: 24 chars, 72 bytes.
        let password = "€".repeat(24);
        assert_eq!(password.len(), 72);
        let hash = CASBCrypt::hash_password_customized(password.clone(), 4).unwrap();
        assert!(CASBCrypt::verify_password(hash, password).unwrap());
    }

    #[test]
    pub fn bcrypt_rejects_73_byte_password_on_hash() {
        let password = "x".repeat(73);
        assert_eq!(
            CASBCrypt::hash_password(password.clone()),
            Err(CasError::InvalidParameters)
        );
        assert_eq!(
            CASBCrypt::hash_password_customized(password, 4),
            Err(CasError::InvalidParameters)
        );
        // The limit is in bytes: 25 three-byte characters is 75 bytes.
        assert_eq!(
            CASBCrypt::hash_password_customized("€".repeat(25), 4),
            Err(CasError::InvalidParameters)
        );
    }

    #[test]
    pub fn bcrypt_rejects_73_byte_password_on_verify() {
        let hash = CASBCrypt::hash_password_customized("DoNotUseThisPassword".to_string(), 4).unwrap();
        assert_eq!(
            CASBCrypt::verify_password(hash, "x".repeat(73)),
            Err(CasError::InvalidParameters)
        );
    }

    #[test]
    pub fn bcrypt_passwords_sharing_first_72_bytes_are_not_equal() {
        let prefix = "x".repeat(72);
        let first = format!("{}first", prefix);
        let second = format!("{}second", prefix);

        // Neither long password can be hashed, so they cannot collide.
        assert_eq!(
            CASBCrypt::hash_password_customized(first, 4),
            Err(CasError::InvalidParameters)
        );

        // A long password no longer verifies against a hash of its first 72 bytes.
        let prefix_hash = CASBCrypt::hash_password_customized(prefix.clone(), 4).unwrap();
        assert!(CASBCrypt::verify_password(prefix_hash.clone(), prefix).unwrap());
        assert_eq!(
            CASBCrypt::verify_password(prefix_hash, second),
            Err(CasError::InvalidParameters)
        );
    }

    #[test]
    pub fn bcrypt_verifies_hash_from_truncating_version() {
        // bcrypt of "x" * 100 with cost 5, made by a truncating implementation
        // (the vector from the `bcrypt` crate's own tests, produced with Python's
        // bcrypt). It is the hash of the first 72 bytes, so the 72-byte password
        // still verifies while the original 100-byte input is now rejected.
        let legacy_hash = "$2a$05$......................YgIDy4hFBdVlc/6LHnD9mX488r9cLd2".to_string();
        assert!(CASBCrypt::verify_password(legacy_hash.clone(), "x".repeat(72)).unwrap());
        assert!(!CASBCrypt::verify_password(legacy_hash.clone(), "x".repeat(71)).unwrap());
        assert_eq!(
            CASBCrypt::verify_password(legacy_hash, "x".repeat(100)),
            Err(CasError::InvalidParameters)
        );
    }

    #[test]
    pub fn bcrypt_verifies_hash_created_before_length_check() {
        // Earlier versions of this crate hashed with plain `bcrypt::hash`.
        let password = "DoNotUseThisPassword".to_string();
        let old_hash = bcrypt::hash(&password, 4).unwrap();
        assert!(CASBCrypt::verify_password(old_hash.clone(), password).unwrap());
        assert!(!CASBCrypt::verify_password(old_hash, "wrong".to_string()).unwrap());

        // A hash made elsewhere (Python's bcrypt, from the `bcrypt` crate's tests).
        let python_hash = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie".to_string();
        assert!(CASBCrypt::verify_password(python_hash, "correctbatteryhorsestapler".to_string()).unwrap());
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

    // Borrowed from RustCrypto's pbkdf2 crate tests, which in turn are based on the test vectors from RFC 6070.
    // https://www.rfc-editor.org/rfc/rfc6070
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
