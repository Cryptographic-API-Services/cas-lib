#[cfg(test)]
mod password_hashers {
    use std::path::Path;
    use cas_lib::{
        error::CasError,
        password_hashers::{argon2::CASArgon, bcrypt::CASBCrypt, pbkdf2, scrypt::CASScrypt},
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
                let derived = pbkdf2::derivation_with_salt($password.to_vec(), $rounds, $salt.to_vec()).unwrap();
                assert_eq!(
                    derived,
                    hex_to_bytes($expected_hex),
                    "PBKDF2-HMAC-SHA3-256 mismatch for password {:?}, salt {:?}, iterations {}",
                    $password,
                    $salt,
                    $rounds
                );
            )*
        };
    }

    // PBKDF2-HMAC-SHA3-256 known answers at the minimum iteration count and salt length, in the
    // style of RFC 6070 (https://www.rfc-editor.org/rfc/rfc6070). The expected values were
    // computed independently with OpenSSL through Python's
    // `hashlib.pbkdf2_hmac("sha3_256", password, salt, iterations)`, so they also pin the PRF:
    // keys derived before the minimums were introduced stay derivable.
    #[test]
    pub fn pbkdf2_sha3_known_answer_vectors() {
        pbkdf2_vectors!(
            b"password", b"saltSALTsaltSALT", 600_000,
                "09b0b25930ec6de36f4035300c0f0e30b82643df38291dc2ff6c67a32b42d568";
            b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 600_000,
                "0f2b39323f7523a6eef386c4458b0c5e055fb5f9349655cf704b31244751a95f";
            b"pass\0word", b"sa\0ltsa\0ltsa\0lt\0", 600_001,
                "3ff5f88bfbd68d52fcbe84b1d0f0fbc7e0e44bdb87621b384a50f0fe22eb39bc";
        );
    }

    #[test]
    pub fn pbkdf2_minimums_are_exposed() {
        assert_eq!(pbkdf2::MIN_ITERATIONS, 600_000);
        assert_eq!(pbkdf2::MIN_SALT_LENGTH, 16);
    }

    #[test]
    pub fn pbkdf2_accepts_exact_minimums() {
        let salt = vec![0x5a; pbkdf2::MIN_SALT_LENGTH];
        let key = pbkdf2::derivation_with_salt(b"BadPassword".to_vec(), pbkdf2::MIN_ITERATIONS, salt).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    pub fn pbkdf2_rejects_iterations_below_minimum() {
        let salt = vec![0x5a; pbkdf2::MIN_SALT_LENGTH];
        for iterations in [0, 1, 4_096, pbkdf2::MIN_ITERATIONS - 1] {
            assert_eq!(
                pbkdf2::derivation_with_salt(b"BadPassword".to_vec(), iterations, salt.clone()),
                Err(CasError::InvalidParameters),
                "derivation_with_salt accepted {iterations} iterations"
            );
            assert!(
                matches!(pbkdf2::derivation(b"BadPassword".to_vec(), iterations), Err(CasError::InvalidParameters)),
                "derivation accepted {iterations} iterations"
            );
        }
    }

    #[test]
    pub fn pbkdf2_rejects_salt_below_minimum() {
        for salt_length in [0, 1, 8, pbkdf2::MIN_SALT_LENGTH - 1] {
            assert_eq!(
                pbkdf2::derivation_with_salt(b"BadPassword".to_vec(), pbkdf2::MIN_ITERATIONS, vec![0x5a; salt_length]),
                Err(CasError::InvalidParameters),
                "derivation_with_salt accepted a {salt_length}-byte salt"
            );
        }
    }

    #[test]
    pub fn pbkdf2_derivation_round_trip_reuses_salt() {
        let password = b"BadPassword".to_vec();
        let rounds = pbkdf2::MIN_ITERATIONS;
        let result = pbkdf2::derivation(password.clone(), rounds).unwrap();

        assert_eq!(result.password.len(), 32);
        assert!(result.salt.len() >= pbkdf2::MIN_SALT_LENGTH);

        let recomputed = pbkdf2::derivation_with_salt(password, rounds, result.salt.clone()).unwrap();
        assert_eq!(recomputed, result.password);
    }
}
