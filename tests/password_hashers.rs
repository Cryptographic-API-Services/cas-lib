#[cfg(test)]
mod password_hashers {
    use std::path::Path;
    use cas_lib::{
        error::CasError,
        password_hashers::{
            argon2::{self, CASArgon, KDF_SALT_LENGTH, MIN_SALT_LENGTH},
            bcrypt::{CASBCrypt, BCRYPT_MAX_COST, BCRYPT_MAX_PASSWORD_BYTES, BCRYPT_MIN_COST},
            pbkdf2,
            scrypt::{self, CASScrypt},
        },
        symmetric::{
            aes::{CASAES128, CASAES256},
            cas_symmetric_encryption::{CASAES128Encryption, CASAES256Encryption},
        },
    };
    use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};

    /// A fresh password for tests whose outcome does not depend on its value.
    fn random_password() -> String {
        OsRng.sample_iter(&Alphanumeric).take(20).map(char::from).collect()
    }

    /// A fresh salt of `len` bytes for tests whose outcome does not depend on its value.
    fn random_salt(len: usize) -> Vec<u8> {
        (0..len).map(|_| OsRng.gen()).collect()
    }

    #[test]
    pub fn argon2_hash_with_parameters() {
        let password = random_password();
        let hash = CASArgon::hash_password_parameters(1024, 5, 5, password.clone()).unwrap();
        let verification = CASArgon::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn argon2_memory_cost_overflow_is_rejected() {
        // memory_cost is in MiB and multiplied by 1024. 4_194_304 * 1024 wraps to 0 and
        // 4_194_305 * 1024 wraps to 1024 (1 MiB) in release builds; both must be errors,
        // never a panic or a silently weaker hash.
        for memory_cost in [4_194_304, 4_194_305, u32::MAX] {
            assert_eq!(
                CASArgon::hash_password_parameters(memory_cost, 1, 1, random_password()),
                Err(CasError::InvalidParameters),
                "memory_cost {memory_cost} MiB was accepted"
            );
        }
    }

    #[test]
    pub fn argon2_memory_cost_is_in_mebibytes() {
        let hash = CASArgon::hash_password_parameters(19, 1, 1, random_password()).unwrap();
        assert!(hash.contains("m=19456,"), "19 MiB should be stored as m=19456 KiB: {hash}");
    }

    #[test]
    pub fn argon2_rejects_parameters_outside_bounds() {
        let cases = [
            (argon2::MIN_MEMORY_COST_MIB - 1, 1, 1),
            (argon2::MAX_MEMORY_COST_MIB + 1, 1, 1),
            (argon2::MIN_MEMORY_COST_MIB, 0, 1),
            (argon2::MIN_MEMORY_COST_MIB, argon2::MAX_ITERATIONS + 1, 1),
            (argon2::MIN_MEMORY_COST_MIB, 1, 0),
            (argon2::MIN_MEMORY_COST_MIB, 1, argon2::MAX_PARALLELISM + 1),
        ];
        for (m, t, p) in cases {
            assert_eq!(
                CASArgon::hash_password_parameters(m, t, p, random_password()),
                Err(CasError::InvalidParameters),
                "accepted m={m} MiB, t={t}, p={p}"
            );
        }
    }

    #[test]
    pub fn argon2_bounds_are_documented_values() {
        assert_eq!(
            (argon2::MIN_MEMORY_COST_MIB, argon2::MAX_MEMORY_COST_MIB),
            (19, 4096)
        );
        assert_eq!((argon2::MIN_ITERATIONS, argon2::MAX_ITERATIONS), (1, 10));
        assert_eq!((argon2::MIN_PARALLELISM, argon2::MAX_PARALLELISM), (1, 16));
    }

    #[test]
    pub fn argon2_verify_rejects_hashes_over_the_bounds_before_hashing() {
        // A stored hash chooses its own cost. These would ask for 4 TiB of memory, a
        // huge iteration count or parallelism; verify must refuse them up front.
        let salt = "c29tZXNhbHRzb21lc2FsdA";
        let digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        for params in [
            format!("m={},t=1,p=1", (argon2::MAX_MEMORY_COST_MIB + 1) * 1024),
            format!("m=19456,t={},p=1", argon2::MAX_ITERATIONS + 1),
            format!("m=19456,t=1,p={}", argon2::MAX_PARALLELISM + 1),
            "m=4294967295,t=4294967295,p=255".to_string(),
        ] {
            let hostile = format!("$argon2id$v=19${params}${salt}${digest}");
            assert_eq!(
                CASArgon::verify_password(hostile.clone(), random_password()),
                Err(CasError::InvalidParameters),
                "verified {hostile}"
            );
        }
    }

    #[test]
    pub fn argon2_verify_still_accepts_hashes_below_the_hashing_minimums() {
        // Older hashes may use less memory than MIN_MEMORY_COST_MIB; they must verify.
        use ::argon2::{password_hash::{rand_core::OsRng, PasswordHasher, SaltString}, Algorithm, Argon2, Params, Version};
        let password = random_password();
        let weak = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(8 * 1024, 1, 1, None).unwrap())
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        assert!(CASArgon::verify_password(weak.clone(), password).unwrap());
        assert!(!CASArgon::verify_password(weak, random_password()).unwrap());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Argon2id v0x13, m = 19456 KiB, t = 2, p = 1, salt = 00..0f. Expected values
    /// from the libargon2 reference implementation (argon2-cffi `hash_secret_raw`).
    /// They pin the KDF parameters: a key derived from a stored salt must never change.
    #[test]
    pub fn argon2_derive_with_salt_known_answer() {
        let password = b"correct horse battery staple".to_vec();
        let salt: Vec<u8> = (0u8..16).collect();
        assert_eq!(
            CASArgon::derive_aes_128_key_with_salt(password.clone(), salt.clone()).unwrap(),
            hex("911d4ab546d03a49b9d668aa5f1619cd")
        );
        assert_eq!(
            CASArgon::derive_aes_256_key_with_salt(password, salt).unwrap(),
            hex("818259b6310026a8e0dbac5d2e6927abcfdb07b32258fac4f61b18b80f929085")
        );
    }

    #[test]
    pub fn argon2_derive_with_salt_rederives_the_same_key() {
        let password = random_password().into_bytes();
        let salt = CASArgon::generate_salt();
        assert_eq!(salt.len(), KDF_SALT_LENGTH);
        let key = CASArgon::derive_aes_256_key_with_salt(password.clone(), salt.clone()).unwrap();
        let again = CASArgon::derive_aes_256_key_with_salt(password.clone(), salt).unwrap();
        assert_eq!(key, again);

        // A different salt, or a different password, gives a different key.
        let other_salt = CASArgon::derive_aes_256_key_with_salt(password, CASArgon::generate_salt()).unwrap();
        assert_ne!(key, other_salt);

        let nonce = CASAES256::generate_nonce();
        let encrypted = CASAES256::encrypt_plaintext(key, nonce.clone(), b"hello".to_vec()).unwrap();
        assert_eq!(CASAES256::decrypt_ciphertext(again, nonce, encrypted).unwrap(), b"hello");
    }

    #[test]
    pub fn argon2_derive_with_salt_rejects_short_salt() {
        let short = vec![0u8; MIN_SALT_LENGTH - 1];
        assert!(matches!(
            CASArgon::derive_aes_128_key_with_salt(b"pw".to_vec(), short.clone()),
            Err(CasError::InvalidParameters)
        ));
        assert!(matches!(
            CASArgon::derive_aes_256_key_with_salt(b"pw".to_vec(), short),
            Err(CasError::InvalidParameters)
        ));
        assert!(CASArgon::derive_aes_128_key_with_salt(b"pw".to_vec(), vec![0u8; MIN_SALT_LENGTH]).is_ok());
    }

    #[test]
    #[allow(deprecated)]
    pub fn argon2_derive_aes_128_and_encrypt() {
        let password = random_password().into_bytes();
        let key = CASArgon::derive_aes_128_key(password).unwrap();
        let nonce = CASAES128::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let encrypted = CASAES128::encrypt_plaintext(key.clone(), nonce.clone(), file_bytes.clone()).unwrap();
        let decrypted = CASAES128::decrypt_ciphertext(key, nonce, encrypted).unwrap();
        assert_eq!(file_bytes, decrypted);
    }

    #[test]
    #[allow(deprecated)]
    pub fn argon2_derive_aes_256_and_encrypt() {
        let password = random_password().into_bytes();
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
        let password = random_password();
        let hash = CASArgon::hash_password(password.clone()).unwrap();
        let verification = CASArgon::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn scrypt_hash_password() {
        let password = random_password();
        let hash = CASScrypt::hash_password(password.clone()).unwrap();
        let verification = CASScrypt::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn scrypt_hash_password_customized() {
        let password = random_password();
        let hash = CASScrypt::hash_password_customized(password.clone(), 17, 8, 1).unwrap();
        let verification = CASScrypt::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn scrypt_rejects_parameters_outside_bounds() {
        let cases = [
            (scrypt::MIN_LOG_N - 1, 8, 1),
            (scrypt::MAX_LOG_N + 1, 8, 1),
            (40, 8, 1), // 128 PiB, from the issue
            (scrypt::MIN_LOG_N, 0, 1),
            (scrypt::MIN_LOG_N, scrypt::MAX_BLOCK_SIZE + 1, 1),
            (scrypt::MIN_LOG_N, 8, 0),
            (scrypt::MIN_LOG_N, 8, scrypt::MAX_PARALLELISM + 1),
        ];
        for (log_n, r, p) in cases {
            assert_eq!(
                CASScrypt::hash_password_customized(random_password(), log_n, r, p),
                Err(CasError::InvalidParameters),
                "accepted log_n={log_n}, r={r}, p={p}"
            );
        }
    }

    #[test]
    pub fn scrypt_accepts_the_bounds_themselves() {
        let password = random_password();
        let hash = CASScrypt::hash_password_customized(password.clone(), scrypt::MIN_LOG_N, 1, 1).unwrap();
        assert!(CASScrypt::verify_password(hash, password).unwrap());
        assert_eq!((scrypt::MIN_LOG_N, scrypt::MAX_LOG_N), (10, 20));
        assert_eq!((scrypt::MAX_BLOCK_SIZE, scrypt::MAX_PARALLELISM), (32, 16));
    }

    #[test]
    pub fn scrypt_verify_rejects_hashes_over_the_bounds_before_hashing() {
        let salt = "c29tZXNhbHRzb21lc2FsdA";
        let digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        for params in [
            format!("ln={},r=8,p=1", scrypt::MAX_LOG_N + 1),
            format!("ln=17,r={},p=1", scrypt::MAX_BLOCK_SIZE + 1),
            format!("ln=17,r=8,p={}", scrypt::MAX_PARALLELISM + 1),
            "ln=40,r=8,p=1".to_string(),
        ] {
            let hostile = format!("$scrypt${params}${salt}${digest}");
            assert_eq!(
                CASScrypt::verify_password(hostile.clone(), random_password()),
                Err(CasError::InvalidParameters),
                "verified {hostile}"
            );
        }
    }

    #[test]
    pub fn bcrypt_rejects_costs_outside_bounds() {
        for cost in [0, 4, BCRYPT_MIN_COST - 1, BCRYPT_MAX_COST + 1, 31] {
            assert_eq!(
                CASBCrypt::hash_password_customized(random_password(), cost),
                Err(CasError::InvalidParameters),
                "accepted cost {cost}"
            );
        }
        assert_eq!((BCRYPT_MIN_COST, BCRYPT_MAX_COST), (10, 16));
    }

    #[test]
    pub fn bcrypt_verify_rejects_costs_over_the_maximum_before_hashing() {
        // A $2b$31$ hash would take hours to check. It must be refused immediately.
        let hostile = format!(
            "$2b${:02}$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie",
            BCRYPT_MAX_COST + 1
        );
        assert_eq!(
            CASBCrypt::verify_password(hostile, random_password()),
            Err(CasError::InvalidParameters)
        );
        let hours = "$2b$31$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie".to_string();
        assert_eq!(
            CASBCrypt::verify_password(hours, random_password()),
            Err(CasError::InvalidParameters)
        );
    }

    #[test]
    pub fn bcrypt_hash_password() {
        let password = random_password();
        let hash = CASBCrypt::hash_password(password.clone()).unwrap();
        let verification = CASBCrypt::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn bcrypt_hash_password_customized() {
        let password = random_password();
        let hash = CASBCrypt::hash_password_customized(password.clone(), 12).unwrap();
        let verification = CASBCrypt::verify_password(hash, password).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    pub fn bcrypt_accepts_72_byte_password() {
        let password = "x".repeat(BCRYPT_MAX_PASSWORD_BYTES);
        assert_eq!(password.len(), 72);
        let hash = CASBCrypt::hash_password_customized(password.clone(), BCRYPT_MIN_COST).unwrap();
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
        let hash = CASBCrypt::hash_password_customized(password.clone(), BCRYPT_MIN_COST).unwrap();
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
            CASBCrypt::hash_password_customized(password, BCRYPT_MIN_COST),
            Err(CasError::InvalidParameters)
        );
        // The limit is in bytes: 25 three-byte characters is 75 bytes.
        assert_eq!(
            CASBCrypt::hash_password_customized("€".repeat(25), BCRYPT_MIN_COST),
            Err(CasError::InvalidParameters)
        );
    }

    #[test]
    pub fn bcrypt_rejects_73_byte_password_on_verify() {
        let hash = CASBCrypt::hash_password_customized(random_password(), BCRYPT_MIN_COST).unwrap();
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
            CASBCrypt::hash_password_customized(first, BCRYPT_MIN_COST),
            Err(CasError::InvalidParameters)
        );

        // A long password no longer verifies against a hash of its first 72 bytes.
        let prefix_hash = CASBCrypt::hash_password_customized(prefix.clone(), BCRYPT_MIN_COST).unwrap();
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
        let password = random_password();
        let wrong_password = random_password();
        assert_ne!(password, wrong_password);
        let old_hash = bcrypt::hash(&password, 4).unwrap();
        assert!(CASBCrypt::verify_password(old_hash.clone(), password).unwrap());
        assert!(!CASBCrypt::verify_password(old_hash, wrong_password).unwrap());

        // Hashes made elsewhere (Python's bcrypt, from the `bcrypt` crate's tests). Known-answer
        // vectors live in tests/data/, like the other algorithms' test vectors.
        let vectors = std::fs::read_to_string("tests/data/bcrypt/known_answers.txt").unwrap();
        let mut checked = 0;
        for line in vectors.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let (password, hash) = line.split_once(' ').expect("each vector is `<password> <hash>`");
            assert!(
                CASBCrypt::verify_password(hash.to_string(), password.to_string()).unwrap(),
                "known-answer hash {hash} did not verify"
            );
            checked += 1;
        }
        assert!(checked > 0, "no bcrypt known-answer vectors found");
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
        let salt = random_salt(pbkdf2::MIN_SALT_LENGTH);
        let key = pbkdf2::derivation_with_salt(random_password().into_bytes(), pbkdf2::MIN_ITERATIONS, salt).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    pub fn pbkdf2_rejects_iterations_below_minimum() {
        let salt = random_salt(pbkdf2::MIN_SALT_LENGTH);
        for iterations in [0, 1, 4_096, pbkdf2::MIN_ITERATIONS - 1] {
            assert_eq!(
                pbkdf2::derivation_with_salt(random_password().into_bytes(), iterations, salt.clone()),
                Err(CasError::InvalidParameters),
                "derivation_with_salt accepted {iterations} iterations"
            );
            assert!(
                matches!(pbkdf2::derivation(random_password().into_bytes(), iterations), Err(CasError::InvalidParameters)),
                "derivation accepted {iterations} iterations"
            );
        }
    }

    #[test]
    pub fn pbkdf2_rejects_salt_below_minimum() {
        for salt_length in [0, 1, 8, pbkdf2::MIN_SALT_LENGTH - 1] {
            assert_eq!(
                pbkdf2::derivation_with_salt(random_password().into_bytes(), pbkdf2::MIN_ITERATIONS, random_salt(salt_length)),
                Err(CasError::InvalidParameters),
                "derivation_with_salt accepted a {salt_length}-byte salt"
            );
        }
    }

    #[test]
    pub fn pbkdf2_derivation_round_trip_reuses_salt() {
        let password = random_password().into_bytes();
        let rounds = pbkdf2::MIN_ITERATIONS;
        let result = pbkdf2::derivation(password.clone(), rounds).unwrap();

        assert_eq!(result.password.len(), 32);
        assert!(result.salt.len() >= pbkdf2::MIN_SALT_LENGTH);

        let recomputed = pbkdf2::derivation_with_salt(password, rounds, result.salt.clone()).unwrap();
        assert_eq!(recomputed, result.password);
    }
}
