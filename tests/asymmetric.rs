#[cfg(test)]
mod asymmetric {
    use cas_lib::asymmetric::{cas_rsa::CASRSA, types::{CASRSAEncryption, RSAKeyPairResult}};
    use cas_lib::error::CasError;
    use getrandom::SysRng;
    use rsa::pkcs1::{EncodeRsaPublicKey, LineEnding};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::sha2::{Digest, Sha256};
    use rsa::{Pkcs1v15Sign, PrivateKey};
    use std::sync::OnceLock;

    /// One 2048-bit key pair shared by the tests that do not care about the
    /// size, so the suite does not generate a key per test.
    fn key_pair() -> &'static RSAKeyPairResult {
        static KEY_PAIR: OnceLock<RSAKeyPairResult> = OnceLock::new();
        KEY_PAIR.get_or_init(|| CASRSA::generate_rsa_keys(2048).unwrap())
    }

    const DOCUMENT: &[u8] = b"Hello, world!";

    #[test]
    pub fn generate_rsa_keys() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(2048).unwrap();
        assert!(key_pair.private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key_pair.public_key.starts_with("-----BEGIN RSA PUBLIC KEY-----"));
    }

    #[test]
    pub fn rejects_small_key_size() {
        let result = CASRSA::generate_rsa_keys(1024);
        assert!(result.is_err(), "RSA key sizes below 2048 bits should be rejected");
    }

    #[test]
    pub fn rejects_unsupported_key_size() {
        for size in [2047, 2049, 2560, 8192] {
            assert_eq!(CASRSA::generate_rsa_keys(size).err(), Some(CasError::InvalidParameters));
        }
    }

    #[test]
    pub fn signature() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(3072).unwrap();
        let signature = CASRSA::sign(key_pair.private_key, DOCUMENT.to_vec()).unwrap();
        assert_eq!(signature.len(), 3072 / 8, "an RSA signature is the modulus size");
    }

    #[test]
    pub fn verification() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(4096).unwrap();
        let signature = CASRSA::sign(key_pair.private_key.clone(), DOCUMENT.to_vec()).unwrap();
        let verification = CASRSA::verify(key_pair.public_key, DOCUMENT.to_vec(), signature).unwrap();
        assert!(verification, "Signature should be valid");
    }

    #[test]
    pub fn pkcs1v15_signatures_are_deterministic() {
        let key_pair = key_pair();
        let first = CASRSA::sign(key_pair.private_key.clone(), DOCUMENT.to_vec()).unwrap();
        let second = CASRSA::sign(key_pair.private_key.clone(), DOCUMENT.to_vec()).unwrap();
        assert_eq!(first, second, "RSASSA-PKCS1-v1_5 signing is deterministic");
    }

    /// `sign` must produce exactly the standard RS256 signature: the SHA-256
    /// `DigestInfo` of the message under PKCS#1 v1.5 padding. Built here with
    /// the `rsa` crate's prefixed scheme as an independent reference.
    #[test]
    pub fn sign_matches_standard_rs256_encoding() {
        let key_pair = key_pair();
        let private_key: PrivateKey =
            rsa::pkcs8::DecodePrivateKey::from_pkcs8_pem(&key_pair.private_key).unwrap();
        let expected = private_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(DOCUMENT))
            .unwrap();
        let signature = CASRSA::sign(key_pair.private_key.clone(), DOCUMENT.to_vec()).unwrap();
        assert_eq!(signature, expected);
    }

    #[test]
    pub fn pss_round_trip() {
        let key_pair = key_pair();
        let signature = CASRSA::sign_pss(key_pair.private_key.clone(), DOCUMENT.to_vec()).unwrap();
        assert_eq!(signature.len(), 2048 / 8);
        assert!(CASRSA::verify_pss(key_pair.public_key.clone(), DOCUMENT.to_vec(), signature).unwrap());
    }

    #[test]
    pub fn pss_round_trip_all_key_sizes() {
        for size in [3072, 4096] {
            let key_pair = CASRSA::generate_rsa_keys(size).unwrap();
            let signature = CASRSA::sign_pss(key_pair.private_key, DOCUMENT.to_vec()).unwrap();
            assert!(CASRSA::verify_pss(key_pair.public_key, DOCUMENT.to_vec(), signature).unwrap());
        }
    }

    #[test]
    pub fn pss_signatures_are_randomized() {
        let key_pair = key_pair();
        let first = CASRSA::sign_pss(key_pair.private_key.clone(), DOCUMENT.to_vec()).unwrap();
        let second = CASRSA::sign_pss(key_pair.private_key.clone(), DOCUMENT.to_vec()).unwrap();
        assert_ne!(first, second, "PSS uses a fresh random salt per signature");
        for signature in [first, second] {
            assert!(CASRSA::verify_pss(key_pair.public_key.clone(), DOCUMENT.to_vec(), signature).unwrap());
        }
    }

    /// Flips one bit of the message, then one bit of the signature, and checks
    /// both are reported as `Ok(false)` rather than as an error.
    fn assert_rejects_tampering(
        sign: fn(String, Vec<u8>) -> cas_lib::error::CasResult<Vec<u8>>,
        verify: fn(String, Vec<u8>, Vec<u8>) -> cas_lib::error::CasResult<bool>,
    ) {
        let key_pair = key_pair();
        let signature = sign(key_pair.private_key.clone(), DOCUMENT.to_vec()).unwrap();

        let mut tampered_message = DOCUMENT.to_vec();
        tampered_message[0] ^= 0x01;
        assert_eq!(verify(key_pair.public_key.clone(), tampered_message, signature.clone()), Ok(false));

        for index in [0, signature.len() / 2, signature.len() - 1] {
            let mut tampered_signature = signature.clone();
            tampered_signature[index] ^= 0x01;
            assert_eq!(
                verify(key_pair.public_key.clone(), DOCUMENT.to_vec(), tampered_signature),
                Ok(false)
            );
        }

        // Wrong-length and empty signatures are invalid signatures, not errors.
        assert_eq!(verify(key_pair.public_key.clone(), DOCUMENT.to_vec(), signature[1..].to_vec()), Ok(false));
        assert_eq!(verify(key_pair.public_key.clone(), DOCUMENT.to_vec(), Vec::new()), Ok(false));

        // A different key pair's public key does not verify it either.
        let other = CASRSA::generate_rsa_keys(2048).unwrap();
        assert_eq!(verify(other.public_key, DOCUMENT.to_vec(), signature), Ok(false));
    }

    #[test]
    pub fn pkcs1v15_rejects_tampering() {
        assert_rejects_tampering(CASRSA::sign, CASRSA::verify);
    }

    #[test]
    pub fn pss_rejects_tampering() {
        assert_rejects_tampering(CASRSA::sign_pss, CASRSA::verify_pss);
    }

    #[test]
    pub fn schemes_do_not_cross_verify() {
        let key_pair = key_pair();
        let pkcs1v15 = CASRSA::sign(key_pair.private_key.clone(), DOCUMENT.to_vec()).unwrap();
        let pss = CASRSA::sign_pss(key_pair.private_key.clone(), DOCUMENT.to_vec()).unwrap();
        assert_eq!(CASRSA::verify_pss(key_pair.public_key.clone(), DOCUMENT.to_vec(), pkcs1v15), Ok(false));
        assert_eq!(CASRSA::verify(key_pair.public_key.clone(), DOCUMENT.to_vec(), pss), Ok(false));
    }

    /// The message is hashed inside the library, so it can be longer than the
    /// modulus. In 0.4 and earlier, inputs over `k - 11` bytes (245 for 2048-bit keys)
    /// failed.
    #[test]
    pub fn long_messages_are_signed() {
        let key_pair = key_pair();
        let empty: Vec<u8> = Vec::new();
        let long: Vec<u8> = (0..1024 * 1024).map(|i| i as u8).collect();
        for message in [empty, vec![0xAB; 246], long] {
            let signature = CASRSA::sign(key_pair.private_key.clone(), message.clone()).unwrap();
            assert!(CASRSA::verify(key_pair.public_key.clone(), message.clone(), signature).unwrap());
            let signature = CASRSA::sign_pss(key_pair.private_key.clone(), message.clone()).unwrap();
            assert!(CASRSA::verify_pss(key_pair.public_key.clone(), message, signature).unwrap());
        }
    }

    /// Breaking change after 0.4: `sign`/`verify` used to apply PKCS#1 v1.5
    /// padding to the caller's bytes with no `DigestInfo` prefix. Such a
    /// signature must no longer verify, whether the caller passed the
    /// message or a digest of it.
    #[test]
    pub fn legacy_unprefixed_signatures_no_longer_verify() {
        let key_pair = key_pair();
        let private_key: PrivateKey =
            rsa::pkcs8::DecodePrivateKey::from_pkcs8_pem(&key_pair.private_key).unwrap();
        for signed_bytes in [DOCUMENT.to_vec(), Sha256::digest(DOCUMENT).to_vec()] {
            let legacy = private_key.sign(Pkcs1v15Sign::new_unprefixed(), &signed_bytes).unwrap();
            assert_eq!(CASRSA::verify(key_pair.public_key.clone(), DOCUMENT.to_vec(), legacy.clone()), Ok(false));
            assert_eq!(CASRSA::verify(key_pair.public_key.clone(), signed_bytes, legacy), Ok(false));
        }
    }

    #[test]
    pub fn invalid_pem_is_rejected() {
        let key_pair = key_pair();
        let garbage = "not a PEM key".to_string();
        assert_eq!(CASRSA::sign(garbage.clone(), DOCUMENT.to_vec()), Err(CasError::InvalidPemKey));
        assert_eq!(CASRSA::sign_pss(garbage.clone(), DOCUMENT.to_vec()), Err(CasError::InvalidPemKey));
        assert_eq!(CASRSA::verify(garbage.clone(), DOCUMENT.to_vec(), vec![0; 256]), Err(CasError::InvalidPemKey));
        assert_eq!(CASRSA::verify_pss(garbage, DOCUMENT.to_vec(), vec![0; 256]), Err(CasError::InvalidPemKey));
        // The keys are not interchangeable: a public key is not a private key
        // and vice versa.
        assert_eq!(
            CASRSA::sign(key_pair.public_key.clone(), DOCUMENT.to_vec()),
            Err(CasError::InvalidPemKey)
        );
        assert_eq!(
            CASRSA::verify(key_pair.private_key.clone(), DOCUMENT.to_vec(), vec![0; 256]),
            Err(CasError::InvalidPemKey)
        );
    }

    /// Builds a 1024-bit key pair outside the library (whose key generation
    /// refuses that size), as a key imported from elsewhere would be.
    fn small_key_pair_pem() -> (PrivateKey, String, String) {
        let private_key = PrivateKey::new(&mut SysRng, 1024).unwrap();
        let private_pem = private_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let public_pem = private_key.to_public_key().to_pkcs1_pem(LineEnding::LF).unwrap();
        (private_key, private_pem, public_pem)
    }

    #[test]
    pub fn sign_rejects_small_private_key() {
        let (_, private_pem, _) = small_key_pair_pem();
        for result in [
            CASRSA::sign(private_pem.clone(), DOCUMENT.to_vec()),
            CASRSA::sign_pss(private_pem, DOCUMENT.to_vec()),
        ] {
            assert_eq!(
                result,
                Err(CasError::InvalidParameters),
                "signing with a private key below 2048 bits should be rejected"
            );
        }
    }

    #[test]
    pub fn verify_rejects_small_public_key() {
        let (private_key, _, public_pem) = small_key_pair_pem();
        // Signatures that are valid for the 1024-bit key, so the only reason
        // to refuse them is the key size.
        let pkcs1v15 = private_key.pkcs1v15_sign::<Sha256>(DOCUMENT).unwrap();
        let pss = private_key.pss_sign::<Sha256>(DOCUMENT).unwrap();
        for result in [
            CASRSA::verify(public_pem.clone(), DOCUMENT.to_vec(), pkcs1v15),
            CASRSA::verify_pss(public_pem, DOCUMENT.to_vec(), pss),
        ] {
            assert_eq!(
                result,
                Err(CasError::InvalidParameters),
                "verifying with a public key below 2048 bits should be rejected"
            );
        }
    }
}

/// NIST CAVS FIPS 186-4 known-answer tests for RSASSA-PKCS#1 v1.5 signatures.
///
/// `CASRSA::sign` / `verify` are RSASSA-PKCS1-v1_5 with SHA-256 over the
/// message (RS256). These vectors come from the CAVS "SigGen RSA (PKCS#1 Ver
/// 1.5)" file `SigGen15_186-3.txt`, which lists `n, e, d, Msg, S` per case for
/// SHA-224/256/384/512. The message is passed to the library as is:
///
/// - **SHA-256 cases** must verify, and signing `Msg` with the key rebuilt from
///   `(n, e, d)` must reproduce `S` byte for byte (PKCS#1 v1.5 is
///   deterministic). The primes are recovered from `(n, e, d)`.
/// - **Other hashes** must not verify: their `DigestInfo` names a different
///   hash, so accepting them would mean the hash is not bound.
#[cfg(test)]
mod rsa_pkcs1v15_kat {
    use cas_lib::asymmetric::{cas_rsa::CASRSA, types::CASRSAEncryption};
    use rsa::pkcs1::{EncodeRsaPublicKey, LineEnding};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::{BoxedUint, PrivateKey, PublicKey};
    use std::fs;

    const VECTOR_FILE: &str = "tests/data/rsa/SigGen15_186-3.txt";

    fn decode_hex(hex: &str) -> Vec<u8> {
        let hex = hex.trim();
        assert_eq!(hex.len() % 2, 0, "hex input must have an even length");
        hex.as_bytes()
            .chunks(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
            .collect()
    }

    /// Parses a big-endian hex integer, dropping the leading zero bytes the
    /// CAVS file pads `e` with so its precision matches its value.
    fn uint(hex: &str) -> BoxedUint {
        let bytes = decode_hex(hex);
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        BoxedUint::from_be_slice_vartime(&bytes[start..])
    }

    struct Key {
        public_pem: String,
        private_pem: String,
    }

    struct Vector {
        key: std::rc::Rc<Key>,
        sha_alg: String,
        msg: Vec<u8>,
        signature: Vec<u8>,
    }

    fn build_key(n: BoxedUint, e: BoxedUint, d: BoxedUint) -> Key {
        let public_pem = PublicKey::new(n.clone(), e.clone())
            .expect("valid RSA public key components")
            .to_pkcs1_pem(LineEnding::LF)
            .expect("encode public key to PKCS#1 PEM");
        // No primes given: `from_components` recovers p and q from (n, e, d).
        let private_pem = PrivateKey::from_components(n, e, d, Vec::new())
            .expect("valid RSA private key components")
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode private key to PKCS#8 PEM")
            .to_string();
        Key { public_pem, private_pem }
    }

    fn parse_vectors(path: &str) -> Vec<Vector> {
        let contents = fs::read_to_string(path).unwrap_or_else(|err| {
            panic!("could not read {path}: {err}. Save the CAVS file `SigGen15_186-3.txt` there.")
        });

        let mut vectors = Vec::new();
        let mut n: Option<BoxedUint> = None;
        let mut e: Option<BoxedUint> = None;
        let mut key: Option<std::rc::Rc<Key>> = None;
        let mut sha_alg: Option<String> = None;
        let mut msg: Option<Vec<u8>> = None;

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }

            if let Some(value) = line.strip_prefix("n = ") {
                n = Some(uint(value));
                key = None;
            } else if let Some(value) = line.strip_prefix("e = ") {
                e = Some(uint(value));
            } else if let Some(value) = line.strip_prefix("d = ") {
                // The key is fully determined by (n, e, d); build it once and
                // share it with every Msg/S case under this header.
                key = Some(std::rc::Rc::new(build_key(
                    n.clone().expect("n before d"),
                    e.clone().expect("e before d"),
                    uint(value),
                )));
            } else if let Some(value) = line.strip_prefix("SHAAlg = ") {
                sha_alg = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("Msg = ") {
                msg = Some(decode_hex(value));
            } else if let Some(value) = line.strip_prefix("S = ") {
                vectors.push(Vector {
                    key: key.clone().expect("key header before S"),
                    sha_alg: sha_alg.clone().expect("SHAAlg before S"),
                    msg: msg.take().expect("Msg before S"),
                    signature: decode_hex(value),
                });
            }
        }

        vectors
    }

    fn sha256_vectors() -> Vec<Vector> {
        let vectors: Vec<Vector> =
            parse_vectors(VECTOR_FILE).into_iter().filter(|v| v.sha_alg == "SHA256").collect();
        assert_eq!(vectors.len(), 20, "expected 10 SHA-256 cases per modulus size");
        vectors
    }

    #[test]
    fn siggen15_sha256_verify_vectors() {
        for (i, vector) in sha256_vectors().iter().enumerate() {
            let verified = CASRSA::verify(
                vector.key.public_pem.clone(),
                vector.msg.clone(),
                vector.signature.clone(),
            )
            .unwrap_or_else(|err| panic!("verify errored for SHA-256 vector {i}: {err:?}"));
            assert!(verified, "SHA-256 vector {i} should verify against the NIST signature");
        }
    }

    #[test]
    fn siggen15_sha256_sign_vectors() {
        for (i, vector) in sha256_vectors().iter().enumerate() {
            let signature = CASRSA::sign(vector.key.private_pem.clone(), vector.msg.clone())
                .unwrap_or_else(|err| panic!("sign errored for SHA-256 vector {i}: {err:?}"));
            assert_eq!(signature, vector.signature, "SHA-256 vector {i} signature mismatch");
        }
    }

    #[test]
    fn siggen15_other_hashes_do_not_verify() {
        let vectors = parse_vectors(VECTOR_FILE);
        let others: Vec<&Vector> = vectors.iter().filter(|v| v.sha_alg != "SHA256").collect();
        assert_eq!(others.len(), 60, "expected the SHA-224/384/512 cases");
        for (i, vector) in others.iter().enumerate() {
            let verified = CASRSA::verify(
                vector.key.public_pem.clone(),
                vector.msg.clone(),
                vector.signature.clone(),
            )
            .unwrap();
            assert!(!verified, "{} vector {i} must not verify as RS256", vector.sha_alg);
        }
    }

    #[test]
    fn siggen15_rejects_tampered_message_and_signature() {
        let vectors = sha256_vectors();
        let vector = vectors.first().expect("at least one vector");

        let mut tampered = vector.signature.clone();
        tampered[0] ^= 0x01;
        let verified =
            CASRSA::verify(vector.key.public_pem.clone(), vector.msg.clone(), tampered).unwrap();
        assert!(!verified, "a tampered signature must not verify");

        let mut tampered = vector.msg.clone();
        tampered[0] ^= 0x01;
        let verified =
            CASRSA::verify(vector.key.public_pem.clone(), tampered, vector.signature.clone()).unwrap();
        assert!(!verified, "a tampered message must not verify");
    }
}
