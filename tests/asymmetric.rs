#[cfg(test)]
mod asymmetric {
    use cas_lib::asymmetric::{cas_rsa::CASRSA, types::{CASRSAEncryption, RSAKeyPairResult}};

    #[test]
    pub fn generate_rsa_keys() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(2048).unwrap();
        assert!(!key_pair.private_key.is_empty());
        assert!(!key_pair.public_key.is_empty());
    }

    #[test]
    pub fn rejects_small_key_size() {
        let result = CASRSA::generate_rsa_keys(1024);
        assert!(result.is_err(), "RSA key sizes below 2048 bits should be rejected");
    }

    #[test]
    pub fn signature() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(3072).unwrap();
        let document = b"Hello, world!".to_vec();
        let signature = CASRSA::sign(key_pair.private_key, document.clone()).unwrap();
        assert!(document != signature, "Signature should not be the same as the document");
    }

    #[test]
    pub fn verification() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(4096).unwrap();
        let document = b"Hello, world!".to_vec();
        let signature = CASRSA::sign(key_pair.private_key.clone(), document.clone()).unwrap();
        let verification = CASRSA::verify(key_pair.public_key, document, signature).unwrap();
        assert!(verification, "Signature should be valid");
    }
}

/// NIST CAVS FIPS 186-4 known-answer tests for RSASSA-PKCS#1 v1.5 signatures.
///
/// `CASRSA` signs/verifies with `Pkcs1v15Sign::new_unprefixed()`, i.e. the
/// RSASSA-PKCS#1 v1.5 scheme where the caller supplies the fully-encoded
/// `DigestInfo` (ASN.1 prefix || message digest). These vectors come from the
/// CAVS "SigGen RSA (PKCS#1 Ver 1.5)" file `SigGen15_186-3.txt`, which lists
/// `n, e, d, Msg, S` per case. The file does not include the primes `p, q`, so
/// a private-key PEM cannot be reconstructed; we therefore drive the `verify`
/// path (same scheme/padding as `sign`) using a public key built from `(n, e)`.
#[cfg(test)]
mod rsa_pkcs1v15_kat {
    use cas_lib::asymmetric::{cas_rsa::CASRSA, types::CASRSAEncryption};
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::{BigUint, RsaPublicKey};
    use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
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

    /// Builds the EMSA-PKCS1-v1_5 `DigestInfo` (DER prefix || digest) that the
    /// library expects as its unprefixed input, for the given CAVS `SHAAlg`.
    fn digest_info(sha_alg: &str, msg: &[u8]) -> Vec<u8> {
        let (prefix_hex, digest): (&str, Vec<u8>) = match sha_alg {
            "SHA224" => (
                "302d300d06096086480165030402040500041c",
                Sha224::digest(msg).to_vec(),
            ),
            "SHA256" => (
                "3031300d060960864801650304020105000420",
                Sha256::digest(msg).to_vec(),
            ),
            "SHA384" => (
                "3041300d060960864801650304020205000430",
                Sha384::digest(msg).to_vec(),
            ),
            "SHA512" => (
                "3051300d060960864801650304020305000440",
                Sha512::digest(msg).to_vec(),
            ),
            other => panic!("unsupported SHAAlg in vector file: {other}"),
        };
        let mut encoded = decode_hex(prefix_hex);
        encoded.extend_from_slice(&digest);
        encoded
    }

    struct Vector {
        public_pem: String,
        sha_alg: String,
        msg: Vec<u8>,
        signature: Vec<u8>,
    }

    fn public_pem(n: &BigUint, e: &BigUint) -> String {
        RsaPublicKey::new(n.clone(), e.clone())
            .expect("valid RSA public key components")
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("encode public key to PKCS#1 PEM")
    }

    fn parse_vectors(path: &str) -> Vec<Vector> {
        let contents = fs::read_to_string(path).unwrap_or_else(|err| {
            panic!(
                "could not read {path}: {err}. Save the CAVS file `SigGen15_186-3.txt` there."
            )
        });

        let mut vectors = Vec::new();
        let mut n: Option<BigUint> = None;
        let mut e: Option<BigUint> = None;
        let mut current_pem: Option<String> = None;
        let mut sha_alg: Option<String> = None;
        let mut msg: Option<Vec<u8>> = None;

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }

            if let Some(value) = line.strip_prefix("n = ") {
                n = Some(BigUint::from_bytes_be(&decode_hex(value)));
                current_pem = None;
            } else if let Some(value) = line.strip_prefix("e = ") {
                let e_val = BigUint::from_bytes_be(&decode_hex(value));
                // The public key is fully determined by (n, e); build it now so
                // every following Msg/S case under this header reuses it.
                current_pem = Some(public_pem(n.as_ref().expect("n before e"), &e_val));
                e = Some(e_val);
            } else if line.strip_prefix("d = ").is_some() {
                // d is present in the file but not needed for the verify path.
            } else if let Some(value) = line.strip_prefix("SHAAlg = ") {
                sha_alg = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("Msg = ") {
                msg = Some(decode_hex(value));
            } else if let Some(value) = line.strip_prefix("S = ") {
                vectors.push(Vector {
                    public_pem: current_pem.clone().expect("key header before S"),
                    sha_alg: sha_alg.clone().expect("SHAAlg before S"),
                    msg: msg.take().expect("Msg before S"),
                    signature: decode_hex(value),
                });
            }
        }

        let _ = e; // silence unused warning; retained for clarity of the parse state.
        vectors
    }

    #[test]
    fn siggen15_186_3_verify_vectors() {
        let vectors = parse_vectors(VECTOR_FILE);
        assert!(!vectors.is_empty(), "no vectors parsed from {VECTOR_FILE}");

        for (i, vector) in vectors.iter().enumerate() {
            let encoded = digest_info(&vector.sha_alg, &vector.msg);
            let verified = CASRSA::verify(
                vector.public_pem.clone(),
                encoded,
                vector.signature.clone(),
            )
            .unwrap_or_else(|err| panic!("verify errored for vector {i}: {err:?}"));
            assert!(
                verified,
                "vector {i} ({}) should verify against the NIST signature",
                vector.sha_alg
            );
        }
    }

    #[test]
    fn siggen15_186_3_rejects_tampered_signature() {
        let vectors = parse_vectors(VECTOR_FILE);
        let vector = vectors.first().expect("at least one vector");

        let mut tampered = vector.signature.clone();
        tampered[0] ^= 0x01;

        let encoded = digest_info(&vector.sha_alg, &vector.msg);
        let verified = CASRSA::verify(vector.public_pem.clone(), encoded, tampered).unwrap();
        assert!(!verified, "a tampered signature must not verify");
    }
}
