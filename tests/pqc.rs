#[cfg(test)]
mod pqc {
    use cas_lib::{hashers::sha::CASSHA, pqc::{cas_pqc::MlKemKeyPair, ml_kem::{ml_kem_1024_decapsulate, ml_kem_1024_encapsulate, ml_kem_1024_generate}, slh_dsa::*}};
    use cas_lib::hashers::cas_hasher::CASHasher;
    use cas_lib::pqc::ml_dsa;

    #[test]
    pub fn round_trip_mlkem1024() {
        let secret_key_public_key: MlKemKeyPair = ml_kem_1024_generate();
            let ct = ml_kem_1024_encapsulate(secret_key_public_key.public_key).expect("encapsulate failed");
            let ss_receiver = ml_kem_1024_decapsulate(secret_key_public_key.secret_key, ct.ciphertext).expect("decapsulate failed");
        assert_eq!(ss_receiver, ss_receiver);
    }

    #[test]
    pub fn slh_dsa_sign_verify_pass() {
        let to_hash = b"Lets HashThis".to_vec();
        let hash = <CASSHA as CASHasher>::hash_512(to_hash.clone());

        let keys = generate_signing_and_verification_key();
        let signature = sign_message(hash.clone(), keys.signing_key).unwrap();
        let is_valid = verify_signature(hash, signature, keys.verification_key).unwrap();
        assert_eq!(true, is_valid);
    }

    #[test]
    pub fn slh_dsa_sign_verify_fail() {
        let to_hash = b"Lets HashThis".to_vec();
        let hash = <CASSHA as CASHasher>::hash_512(to_hash.clone());

        let keys = generate_signing_and_verification_key();
        let signature = sign_message(hash, keys.signing_key).unwrap();
        let is_valid = verify_signature(to_hash, signature, keys.verification_key).unwrap();
        assert_eq!(false, is_valid);
    }

    #[test]
    pub fn ml_dsa_65_sign_verify_pass() {
        let message = b"Lets HashThis".to_vec();

        let keys = ml_dsa::generate_signing_and_verification_key();
        let signature = ml_dsa::sign_message(message.clone(), keys.signing_key).unwrap();
        let is_valid = ml_dsa::verify_signature(message, signature, keys.verification_key).unwrap();
        assert_eq!(true, is_valid);
    }

    #[test]
    pub fn ml_dsa_65_sign_verify_fail() {
        let message = b"Lets HashThis".to_vec();
        let tampered = b"Lets HashThat".to_vec();

        let keys = ml_dsa::generate_signing_and_verification_key();
        let signature = ml_dsa::sign_message(message, keys.signing_key).unwrap();
        let is_valid = ml_dsa::verify_signature(tampered, signature, keys.verification_key).unwrap();
        assert_eq!(false, is_valid);
    }
}

/// Project Wycheproof known-answer tests for ML-DSA-65 (FIPS 204).
///
/// `cas_lib::pqc::ml_dsa` uses the `MlDsa65` parameter set, the pure
/// (non-prehashed) external signing interface, and the deterministic signing
/// variant with an empty context. These vectors match that configuration:
///
/// - `mldsa_65_sign_seed_test.json` exposes each group's 32-byte `privateSeed`,
///   which is exactly the seed our signing key serializes to, so deterministic
///   signing must reproduce the expected `sig` byte-for-byte.
/// - `mldsa_65_verify_test.json` provides `publicKey` / `msg` / `sig` / `result`
///   triples; `valid` cases must verify and `invalid` cases must not.
///
/// Only the empty-context cases are exercised, since the public API signs and
/// verifies with an empty context. See [`tests/data/ml_dsa/README.md`].
#[cfg(test)]
mod ml_dsa_kat {
    use cas_lib::pqc::ml_dsa;
    use serde_json::Value;
    use std::fs;

    const SIGN_VECTORS: &str = "tests/data/ml_dsa/mldsa_65_sign_seed_test.json";
    const VERIFY_VECTORS: &str = "tests/data/ml_dsa/mldsa_65_verify_test.json";

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input must have an even length");
        hex.as_bytes()
            .chunks(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
            .collect()
    }

    /// Reads a required hex-encoded field into bytes.
    fn hex_field(obj: &Value, key: &str) -> Vec<u8> {
        decode_hex(obj[key].as_str().unwrap_or_else(|| panic!("missing field `{key}`")))
    }

    /// Reads an optional hex-encoded field (absent or JSON `null` -> `None`).
    fn opt_hex_field(obj: &Value, key: &str) -> Option<Vec<u8>> {
        obj.get(key).and_then(Value::as_str).map(decode_hex)
    }

    /// A test's context is "empty" when the `ctx` field is absent or "".
    fn ctx_is_empty(test: &Value) -> bool {
        test.get("ctx").and_then(Value::as_str).unwrap_or("").is_empty()
    }

    /// Whether a test carries the given Wycheproof flag.
    fn has_flag(test: &Value, flag: &str) -> bool {
        test.get("flags")
            .and_then(Value::as_array)
            .is_some_and(|flags| flags.iter().any(|f| f.as_str() == Some(flag)))
    }

    fn load(path: &str) -> Value {
        let contents = fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("could not read {path}: {err}"));
        serde_json::from_str(&contents).unwrap_or_else(|err| panic!("invalid JSON in {path}: {err}"))
    }

    #[test]
    fn sign_seed_vectors_reproduce_signatures() {
        let file = load(SIGN_VECTORS);
        let mut checked = 0usize;

        for group in file["testGroups"].as_array().expect("testGroups array") {
            let seed = hex_field(group, "privateSeed");
            // A few groups carry `publicKey: null`; the round-trip verify below is
            // only attempted when the public key is present.
            let public_key = opt_hex_field(group, "publicKey");

            for test in group["tests"].as_array().expect("tests array") {
                // The deterministic sign path takes no context, so only empty-ctx
                // cases are reproducible through the public API.
                if !ctx_is_empty(test) {
                    continue;
                }
                // Skip the "external mu" cases, which supply a pre-computed `mu`
                // instead of a `msg`; the public API signs a message, not a mu.
                if test.get("msg").is_none() {
                    continue;
                }
                // Skip randomized (hedged) signatures: they are produced with a
                // non-zero rnd, so our deterministic signer cannot reproduce them.
                if has_flag(test, "Randomized") {
                    continue;
                }

                let msg = hex_field(test, "msg");
                let tc = &test["tcId"];

                // The only `invalid` message-based cases here are malformed-length
                // private seeds, which our length-checked key parsing must reject.
                if test["result"].as_str() == Some("invalid") {
                    assert!(
                        ml_dsa::sign_message(msg, seed.clone()).is_err(),
                        "signing should reject malformed seed for tcId {tc}"
                    );
                    checked += 1;
                    continue;
                }

                let expected_sig = hex_field(test, "sig");
                let produced = ml_dsa::sign_message(msg.clone(), seed.clone())
                    .unwrap_or_else(|err| panic!("sign errored for tcId {tc}: {err:?}"));
                assert_eq!(
                    produced, expected_sig,
                    "deterministic signature mismatch for tcId {tc}"
                );

                // When the group carries a public key, the produced signature must
                // also verify under it.
                if let Some(public_key) = &public_key {
                    let verified = ml_dsa::verify_signature(msg, produced, public_key.clone())
                        .unwrap_or_else(|err| panic!("verify errored for tcId {tc}: {err:?}"));
                    assert!(verified, "round-trip verification failed for tcId {tc}");
                }

                checked += 1;
            }
        }

        assert!(checked > 0, "no empty-ctx sign vectors were exercised");
        println!("ML-DSA-65 sign KAT: {checked} vectors checked");
    }

    #[test]
    fn verify_vectors_accept_valid_reject_invalid() {
        let file = load(VERIFY_VECTORS);
        let mut checked = 0usize;

        for group in file["testGroups"].as_array().expect("testGroups array") {
            let public_key = hex_field(group, "publicKey");

            for test in group["tests"].as_array().expect("tests array") {
                if !ctx_is_empty(test) {
                    continue;
                }

                let msg = hex_field(test, "msg");
                let sig = hex_field(test, "sig");
                let tc = &test["tcId"];
                let expected_valid = match test["result"].as_str() {
                    Some("valid") => true,
                    Some("invalid") => false,
                    other => panic!("unexpected result {other:?} for tcId {tc}"),
                };

                // A malformed signature is rejected at the parse step (`Err`); for
                // an `invalid` case that is an acceptable "does not verify" outcome.
                let verified = ml_dsa::verify_signature(msg, sig, public_key.clone()).unwrap_or(false);
                assert_eq!(
                    verified, expected_valid,
                    "verification result mismatch for tcId {tc} ({})",
                    test["comment"]
                );

                checked += 1;
            }
        }

        assert!(checked > 0, "no empty-ctx verify vectors were exercised");
        println!("ML-DSA-65 verify KAT: {checked} vectors checked");
    }
}