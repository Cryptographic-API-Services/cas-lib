mod common;

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
/// verifies with an empty context. The files are downloaded on first use; see
/// `tests/data/wycheproof/README.md`.
#[cfg(test)]
mod ml_dsa_kat {
    use cas_lib::pqc::ml_dsa;
    use serde_json::Value;
    use crate::common::wycheproof::load;

    const SIGN_VECTORS: &str = "mldsa_65_sign_seed_test.json";
    const VERIFY_VECTORS: &str = "mldsa_65_verify_test.json";

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

/// API-contract tests for `cas_lib::pqc::ml_dsa` (ML-DSA-65, FIPS 204): encoded
/// sizes, deterministic signing, tamper detection, and the `CasError` mapping
/// for malformed inputs that FFI consumers rely on.
#[cfg(test)]
mod ml_dsa_api {
    use cas_lib::error::CasError;
    use cas_lib::pqc::ml_dsa;

    /// FIPS 204 ML-DSA-65 encodings (signing key is serialized as its seed).
    const SEED_LEN: usize = 32;
    const VERIFICATION_KEY_LEN: usize = 1952;
    const SIGNATURE_LEN: usize = 3309;

    #[test]
    fn key_and_signature_sizes_match_fips_204() {
        let keys = ml_dsa::generate_signing_and_verification_key();
        assert_eq!(keys.signing_key.len(), SEED_LEN);
        assert_eq!(keys.verification_key.len(), VERIFICATION_KEY_LEN);

        let signature = ml_dsa::sign_message(b"size check".to_vec(), keys.signing_key).unwrap();
        assert_eq!(signature.len(), SIGNATURE_LEN);
    }

    #[test]
    fn key_generation_produces_distinct_keys() {
        let a = ml_dsa::generate_signing_and_verification_key();
        let b = ml_dsa::generate_signing_and_verification_key();
        assert_ne!(a.signing_key, b.signing_key);
        assert_ne!(a.verification_key, b.verification_key);
    }

    #[test]
    fn signing_is_deterministic() {
        let keys = ml_dsa::generate_signing_and_verification_key();
        let message = b"deterministic".to_vec();
        let first = ml_dsa::sign_message(message.clone(), keys.signing_key.clone()).unwrap();
        let second = ml_dsa::sign_message(message, keys.signing_key).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn different_messages_produce_different_signatures() {
        let keys = ml_dsa::generate_signing_and_verification_key();
        let a = ml_dsa::sign_message(b"message a".to_vec(), keys.signing_key.clone()).unwrap();
        let b = ml_dsa::sign_message(b"message b".to_vec(), keys.signing_key).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_message_round_trips() {
        let keys = ml_dsa::generate_signing_and_verification_key();
        let signature = ml_dsa::sign_message(Vec::new(), keys.signing_key).unwrap();
        assert!(ml_dsa::verify_signature(Vec::new(), signature, keys.verification_key).unwrap());
    }

    #[test]
    fn large_message_round_trips() {
        let keys = ml_dsa::generate_signing_and_verification_key();
        let message: Vec<u8> = (0..1_000_000u32).map(|i| i as u8).collect();
        let signature = ml_dsa::sign_message(message.clone(), keys.signing_key).unwrap();
        assert!(ml_dsa::verify_signature(message, signature, keys.verification_key).unwrap());
    }

    #[test]
    fn signature_does_not_verify_under_another_key() {
        let signer = ml_dsa::generate_signing_and_verification_key();
        let other = ml_dsa::generate_signing_and_verification_key();
        let message = b"wrong key".to_vec();
        let signature = ml_dsa::sign_message(message.clone(), signer.signing_key).unwrap();
        assert!(!ml_dsa::verify_signature(message, signature, other.verification_key).unwrap());
    }

    #[test]
    fn single_bit_flip_in_message_is_rejected() {
        let keys = ml_dsa::generate_signing_and_verification_key();
        let message = b"flip a bit in me".to_vec();
        let signature = ml_dsa::sign_message(message.clone(), keys.signing_key).unwrap();

        for byte in [0, message.len() / 2, message.len() - 1] {
            let mut tampered = message.clone();
            tampered[byte] ^= 0x01;
            assert!(
                !ml_dsa::verify_signature(tampered, signature.clone(), keys.verification_key.clone()).unwrap(),
                "tampered message byte {byte} still verified"
            );
        }
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let keys = ml_dsa::generate_signing_and_verification_key();
        let message = b"tamper with the signature".to_vec();
        let signature = ml_dsa::sign_message(message.clone(), keys.signing_key).unwrap();

        // Cover the challenge (c~), the response z, and the trailing hint bytes.
        for byte in [0, 100, SIGNATURE_LEN / 2, SIGNATURE_LEN - 1] {
            let mut tampered = signature.clone();
            tampered[byte] ^= 0x01;
            // A malformed hint encoding is rejected at parse time (`Err`); either
            // way the signature must not verify.
            let verified = ml_dsa::verify_signature(message.clone(), tampered, keys.verification_key.clone())
                .unwrap_or(false);
            assert!(!verified, "tampered signature byte {byte} still verified");
        }
    }

    #[test]
    fn tampered_verification_key_is_rejected() {
        let keys = ml_dsa::generate_signing_and_verification_key();
        let message = b"tamper with the key".to_vec();
        let signature = ml_dsa::sign_message(message.clone(), keys.signing_key).unwrap();

        let mut tampered_vk = keys.verification_key.clone();
        tampered_vk[VERIFICATION_KEY_LEN / 2] ^= 0x01;
        let verified = ml_dsa::verify_signature(message, signature, tampered_vk).unwrap_or(false);
        assert!(!verified);
    }

    #[test]
    fn all_zero_signature_is_rejected() {
        let keys = ml_dsa::generate_signing_and_verification_key();
        let verified = ml_dsa::verify_signature(b"zeros".to_vec(), vec![0u8; SIGNATURE_LEN], keys.verification_key)
            .unwrap_or(false);
        assert!(!verified);
    }

    #[test]
    fn sign_rejects_malformed_signing_key() {
        for len in [0, 1, SEED_LEN - 1, SEED_LEN + 1, VERIFICATION_KEY_LEN] {
            assert_eq!(
                ml_dsa::sign_message(b"msg".to_vec(), vec![0u8; len]),
                Err(CasError::InvalidKey),
                "signing key of length {len} was accepted"
            );
        }
    }

    #[test]
    fn verify_rejects_malformed_verification_key() {
        let keys = ml_dsa::generate_signing_and_verification_key();
        let signature = ml_dsa::sign_message(b"msg".to_vec(), keys.signing_key.clone()).unwrap();

        for bad_vk in [Vec::new(), vec![0u8; VERIFICATION_KEY_LEN - 1], vec![0u8; VERIFICATION_KEY_LEN + 1], keys.signing_key] {
            assert_eq!(
                ml_dsa::verify_signature(b"msg".to_vec(), signature.clone(), bad_vk.clone()),
                Err(CasError::InvalidKey),
                "verification key of length {} was accepted",
                bad_vk.len()
            );
        }
    }

    #[test]
    fn verify_rejects_malformed_signature_length() {
        let keys = ml_dsa::generate_signing_and_verification_key();
        let message = b"msg".to_vec();
        let signature = ml_dsa::sign_message(message.clone(), keys.signing_key).unwrap();

        let truncated = signature[..SIGNATURE_LEN - 1].to_vec();
        let mut extended = signature.clone();
        extended.push(0);

        for bad_sig in [Vec::new(), truncated, extended] {
            assert_eq!(
                ml_dsa::verify_signature(message.clone(), bad_sig.clone(), keys.verification_key.clone()),
                Err(CasError::InvalidSignature),
                "signature of length {} was accepted",
                bad_sig.len()
            );
        }
    }
}

/// Known-answer tests for SLH-DSA-SHAKE-128f key generation (FIPS 205).
///
/// `cas_lib::pqc::slh_dsa::generate_signing_and_verification_key` draws
/// `SK.seed`, `SK.prf` and `PK.seed` from the OS RNG and builds the key with
/// slh-dsa's `SigningKey::slh_keygen_internal`. Wycheproof has no SLH-DSA
/// vectors, so these are the SLH-DSA-SHAKE-128f cases (tgId 4, tcId 31-40) of
/// NIST ACVP `SLH-DSA-keyGen-FIPS205/internalProjection.json`
/// (usnistgov/ACVP-Server@975de31eb83d87039ec88934fdc47d8c312b892d).
/// Each vector's `sk` is `skSeed || skPrf || pk`, so only `pk` is listed.
#[cfg(test)]
mod slh_dsa_kat {
    use cas_lib::pqc::slh_dsa::{generate_signing_and_verification_key, sign_message, verify_signature};
    use slh_dsa::{signature::Keypair, Shake128f, SigningKey};

    /// `(skSeed, skPrf, pkSeed, pk)`.
    const KEYGEN_VECTORS: &[(&str, &str, &str, &str)] = &[
        // tcId 31
        ("3956AB391B4D22FC907AF0740326D061", "AB0EB206436F2B86EBE086D77739B3E4", "56505C229F4E7FA6B201714C7DCC9DA3",
         "56505C229F4E7FA6B201714C7DCC9DA366578F1F24C3FE371C97C14CE0E79CDC"),
        // tcId 32
        ("57250E2880AF25BC0D8DBA76A8FBB666", "A0533D329A87D276A802A70EB58376A2", "F8B2314A9ABB09E72509F14A742035BA",
         "F8B2314A9ABB09E72509F14A742035BA6B5F4A0CC172672BBE8DF3F86CB58F51"),
        // tcId 33
        ("DE486E8EADC57C5FDD27AF77CE69BD11", "67FB5878F5493EE18F64ABC9AC9134FB", "54588FC5EF647313E2FA30779F88068F",
         "54588FC5EF647313E2FA30779F88068FF18AFFE7A11A74013C03E6EDA99609FC"),
        // tcId 34
        ("445FEFCA9EEA1DB4738A1741F3A60EA2", "7D833D62BAF7EBE4CFF06863E8AC91E0", "AB2BC0210F0949A2B42AE80FDCDFA4E2",
         "AB2BC0210F0949A2B42AE80FDCDFA4E2D7E6412266744B0C38AC60F602749E26"),
        // tcId 35
        ("6871F7E947A7AE4506DCCAF19ED7FFAD", "BA5A37EFCA990D23065E810D31C5D040", "35635806B764B62DCAAD53DFEB29F8E2",
         "35635806B764B62DCAAD53DFEB29F8E2623B5BDF6D4CACAC5C5F46A16964EE99"),
        // tcId 36
        ("7C353DC3733996FF98CC5D044B12F488", "8A9CBC4EDC92CDE474841DC01D974731", "B5835B6395B50538ADD7A66DD12241B9",
         "B5835B6395B50538ADD7A66DD12241B951161AED8A96C72045566981D10A8FD0"),
        // tcId 37
        ("1EE3A65D2B258DE10AE19ED4A97B0391", "17914367222B2363F213FE7C8585B801", "ACB64C35AFB630F9EBAAE6E98796D719",
         "ACB64C35AFB630F9EBAAE6E98796D7192620E3EDBABA95E14454B8354DF79BA1"),
        // tcId 38
        ("E7641BEB6720E99F5D880D840AD1EA06", "1D272B7823EA04CFE16EAE8A799D537C", "66B7EBA18B1745D782E923FE145B4FD8",
         "66B7EBA18B1745D782E923FE145B4FD80A7EC1BC4F60630625645689F2A499D0"),
        // tcId 39
        ("01248AE5215566E4A833C84AA1A1DE4F", "62A110EEB0C8470C28F97015B9597499", "164024F24E4EBA2E8DADDD396D9D7A26",
         "164024F24E4EBA2E8DADDD396D9D7A26C120BAC8D69FF6AFBF01CCE329B845D9"),
        // tcId 40
        ("9EA3BF72B04589EF93272E33D1071C2C", "16BC64474B8B9A0D1A355C1085110EFC", "3A79FAA1609703AFEBE4C03B4AF57F6D",
         "3A79FAA1609703AFEBE4C03B4AF57F6DACE0E6BFDBBF2804A1808505CAE60B6C"),
    ];

    /// SLH-DSA-SHAKE-128f: n = 16, so 64-byte signing keys, 32-byte
    /// verification keys and 17088-byte signatures (FIPS 205 table 2).
    const N: usize = 16;
    const SIGNING_KEY_LEN: usize = 4 * N;
    const VERIFICATION_KEY_LEN: usize = 2 * N;
    const SIGNATURE_LEN: usize = 17088;

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input must have an even length");
        hex.as_bytes()
            .chunks(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
            .collect()
    }

    /// `slh_keygen_internal`, which key generation calls with OS-random seeds,
    /// reproduces the ACVP key pairs byte for byte.
    #[test]
    fn keygen_internal_matches_acvp_vectors() {
        for (sk_seed, sk_prf, pk_seed, pk) in KEYGEN_VECTORS {
            let (sk_seed, sk_prf, pk_seed, pk) =
                (decode_hex(sk_seed), decode_hex(sk_prf), decode_hex(pk_seed), decode_hex(pk));
            assert_eq!([sk_seed.len(), sk_prf.len(), pk_seed.len()], [N; 3]);
            let sk = SigningKey::<Shake128f>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
            assert_eq!(sk.verifying_key().to_bytes().to_vec(), pk);
            assert_eq!(sk.to_bytes().to_vec(), [sk_seed, sk_prf, pk].concat());
        }
    }

    /// Keys in the FIPS 205 encoding (what 0.7.x returned) sign and verify
    /// through the public API.
    #[test]
    fn acvp_keys_sign_and_verify() {
        let message = b"SLH-DSA known-answer key".to_vec();
        for (sk_seed, sk_prf, _, pk) in KEYGEN_VECTORS.iter().take(2) {
            let pk = decode_hex(pk);
            let signing_key = [decode_hex(sk_seed), decode_hex(sk_prf), pk.clone()].concat();
            let signature = sign_message(message.clone(), signing_key).unwrap();
            assert_eq!(signature.len(), SIGNATURE_LEN);
            assert!(verify_signature(message.clone(), signature, pk).unwrap());
        }
    }

    /// A freshly generated key pair has the FIPS 205 lengths, its verification
    /// key is the public half of the signing key, and it signs and verifies.
    #[test]
    fn fresh_key_round_trip() {
        let keys = generate_signing_and_verification_key();
        assert_eq!(keys.signing_key.len(), SIGNING_KEY_LEN);
        assert_eq!(keys.verification_key.len(), VERIFICATION_KEY_LEN);
        assert_eq!(&keys.signing_key[2 * N..], &keys.verification_key[..]);

        let message = b"fresh SLH-DSA key".to_vec();
        let signature = sign_message(message.clone(), keys.signing_key.clone()).unwrap();
        assert_eq!(signature.len(), SIGNATURE_LEN);
        assert!(verify_signature(message, signature.clone(), keys.verification_key.clone()).unwrap());
        assert!(!verify_signature(b"other message".to_vec(), signature, keys.verification_key).unwrap());

        // Each call draws fresh seeds.
        let other = generate_signing_and_verification_key();
        assert_ne!(other.signing_key, keys.signing_key);
    }
}
