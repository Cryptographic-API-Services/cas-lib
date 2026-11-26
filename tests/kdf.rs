use cas_lib::error::CasError;
use cas_lib::kdf::cas_hkdf::{CASHkdfSha256, CASHkdfSha512, CASHKDF};
use std::collections::HashMap;
use std::fs;

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex input must have an even length");
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}

/// Parses `tests/data/hkdf/rfc5869_sha256.txt` into one `field -> value` map per test case.
fn rfc5869_cases() -> Vec<HashMap<String, String>> {
    let text = fs::read_to_string("tests/data/hkdf/rfc5869_sha256.txt").unwrap();
    let mut cases = Vec::new();
    let mut current: Option<HashMap<String, String>> = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            cases.extend(current.take());
            current = Some(HashMap::new());
        } else if let Some((key, value)) = line.split_once('=') {
            current
                .as_mut()
                .expect("field before the first [Test Case]")
                .insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    cases.extend(current);
    cases
}

#[test]
fn rfc5869_sha256_vectors() {
    let cases = rfc5869_cases();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let field = |name: &str| decode_hex(&case[name]);
        let length: usize = case["L"].parse().unwrap();

        let prk = CASHkdfSha256::extract(field("salt"), field("IKM"));
        assert_eq!(prk, field("PRK"), "PRK mismatch");

        let okm = CASHkdfSha256::expand(prk, field("info"), length).unwrap();
        assert_eq!(okm, field("OKM"), "OKM from extract + expand mismatch");

        let okm = CASHkdfSha256::derive(field("salt"), field("IKM"), field("info"), length).unwrap();
        assert_eq!(okm, field("OKM"), "OKM from derive mismatch");
    }
}

/// One PRK, several `expand` calls with distinct `info`: the keys differ, and
/// each matches what `derive` gives for the same inputs.
fn one_prk_many_keys<H: CASHKDF>() {
    let salt = vec![7u8; H::HASH_LEN];
    let ikm = vec![42u8; 96];
    let prk = H::extract(salt.clone(), ikm.clone());
    assert_eq!(prk.len(), H::HASH_LEN);

    let send = H::expand(prk.clone(), b"chat/v1 send".to_vec(), 32).unwrap();
    let receive = H::expand(prk, b"chat/v1 receive".to_vec(), 32).unwrap();
    assert_eq!(send.len(), 32);
    assert_ne!(send, receive);
    assert_eq!(send, H::derive(salt, ikm, b"chat/v1 send".to_vec(), 32).unwrap());
}

#[test]
fn sha256_one_prk_many_keys() {
    one_prk_many_keys::<CASHkdfSha256>();
}

#[test]
fn sha512_one_prk_many_keys() {
    one_prk_many_keys::<CASHkdfSha512>();
}

/// An empty salt is RFC 5869's "not provided", i.e. `HashLen` zero bytes.
fn empty_salt_is_zero_salt<H: CASHKDF>() {
    let ikm = vec![1u8; 32];
    assert_eq!(
        H::extract(Vec::new(), ikm.clone()),
        H::extract(vec![0u8; H::HASH_LEN], ikm)
    );
}

#[test]
fn sha256_empty_salt_is_zero_salt() {
    empty_salt_is_zero_salt::<CASHkdfSha256>();
}

#[test]
fn sha512_empty_salt_is_zero_salt() {
    empty_salt_is_zero_salt::<CASHkdfSha512>();
}

fn output_length_limits<H: CASHKDF>() {
    let prk = vec![3u8; H::HASH_LEN];
    let max = H::MAX_OUTPUT_LEN;
    assert_eq!(max, 255 * H::HASH_LEN);

    assert_eq!(H::expand(prk.clone(), Vec::new(), 1).unwrap().len(), 1);
    assert_eq!(H::expand(prk.clone(), Vec::new(), max).unwrap().len(), max);
    assert_eq!(H::expand(prk.clone(), Vec::new(), 0), Err(CasError::InvalidParameters));
    assert_eq!(H::expand(prk, Vec::new(), max + 1), Err(CasError::InvalidParameters));

    assert_eq!(H::derive(Vec::new(), vec![1], Vec::new(), max).unwrap().len(), max);
    assert_eq!(H::derive(Vec::new(), vec![1], Vec::new(), 0), Err(CasError::InvalidParameters));
    assert_eq!(H::derive(Vec::new(), vec![1], Vec::new(), max + 1), Err(CasError::InvalidParameters));
}

#[test]
fn sha256_output_length_limits() {
    output_length_limits::<CASHkdfSha256>();
}

#[test]
fn sha512_output_length_limits() {
    output_length_limits::<CASHkdfSha512>();
}

/// RFC 5869 section 2.3: the PRK must be at least `HashLen` bytes.
fn short_prk_is_rejected<H: CASHKDF>() {
    let short = vec![1u8; H::HASH_LEN - 1];
    assert_eq!(H::expand(short, Vec::new(), 32), Err(CasError::InvalidKey));
    assert!(H::expand(vec![1u8; H::HASH_LEN + 1], Vec::new(), 32).is_ok());
}

#[test]
fn sha256_short_prk_is_rejected() {
    short_prk_is_rejected::<CASHkdfSha256>();
}

#[test]
fn sha512_short_prk_is_rejected() {
    short_prk_is_rejected::<CASHkdfSha512>();
}

#[test]
fn sha256_and_sha512_differ() {
    let ikm = vec![9u8; 32];
    let okm256 = CASHkdfSha256::derive(Vec::new(), ikm.clone(), Vec::new(), 32).unwrap();
    let okm512 = CASHkdfSha512::derive(Vec::new(), ikm, Vec::new(), 32).unwrap();
    assert_ne!(okm256, okm512);
    assert_eq!(CASHkdfSha512::extract(Vec::new(), vec![1]).len(), 64);
}
