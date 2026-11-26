//! HKDF API tests. The known-answer tests are the Wycheproof `hkdf_sha256` and
//! `hkdf_sha512` files in `tests/wycheproof.rs`, which also cover empty salts.
//! Inputs here are random: CodeQL flags literal salts and keys, even in tests.

use cas_lib::error::CasError;
use cas_lib::kdf::cas_hkdf::{CASHkdfSha256, CASHkdfSha512, CASHKDF};
use rand::{rngs::OsRng, Rng};

fn random(len: usize) -> Vec<u8> {
    (0..len).map(|_| OsRng.gen()).collect()
}

/// One PRK, several `expand` calls with distinct `info`: the keys differ, and
/// each matches what `derive` gives for the same inputs.
fn one_prk_many_keys<H: CASHKDF>() {
    let salt = random(H::HASH_LEN);
    let ikm = random(96);
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

fn output_length_limits<H: CASHKDF>() {
    let prk = random(H::HASH_LEN);
    let ikm = random(32);
    let max = H::MAX_OUTPUT_LEN;
    assert_eq!(max, 255 * H::HASH_LEN);

    assert_eq!(H::expand(prk.clone(), Vec::new(), 1).unwrap().len(), 1);
    assert_eq!(H::expand(prk.clone(), Vec::new(), max).unwrap().len(), max);
    assert_eq!(H::expand(prk.clone(), Vec::new(), 0), Err(CasError::InvalidParameters));
    assert_eq!(H::expand(prk, Vec::new(), max + 1), Err(CasError::InvalidParameters));

    assert_eq!(H::derive(Vec::new(), ikm.clone(), Vec::new(), max).unwrap().len(), max);
    assert_eq!(H::derive(Vec::new(), ikm.clone(), Vec::new(), 0), Err(CasError::InvalidParameters));
    assert_eq!(H::derive(Vec::new(), ikm, Vec::new(), max + 1), Err(CasError::InvalidParameters));
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
    let prk = random(H::HASH_LEN + 1);
    assert_eq!(
        H::expand(prk[..H::HASH_LEN - 1].to_vec(), Vec::new(), 32),
        Err(CasError::InvalidKey)
    );
    assert!(H::expand(prk, Vec::new(), 32).is_ok());
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
    let ikm = random(32);
    let okm256 = CASHkdfSha256::derive(Vec::new(), ikm.clone(), Vec::new(), 32).unwrap();
    let okm512 = CASHkdfSha512::derive(Vec::new(), ikm.clone(), Vec::new(), 32).unwrap();
    assert_ne!(okm256, okm512);
    assert_eq!(CASHkdfSha256::extract(Vec::new(), ikm.clone()).len(), 32);
    assert_eq!(CASHkdfSha512::extract(Vec::new(), ikm).len(), 64);
}
