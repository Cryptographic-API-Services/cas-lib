use std::path::Path;

use cas_lib::hashers::{blake2::CASBlake2, cas_hasher::CASHasher, sha::CASSHA, sha2::CASSHA2};

#[cfg(test)]
mod hashers {
    use super::*;
    use std::fs;

    #[derive(Debug)]
    struct RspCase {
        message: Vec<u8>,
        digest: Vec<u8>,
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input must have an even length");

        hex.as_bytes()
            .chunks(2)
            .map(|chunk| {
                let byte = std::str::from_utf8(chunk).unwrap();
                u8::from_str_radix(byte, 16).unwrap()
            })
            .collect()
    }

    fn parse_rsp_file(path: &str) -> Vec<RspCase> {
        let contents = fs::read_to_string(path).unwrap();
        let mut len_bits: Option<usize> = None;
        let mut msg_hex: Option<String> = None;
        let mut cases = Vec::new();

        for line in contents.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }

            if let Some(value) = line.strip_prefix("Len = ") {
                len_bits = Some(value.parse::<usize>().unwrap());
                continue;
            }

            if let Some(value) = line.strip_prefix("Msg = ") {
                msg_hex = Some(value.to_string());
                continue;
            }

            if let Some(value) = line.strip_prefix("MD = ") {
                let len_bits = len_bits.take().unwrap();
                let msg_hex = msg_hex.take().unwrap();
                let digest = decode_hex(value);
                let message = if len_bits == 0 {
                    Vec::new()
                } else {
                    assert_eq!(len_bits % 8, 0, "only byte-aligned vectors are supported");
                    let message = decode_hex(&msg_hex);
                    assert_eq!(message.len(), len_bits / 8);
                    message
                };

                cases.push(RspCase { message, digest });
            }
        }

        cases
    }

    fn assert_sha3_256_vectors(path: &str) {
        for case in parse_rsp_file(path) {
            let hash = <CASSHA as CASHasher>::hash_256(case.message.clone());
            assert_eq!(hash, case.digest);
            assert!(<CASSHA as CASHasher>::verify_256(case.digest, case.message));
        }
    }

    fn assert_sha3_512_vectors(path: &str) {
        for case in parse_rsp_file(path) {
            let hash = <CASSHA as CASHasher>::hash_512(case.message.clone());
            assert_eq!(hash, case.digest);
            assert!(<CASSHA as CASHasher>::verify_512(case.digest, case.message));
        }
    }

    fn assert_sha2_256_vectors(path: &str) {
        for case in parse_rsp_file(path) {
            let hash = <CASSHA2 as CASHasher>::hash_256(case.message.clone());
            assert_eq!(hash, case.digest);
            assert!(<CASSHA2 as CASHasher>::verify_256(case.digest, case.message));
        }
    }

    fn assert_sha2_512_vectors(path: &str) {
        for case in parse_rsp_file(path) {
            let hash = <CASSHA2 as CASHasher>::hash_512(case.message.clone());
            assert_eq!(hash, case.digest);
            assert!(<CASSHA2 as CASHasher>::verify_512(case.digest, case.message));
        }
    }

    #[test]
    fn test_sha_256_compare_fail() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let hash = <CASSHA as CASHasher>::hash_256(file_bytes);

        let path_2 = Path::new("tests/test2.docx");
        let file_bytes_2: Vec<u8> = std::fs::read(path_2).unwrap();
        let hash_2 = <CASSHA as CASHasher>::hash_256(file_bytes_2);

        assert_ne!(hash, hash_2);
    }

    #[test]
    fn test_sha_256_success() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let hash = <CASSHA as CASHasher>::hash_256(file_bytes);

        let file_bytes_2: Vec<u8> = std::fs::read(path).unwrap();
        let hash_2 = <CASSHA as CASHasher>::hash_256(file_bytes_2);

        assert_eq!(hash, hash_2);
    }

    #[test]
    fn test_sha_512_compare_fail() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let hash = <CASSHA as CASHasher>::hash_512(file_bytes);

        let path_2 = Path::new("tests/test2.docx");
        let file_bytes_2: Vec<u8> = std::fs::read(path_2).unwrap();
        let hash_2 = <CASSHA as CASHasher>::hash_512(file_bytes_2);

        assert_ne!(hash, hash_2);
    }

    #[test]
    fn test_sha_512_success() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let hash = <CASSHA as CASHasher>::hash_512(file_bytes);

        let file_bytes_2: Vec<u8> = std::fs::read(path).unwrap();
        let hash_2 = <CASSHA as CASHasher>::hash_512(file_bytes_2);

        assert_eq!(hash, hash_2);
    }

    #[test]
    fn test_sha3_256_short_msg_rsp_vectors() {
        assert_sha3_256_vectors("tests/data/hashers/SHA3_256ShortMsg.rsp");
    }

    #[test]
    fn test_sha3_256_long_msg_rsp_vectors() {
        assert_sha3_256_vectors("tests/data/hashers/SHA3_256LongMsg.rsp");
    }

    #[test]
    fn test_sha3_512_short_msg_rsp_vectors() {
        assert_sha3_512_vectors("tests/data/hashers/SHA3_512ShortMsg.rsp");
    }

    #[test]
    fn test_sha3_512_long_msg_rsp_vectors() {
        assert_sha3_512_vectors("tests/data/hashers/SHA3_512LongMsg.rsp");
    }

    #[test]
    fn test_sha2_256_compare_fail() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let hash = <CASSHA2 as CASHasher>::hash_256(file_bytes);

        let path_2 = Path::new("tests/test2.docx");
        let file_bytes_2: Vec<u8> = std::fs::read(path_2).unwrap();
        let hash_2 = <CASSHA2 as CASHasher>::hash_256(file_bytes_2);

        assert_ne!(hash, hash_2);
    }

    #[test]
    fn test_sha2_512_compare_fail() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let hash = <CASSHA2 as CASHasher>::hash_512(file_bytes);

        let path_2 = Path::new("tests/test2.docx");
        let file_bytes_2: Vec<u8> = std::fs::read(path_2).unwrap();
        let hash_2 = <CASSHA2 as CASHasher>::hash_512(file_bytes_2);

        assert_ne!(hash, hash_2);
    }

    #[test]
    fn test_sha2_256_verify_rejects_wrong_digest() {
        let data = b"cas-lib sha2".to_vec();
        let mut digest = <CASSHA2 as CASHasher>::hash_256(data.clone());
        assert_eq!(digest.len(), 32);
        digest[0] ^= 0x01;
        assert!(!<CASSHA2 as CASHasher>::verify_256(digest, data));
    }

    #[test]
    fn test_sha2_512_verify_rejects_wrong_digest() {
        let data = b"cas-lib sha2".to_vec();
        let mut digest = <CASSHA2 as CASHasher>::hash_512(data.clone());
        assert_eq!(digest.len(), 64);
        digest[0] ^= 0x01;
        assert!(!<CASSHA2 as CASHasher>::verify_512(digest, data));
    }

    #[test]
    fn test_sha2_256_short_msg_rsp_vectors() {
        assert_sha2_256_vectors("tests/data/hashers/SHA256ShortMsg.rsp");
    }

    #[test]
    fn test_sha2_256_long_msg_rsp_vectors() {
        assert_sha2_256_vectors("tests/data/hashers/SHA256LongMsg.rsp");
    }

    #[test]
    fn test_sha2_512_short_msg_rsp_vectors() {
        assert_sha2_512_vectors("tests/data/hashers/SHA512ShortMsg.rsp");
    }

    #[test]
    fn test_sha2_512_long_msg_rsp_vectors() {
        assert_sha2_512_vectors("tests/data/hashers/SHA512LongMsg.rsp");
    }
}

/// Issue #113: every `verify_*` compares digests in constant time and rejects a
/// digest of the wrong length up front. These tests pin down the accept/reject
/// behaviour for each of the six verify functions.
#[cfg(test)]
mod constant_time_verify {
    use super::*;

    type HashFn = fn(Vec<u8>) -> Vec<u8>;
    type VerifyFn = fn(Vec<u8>, Vec<u8>) -> bool;

    fn all_verifiers() -> Vec<(&'static str, HashFn, VerifyFn, usize)> {
        vec![
            ("sha3-256", <CASSHA as CASHasher>::hash_256, <CASSHA as CASHasher>::verify_256, 32),
            ("sha3-512", <CASSHA as CASHasher>::hash_512, <CASSHA as CASHasher>::verify_512, 64),
            ("sha2-256", <CASSHA2 as CASHasher>::hash_256, <CASSHA2 as CASHasher>::verify_256, 32),
            ("sha2-512", <CASSHA2 as CASHasher>::hash_512, <CASSHA2 as CASHasher>::verify_512, 64),
            ("blake2s-256", <CASBlake2 as CASHasher>::hash_256, <CASBlake2 as CASHasher>::verify_256, 32),
            ("blake2b-512", <CASBlake2 as CASHasher>::hash_512, <CASBlake2 as CASHasher>::verify_512, 64),
        ]
    }

    fn data() -> Vec<u8> {
        b"cas-lib constant-time verify".to_vec()
    }

    #[test]
    fn accepts_correct_digest() {
        for (name, hash, verify, len) in all_verifiers() {
            let digest = hash(data());
            assert_eq!(digest.len(), len, "{name}: unexpected digest length");
            assert!(verify(digest, data()), "{name}: correct digest rejected");
        }
    }

    #[test]
    fn rejects_digest_with_one_byte_changed() {
        for (name, hash, verify, len) in all_verifiers() {
            // Flip a byte at the start, middle and end in turn, so a comparison that
            // only looked at some positions would be caught.
            for index in [0, len / 2, len - 1] {
                let mut digest = hash(data());
                digest[index] ^= 0x01;
                assert!(
                    !verify(digest, data()),
                    "{name}: digest with byte {index} changed was accepted"
                );
            }
        }
    }

    #[test]
    fn rejects_digest_of_wrong_length() {
        for (name, hash, verify, _) in all_verifiers() {
            let digest = hash(data());

            let mut truncated = digest.clone();
            truncated.pop();
            assert!(!verify(truncated, data()), "{name}: truncated digest accepted");

            let mut extended = digest.clone();
            extended.push(0);
            assert!(!verify(extended, data()), "{name}: extended digest accepted");

            // A correct prefix of the other output size must not verify either.
            let mut doubled = digest.clone();
            doubled.extend_from_slice(&digest);
            assert!(!verify(doubled, data()), "{name}: doubled digest accepted");
        }
    }

    #[test]
    fn rejects_empty_digest() {
        for (name, _, verify, _) in all_verifiers() {
            assert!(!verify(Vec::new(), data()), "{name}: empty digest accepted");
            assert!(!verify(Vec::new(), Vec::new()), "{name}: empty digest of empty data accepted");
        }
    }
}
