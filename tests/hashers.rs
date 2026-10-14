use std::path::Path;

use cas_lib::hashers::{cas_hasher::CASHasher, sha::CASSHA, sha2::CASSHA2};

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
