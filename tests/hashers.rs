use std::path::Path;

use cas_lib::hashers::{cas_hasher::CASHasher, sha::CASSHA};

#[cfg(test)]
mod tests {
    use super::*;

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

        let path_2 = Path::new("tests/test.docx");
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

        let path_2 = Path::new("tests/test.docx");
        let file_bytes_2: Vec<u8> = std::fs::read(path).unwrap();
        let hash_2 = <CASSHA as CASHasher>::hash_512(file_bytes_2);

        assert_eq!(hash, hash_2);
    }

    #[test]
    fn test_sha_256_threadpool_compare_fail() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let hash = <CASSHA as CASHasher>::hash_256_threadpool(file_bytes);

        let path_2 = Path::new("tests/test2.docx");
        let file_bytes_2: Vec<u8> = std::fs::read(path_2).unwrap();
        let hash_2 = <CASSHA as CASHasher>::hash_256_threadpool(file_bytes_2);

        assert_ne!(hash, hash_2);
    }

    #[test]
    fn test_sha_256_threadpool_success() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let hash = <CASSHA as CASHasher>::hash_256_threadpool(file_bytes);

        let path_2 = Path::new("tests/test.docx");
        let file_bytes_2: Vec<u8> = std::fs::read(path).unwrap();
        let hash_2 = <CASSHA as CASHasher>::hash_256_threadpool(file_bytes_2);

        assert_eq!(hash, hash_2);
    }

    #[test]
    fn test_sha_512_threadpool_compare_fail() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let hash = <CASSHA as CASHasher>::hash_512_threadpool(file_bytes);

        let path_2 = Path::new("tests/test2.docx");
        let file_bytes_2: Vec<u8> = std::fs::read(path_2).unwrap();
        let hash_2 = <CASSHA as CASHasher>::hash_512_threadpool(file_bytes_2);

        assert_ne!(hash, hash_2);
    }

    #[test]
    fn test_sha_512_threadpool_success() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let hash = <CASSHA as CASHasher>::hash_512_threadpool(file_bytes);

        let path_2 = Path::new("tests/test.docx");
        let file_bytes_2: Vec<u8> = std::fs::read(path).unwrap();
        let hash_2 = <CASSHA as CASHasher>::hash_512_threadpool(file_bytes_2);

        assert_eq!(hash, hash_2);
    }
}