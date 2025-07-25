#[cfg(test)]
mod hybrid {
    use std::{os::windows::fs::FileExt, path::Path};

    use cas_lib::hybrid::{cas_hybrid::CASHybrid, hpke::CASHPKE};

    
    #[test]
    pub fn test_generate_key_pair() {
        let (private_key, public_key, info_str) = CASHPKE::generate_key_pair();
        assert!(!private_key.is_empty());
        assert!(!public_key.is_empty());
        assert!(!info_str.is_empty());
    }

    #[test]
    pub fn encrypt_hpke() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let (_private_key, public_key, info_str) = CASHPKE::generate_key_pair();
        let (encapped_key, ciphertext, tag) = CASHPKE::encrypt(file_bytes.clone(), public_key, info_str);
        assert!(!encapped_key.is_empty());
        assert!(!ciphertext.is_empty());
        assert!(!tag.is_empty());
        assert_ne!(file_bytes, ciphertext);
    }

    #[test]
    pub fn decrypt_hpke() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let (private_key, public_key, info_str) = CASHPKE::generate_key_pair();
        let (encapped_key, ciphertext, tag) = CASHPKE::encrypt(file_bytes.clone(), public_key, info_str.clone());
        let decrypted_bytes = CASHPKE::decrypt(ciphertext, private_key, encapped_key, tag, info_str);
        assert_eq!(file_bytes, decrypted_bytes);
    }
}