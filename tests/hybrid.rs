#[cfg(test)]
mod hybrid {
    use std::path::Path;

    use cas_lib::error::CasError;
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
        let (encapped_key, ciphertext, tag) = CASHPKE::encrypt(file_bytes.clone(), public_key, info_str, Vec::new()).unwrap();
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
        let (encapped_key, ciphertext, tag) = CASHPKE::encrypt(file_bytes.clone(), public_key, info_str.clone(), Vec::new()).unwrap();
        let decrypted_bytes = CASHPKE::decrypt(ciphertext, private_key, encapped_key, tag, info_str, Vec::new()).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    pub fn hpke_round_trip_with_aad() {
        let file_bytes: Vec<u8> = std::fs::read("tests/test.docx").unwrap();
        let (private_key, public_key, info_str) = CASHPKE::generate_key_pair();
        let aad = b"message-id:7".to_vec();
        let (encapped_key, ciphertext, tag) =
            CASHPKE::encrypt(file_bytes.clone(), public_key, info_str.clone(), aad.clone()).unwrap();
        let decrypted_bytes =
            CASHPKE::decrypt(ciphertext, private_key, encapped_key, tag, info_str, aad).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    pub fn hpke_rejects_tampered_aad() {
        let (private_key, public_key, info_str) = CASHPKE::generate_key_pair();
        let aad = b"message-id:7".to_vec();
        let (encapped_key, ciphertext, tag) =
            CASHPKE::encrypt(b"hello".to_vec(), public_key, info_str.clone(), aad).unwrap();

        let wrong = CASHPKE::decrypt(
            ciphertext.clone(),
            private_key.clone(),
            encapped_key.clone(),
            tag.clone(),
            info_str.clone(),
            b"message-id:8".to_vec(),
        );
        assert_eq!(wrong, Err(CasError::DecryptionFailed));

        let missing = CASHPKE::decrypt(ciphertext, private_key, encapped_key, tag, info_str, Vec::new());
        assert_eq!(missing, Err(CasError::DecryptionFailed));
    }

    #[test]
    pub fn hpke_rejects_aad_added_after_encryption() {
        let (private_key, public_key, info_str) = CASHPKE::generate_key_pair();
        let (encapped_key, ciphertext, tag) =
            CASHPKE::encrypt(b"hello".to_vec(), public_key, info_str.clone(), Vec::new()).unwrap();
        let result =
            CASHPKE::decrypt(ciphertext, private_key, encapped_key, tag, info_str, b"extra".to_vec());
        assert_eq!(result, Err(CasError::DecryptionFailed));
    }
}
