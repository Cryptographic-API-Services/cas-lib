use std::{fs::{File}, io::Write, path::Path};

use cas_lib::symmetric::{aes::CASAES256, cas_symmetric_encryption::CASAES256Encryption};

#[cfg(test)]
mod symmetric {
    use cas_lib::{key_exchange::{cas_key_exchange::CASKeyExchange, x25519::X25519}, pqc::{cas_pqc::MlKemKeyPair, ml_kem::{ml_kem_1024_decapsulate, ml_kem_1024_encapsulate, ml_kem_1024_generate}}, symmetric::{aes::CASAES128, cas_symmetric_encryption::{CASAES128Encryption, Chacha20Poly1305Encryption}, chacha20poly1305::CASChacha20Poly1305}};
    use hkdf::Hkdf;
    use sha2::Sha256;

    use super::*;

    #[derive(Debug)]
    struct AesGcmRspCase {
        key: Vec<u8>,
        iv: Vec<u8>,
        pt: Vec<u8>,
        ct: Vec<u8>,
        tag: Vec<u8>,
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

    fn parse_value(line: &str, prefix: &str) -> Option<String> {
        line.strip_prefix(prefix).map(|value| value.trim().to_string())
    }

    fn parse_gcm_encryptable_rsp_cases(path: &str) -> Vec<AesGcmRspCase> {
        let contents = std::fs::read_to_string(path).unwrap();
        let mut cases = Vec::new();

        let mut key: Option<String> = None;
        let mut iv: Option<String> = None;
        let mut aad: Option<String> = None;
        let mut pt: Option<String> = None;
        let mut ct: Option<String> = None;
        let mut tag: Option<String> = None;
        let mut failed = false;

        let flush_case = |cases: &mut Vec<AesGcmRspCase>,
                          key: &mut Option<String>,
                          iv: &mut Option<String>,
                          aad: &mut Option<String>,
                          pt: &mut Option<String>,
                          ct: &mut Option<String>,
                          tag: &mut Option<String>,
                          failed: &mut bool| {
            if key.is_none() {
                return;
            }

            let key_hex = key.take();
            let iv_hex = iv.take();
            let pt_hex = pt.take();
            let ct_hex = ct.take();
            let tag_hex = tag.take();
            let aad_hex = aad.take();

            let is_supported_case = !*failed
                && aad_hex.as_deref().unwrap_or("").is_empty()
                && iv_hex.as_deref().is_some_and(|value| value.len() == 24)
                && tag_hex.as_deref().is_some_and(|value| value.len() == 32)
                && key_hex.is_some()
                && pt_hex.is_some()
                && ct_hex.is_some();

            if is_supported_case {
                cases.push(AesGcmRspCase {
                    key: decode_hex(key_hex.unwrap().as_str()),
                    iv: decode_hex(iv_hex.unwrap().as_str()),
                    pt: decode_hex(pt_hex.unwrap().as_str()),
                    ct: decode_hex(ct_hex.unwrap().as_str()),
                    tag: decode_hex(tag_hex.unwrap().as_str()),
                });
            }
            *failed = false;
        };

        for raw_line in contents.lines() {
            let line = raw_line.trim();

            if line.starts_with("Count = ") {
                flush_case(
                    &mut cases,
                    &mut key,
                    &mut iv,
                    &mut aad,
                    &mut pt,
                    &mut ct,
                    &mut tag,
                    &mut failed,
                );
                continue;
            }

            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }

            if line == "FAIL" {
                failed = true;
                continue;
            }

            if let Some(value) = parse_value(line, "Key = ") {
                key = Some(value);
                continue;
            }

            if let Some(value) = parse_value(line, "IV = ") {
                iv = Some(value);
                continue;
            }

            if let Some(value) = parse_value(line, "AAD = ") {
                aad = Some(value);
                continue;
            }

            if let Some(value) = parse_value(line, "PT = ") {
                pt = Some(value);
                continue;
            }

            if let Some(value) = parse_value(line, "CT = ") {
                ct = Some(value);
                continue;
            }

            if let Some(value) = parse_value(line, "Tag = ") {
                tag = Some(value);
            }
        }

        flush_case(
            &mut cases,
            &mut key,
            &mut iv,
            &mut aad,
            &mut pt,
            &mut ct,
            &mut tag,
            &mut failed,
        );

        cases
    }

    fn assert_aes_128_gcm_rsp_encrypt_vectors(path: &str) {
        let cases = parse_gcm_encryptable_rsp_cases(path);
        assert!(!cases.is_empty(), "no AES-128-GCM vectors were loaded from {path}");

        for case in cases {
            let mut expected = case.ct.clone();
            expected.extend_from_slice(&case.tag);

            let encrypted = <CASAES128 as CASAES128Encryption>::encrypt_plaintext(
                case.key.clone(),
                case.iv.clone(),
                case.pt.clone(),
            );

            assert_eq!(encrypted, expected);
        }
    }

    fn assert_aes_256_gcm_rsp_encrypt_vectors(path: &str) {
        let cases = parse_gcm_encryptable_rsp_cases(path);
        assert!(!cases.is_empty(), "no AES-256-GCM vectors were loaded from {path}");

        for case in cases {
            let mut expected = case.ct.clone();
            expected.extend_from_slice(&case.tag);

            let encrypted = <CASAES256 as CASAES256Encryption>::encrypt_plaintext(
                case.key.clone(),
                case.iv.clone(),
                case.pt.clone(),
            );

            assert_eq!(encrypted, expected);
        }
    }

    #[test]
    fn test_aes_256() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let aes_nonce = <CASAES256 as CASAES256Encryption>::generate_nonce();
        let aes_key = <CASAES256 as CASAES256Encryption>::generate_key();
        let encrypted_bytes = <CASAES256 as CASAES256Encryption>::encrypt_plaintext(aes_key.clone(), aes_nonce.clone(), file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes).unwrap();

        let decrypted_bytes = <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(aes_key, aes_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    fn test_aes256_x25519_diffie_hellman() {
        let bob_public = <X25519 as CASKeyExchange>::generate_secret_and_public_key();
        let alice_public = <X25519 as CASKeyExchange>::generate_secret_and_public_key();

        let bob_shared_secret = <X25519 as CASKeyExchange>::diffie_hellman(bob_public.secret_key, alice_public.public_key);
        let alice_shared_secret = <X25519 as CASKeyExchange>::diffie_hellman(alice_public.secret_key, bob_public.public_key);

        let aes_nonce = <CASAES256 as CASAES256Encryption>::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let alice_key = <CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(bob_shared_secret);
        let encrypted_bytes = <CASAES256 as CASAES256Encryption>::encrypt_plaintext(alice_key, aes_nonce.clone(), file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes).unwrap();

        let bob_key = <CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(alice_shared_secret);
        let decrypted_bytes = <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(bob_key, aes_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }
    
    #[test]
    fn test_aes_128() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let aes_nonce = <CASAES128 as CASAES128Encryption>::generate_nonce();
        let aes_key = <CASAES128 as CASAES128Encryption>::generate_key();
        let encrypted_bytes = <CASAES128 as CASAES128Encryption>::encrypt_plaintext(aes_key.clone(), aes_nonce.clone(), file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes).unwrap();


        let decrypted_bytes = <CASAES128 as CASAES128Encryption>::decrypt_ciphertext(aes_key, aes_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    fn test_aes128_x25519_diffie_hellman() {
        let bob_public = <X25519 as CASKeyExchange>::generate_secret_and_public_key();
        let alice_public = <X25519 as CASKeyExchange>::generate_secret_and_public_key();

        let bob_shared_secret = <X25519 as CASKeyExchange>::diffie_hellman(bob_public.secret_key, alice_public.public_key);
        let alice_shared_secret = <X25519 as CASKeyExchange>::diffie_hellman(alice_public.secret_key, bob_public.public_key);

        let aes_nonce = <CASAES128 as CASAES128Encryption>::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let alice_key = <CASAES128 as CASAES128Encryption>::key_from_x25519_shared_secret(bob_shared_secret);
        let encrypted_bytes = <CASAES128 as CASAES128Encryption>::encrypt_plaintext(alice_key, aes_nonce.clone(), file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes).unwrap();
        

        let bob_key = <CASAES128 as CASAES128Encryption>::key_from_x25519_shared_secret(alice_shared_secret);
        let decrypted_bytes = <CASAES128 as CASAES128Encryption>::decrypt_ciphertext(bob_key, aes_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    fn test_chacha20_poly1305() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let chacha20_nonce = <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_nonce();
        let chacha20_key = <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_key();
        let encrypted_bytes = <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::encrypt_plaintext(chacha20_key.clone(), chacha20_nonce.clone(), file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes).unwrap();

        let decrypted_bytes = <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::decrypt_ciphertext(chacha20_key, chacha20_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    pub fn round_trip_mlkem1024_hkdf() {
        let secret_key_public_key: MlKemKeyPair = ml_kem_1024_generate();
        let ct = ml_kem_1024_encapsulate(secret_key_public_key.public_key).expect("encapsulate failed");
        let ss_receiver = ml_kem_1024_decapsulate(secret_key_public_key.secret_key, ct.ciphertext).expect("decapsulate failed");

        let bob_shared_secret = Hkdf::<Sha256>::new(None, &ss_receiver);
        let alice_shared_secret = Hkdf::<Sha256>::new(None, &ct.shared_secret);

        let mut aes_key = Box::new([0u8; 32]);
        bob_shared_secret.expand(b"aes key", &mut *aes_key).unwrap();

        let mut aes_key2 = Box::new([0u8; 32]);
        alice_shared_secret.expand(b"aes key", &mut *aes_key2).unwrap();
        assert_eq!(aes_key.to_vec(), aes_key2.to_vec());

        let aes_nonce = <CASAES256 as CASAES256Encryption>::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let encrypted_bytes = <CASAES256 as CASAES256Encryption>::encrypt_plaintext(aes_key.to_vec(), aes_nonce.clone(), file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes).unwrap();

        let decrypted_bytes = <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(aes_key2.to_vec(), aes_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    fn test_aes_128_gcm_rsp_encrypt_vectors() {
        assert_aes_128_gcm_rsp_encrypt_vectors("tests/data/aes/gcmDecrypt128.rsp");
    }

    #[test]
    fn test_aes_256_gcm_rsp_encrypt_vectors() {
        assert_aes_256_gcm_rsp_encrypt_vectors("tests/data/aes/gcmDecrypt256.rsp");
    }
}
