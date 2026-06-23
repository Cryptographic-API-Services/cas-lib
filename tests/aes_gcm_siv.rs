use std::{fs::File, io::Write, path::Path};

use cas_lib::symmetric::{
    aes_gcm_siv::{CASAES128SIV, CASAES256SIV},
    cas_symmetric_encryption::{CASAES128SIVEncryption, CASAES256SIVEncryption},
};

mod common;

#[cfg(test)]
mod aes_gcm_siv {
    use crate::common::temp_output_path;
    use cas_lib::key_exchange::{cas_key_exchange::CASKeyExchange, x25519::X25519};

    use super::*;

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

    /// Known-answer test vectors from RFC 8452 Appendix C.
    /// Each result is the ciphertext with the 16-byte authentication tag appended,
    /// which matches the output of `encrypt_plaintext`. All cases use empty AAD.
    struct SivKatCase {
        key: &'static str,
        nonce: &'static str,
        plaintext: &'static str,
        result: &'static str,
    }

    // RFC 8452 Appendix C.1 — AES-128-GCM-SIV
    const AES128_GCM_SIV_KAT: &[SivKatCase] = &[
        SivKatCase {
            key: "01000000000000000000000000000000",
            nonce: "030000000000000000000000",
            plaintext: "",
            result: "dc20e2d83f25705bb49e439eca56de25",
        },
        SivKatCase {
            key: "01000000000000000000000000000000",
            nonce: "030000000000000000000000",
            plaintext: "0100000000000000",
            result: "b5d839330ac7b786578782fff6013b815b287c22493a364c",
        },
        SivKatCase {
            key: "01000000000000000000000000000000",
            nonce: "030000000000000000000000",
            plaintext: "010000000000000000000000",
            result: "7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639",
        },
        SivKatCase {
            key: "01000000000000000000000000000000",
            nonce: "030000000000000000000000",
            plaintext: "01000000000000000000000000000000",
            result: "743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4",
        },
        SivKatCase {
            key: "01000000000000000000000000000000",
            nonce: "030000000000000000000000",
            plaintext: "0100000000000000000000000000000002000000000000000000000000000000",
            result: "84e07e62ba83a6585417245d7ec413a9fe427d6315c09b57ce45f2e3936a94451a8e45dcd4578c667cd86847bf6155ff",
        },
    ];

    // RFC 8452 Appendix C.2 — AES-256-GCM-SIV
    const AES256_GCM_SIV_KAT: &[SivKatCase] = &[
        SivKatCase {
            key: "0100000000000000000000000000000000000000000000000000000000000000",
            nonce: "030000000000000000000000",
            plaintext: "",
            result: "07f5f4169bbf55a8400cd47ea6fd400f",
        },
        SivKatCase {
            key: "0100000000000000000000000000000000000000000000000000000000000000",
            nonce: "030000000000000000000000",
            plaintext: "0100000000000000",
            result: "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
        },
        SivKatCase {
            key: "0100000000000000000000000000000000000000000000000000000000000000",
            nonce: "030000000000000000000000",
            plaintext: "010000000000000000000000",
            result: "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e",
        },
        SivKatCase {
            key: "0100000000000000000000000000000000000000000000000000000000000000",
            nonce: "030000000000000000000000",
            plaintext: "01000000000000000000000000000000",
            result: "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
        },
    ];

    #[test]
    fn test_aes_256_gcm_siv_round_trip() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let nonce = <CASAES256SIV as CASAES256SIVEncryption>::generate_nonce();
        let key = <CASAES256SIV as CASAES256SIVEncryption>::generate_key();
        let encrypted_bytes = <CASAES256SIV as CASAES256SIVEncryption>::encrypt_plaintext(
            key.clone(),
            nonce.clone(),
            file_bytes.clone(),
        )
        .unwrap();
        let mut file = File::create(temp_output_path("encrypted.docx")).unwrap();
        file.write_all(&encrypted_bytes).unwrap();

        let decrypted_bytes = <CASAES256SIV as CASAES256SIVEncryption>::decrypt_ciphertext(
            key,
            nonce,
            encrypted_bytes,
        )
        .unwrap();
        let mut file = File::create(temp_output_path("decrypted.docx")).unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    fn test_aes_128_gcm_siv_round_trip() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let nonce = <CASAES128SIV as CASAES128SIVEncryption>::generate_nonce();
        let key = <CASAES128SIV as CASAES128SIVEncryption>::generate_key();
        let encrypted_bytes = <CASAES128SIV as CASAES128SIVEncryption>::encrypt_plaintext(
            key.clone(),
            nonce.clone(),
            file_bytes.clone(),
        )
        .unwrap();
        let mut file = File::create(temp_output_path("encrypted.docx")).unwrap();
        file.write_all(&encrypted_bytes).unwrap();

        let decrypted_bytes = <CASAES128SIV as CASAES128SIVEncryption>::decrypt_ciphertext(
            key,
            nonce,
            encrypted_bytes,
        )
        .unwrap();
        let mut file = File::create(temp_output_path("decrypted.docx")).unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    fn test_aes_128_gcm_siv_rfc8452_vectors() {
        for case in AES128_GCM_SIV_KAT {
            let key = decode_hex(case.key);
            let nonce = decode_hex(case.nonce);
            let plaintext = decode_hex(case.plaintext);
            let expected = decode_hex(case.result);

            let encrypted = <CASAES128SIV as CASAES128SIVEncryption>::encrypt_plaintext(
                key.clone(),
                nonce.clone(),
                plaintext.clone(),
            )
            .unwrap();
            assert_eq!(encrypted, expected, "encrypt mismatch for pt = {}", case.plaintext);

            let decrypted = <CASAES128SIV as CASAES128SIVEncryption>::decrypt_ciphertext(
                key,
                nonce,
                expected,
            )
            .unwrap();
            assert_eq!(decrypted, plaintext, "decrypt mismatch for pt = {}", case.plaintext);
        }
    }

    #[test]
    fn test_aes_256_gcm_siv_rfc8452_vectors() {
        for case in AES256_GCM_SIV_KAT {
            let key = decode_hex(case.key);
            let nonce = decode_hex(case.nonce);
            let plaintext = decode_hex(case.plaintext);
            let expected = decode_hex(case.result);

            let encrypted = <CASAES256SIV as CASAES256SIVEncryption>::encrypt_plaintext(
                key.clone(),
                nonce.clone(),
                plaintext.clone(),
            )
            .unwrap();
            assert_eq!(encrypted, expected, "encrypt mismatch for pt = {}", case.plaintext);

            let decrypted = <CASAES256SIV as CASAES256SIVEncryption>::decrypt_ciphertext(
                key,
                nonce,
                expected,
            )
            .unwrap();
            assert_eq!(decrypted, plaintext, "decrypt mismatch for pt = {}", case.plaintext);
        }
    }

    #[test]
    fn test_aes_256_gcm_siv_tampered_ciphertext_fails() {
        let key = <CASAES256SIV as CASAES256SIVEncryption>::generate_key();
        let nonce = <CASAES256SIV as CASAES256SIVEncryption>::generate_nonce();
        let mut encrypted = <CASAES256SIV as CASAES256SIVEncryption>::encrypt_plaintext(
            key.clone(),
            nonce.clone(),
            b"top secret message".to_vec(),
        )
        .unwrap();

        // Flip a bit so the authentication tag no longer verifies.
        encrypted[0] ^= 0x01;

        let result =
            <CASAES256SIV as CASAES256SIVEncryption>::decrypt_ciphertext(key, nonce, encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_128_gcm_siv_invalid_key_and_nonce() {
        let valid_key = <CASAES128SIV as CASAES128SIVEncryption>::generate_key();
        let valid_nonce = <CASAES128SIV as CASAES128SIVEncryption>::generate_nonce();

        // Wrong key length.
        assert!(<CASAES128SIV as CASAES128SIVEncryption>::encrypt_plaintext(
            vec![0u8; 8],
            valid_nonce.clone(),
            b"data".to_vec()
        )
        .is_err());

        // Wrong nonce length.
        assert!(<CASAES128SIV as CASAES128SIVEncryption>::encrypt_plaintext(
            valid_key,
            vec![0u8; 8],
            b"data".to_vec()
        )
        .is_err());
    }

    #[test]
    fn test_aes_256_gcm_siv_key_from_vec() {
        let key = <CASAES256SIV as CASAES256SIVEncryption>::generate_key();
        assert_eq!(
            <CASAES256SIV as CASAES256SIVEncryption>::key_from_vec(key.clone()).unwrap(),
            key
        );
        assert!(<CASAES256SIV as CASAES256SIVEncryption>::key_from_vec(vec![0u8; 31]).is_err());
    }

    #[test]
    fn test_aes_256_gcm_siv_x25519_diffie_hellman() {
        let bob = <X25519 as CASKeyExchange>::generate_secret_and_public_key();
        let alice = <X25519 as CASKeyExchange>::generate_secret_and_public_key();

        let bob_shared_secret =
            <X25519 as CASKeyExchange>::diffie_hellman(bob.secret_key, alice.public_key).unwrap();
        let alice_shared_secret =
            <X25519 as CASKeyExchange>::diffie_hellman(alice.secret_key, bob.public_key).unwrap();

        let nonce = <CASAES256SIV as CASAES256SIVEncryption>::generate_nonce();
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

        let alice_key = <CASAES256SIV as CASAES256SIVEncryption>::key_from_x25519_shared_secret(
            bob_shared_secret,
        )
        .unwrap();
        let encrypted_bytes = <CASAES256SIV as CASAES256SIVEncryption>::encrypt_plaintext(
            alice_key,
            nonce.clone(),
            file_bytes.clone(),
        )
        .unwrap();

        let bob_key = <CASAES256SIV as CASAES256SIVEncryption>::key_from_x25519_shared_secret(
            alice_shared_secret,
        )
        .unwrap();
        let decrypted_bytes = <CASAES256SIV as CASAES256SIVEncryption>::decrypt_ciphertext(
            bob_key,
            nonce,
            encrypted_bytes,
        )
        .unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }
}
