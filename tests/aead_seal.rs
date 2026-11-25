//! Tests for the nonce-managing `CASAeadSeal::seal` / `open` helpers and the
//! AAD variants of every AEAD (issue #117).

use cas_lib::error::CasError;
use cas_lib::sponges::{
    ascon_aead::AsconAead,
    cas_ascon_aead::{CASAsconAead, CASAsconAeadAad},
};
use cas_lib::symmetric::{
    aes::{CASAES128, CASAES256},
    aes_gcm_siv::{CASAES128SIV, CASAES256SIV},
    cas_symmetric_encryption::{
        CASAES128AadEncryption, CASAES128Encryption, CASAES128SIVAadEncryption,
        CASAES128SIVEncryption, CASAES256AadEncryption, CASAES256Encryption,
        CASAES256SIVAadEncryption, CASAES256SIVEncryption, CASAeadSeal,
        Chacha20Poly1305AadEncryption, Chacha20Poly1305Encryption,
    },
    chacha20poly1305::CASChacha20Poly1305,
};

const TAG_LEN: usize = 16;

/// One AEAD under test: its key generator and its caller-nonce AAD API, used
/// to check that `seal` output really is `nonce || ciphertext || tag`.
struct Aead {
    name: &'static str,
    generate_key: fn() -> Vec<u8>,
    generate_nonce: fn() -> Vec<u8>,
    encrypt_with_aad: fn(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) -> cas_lib::error::CasResult<Vec<u8>>,
    decrypt_with_aad: fn(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) -> cas_lib::error::CasResult<Vec<u8>>,
    seal: fn(Vec<u8>, Vec<u8>, Option<Vec<u8>>) -> cas_lib::error::CasResult<Vec<u8>>,
    open: fn(Vec<u8>, Vec<u8>, Option<Vec<u8>>) -> cas_lib::error::CasResult<Vec<u8>>,
    nonce_len: usize,
}

fn aead<T: CASAeadSeal>(
    name: &'static str,
    generate_key: fn() -> Vec<u8>,
    generate_nonce: fn() -> Vec<u8>,
    encrypt_with_aad: fn(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) -> cas_lib::error::CasResult<Vec<u8>>,
    decrypt_with_aad: fn(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) -> cas_lib::error::CasResult<Vec<u8>>,
) -> Aead {
    Aead {
        name,
        generate_key,
        generate_nonce,
        encrypt_with_aad,
        decrypt_with_aad,
        seal: T::seal,
        open: T::open,
        nonce_len: T::NONCE_LEN,
    }
}

fn all_aeads() -> Vec<Aead> {
    vec![
        aead::<CASAES128>(
            "AES-128-GCM",
            <CASAES128 as CASAES128Encryption>::generate_key,
            <CASAES128 as CASAES128Encryption>::generate_nonce,
            <CASAES128 as CASAES128AadEncryption>::encrypt_plaintext_with_aad,
            <CASAES128 as CASAES128AadEncryption>::decrypt_ciphertext_with_aad,
        ),
        aead::<CASAES256>(
            "AES-256-GCM",
            <CASAES256 as CASAES256Encryption>::generate_key,
            <CASAES256 as CASAES256Encryption>::generate_nonce,
            <CASAES256 as CASAES256AadEncryption>::encrypt_plaintext_with_aad,
            <CASAES256 as CASAES256AadEncryption>::decrypt_ciphertext_with_aad,
        ),
        aead::<CASAES128SIV>(
            "AES-128-GCM-SIV",
            <CASAES128SIV as CASAES128SIVEncryption>::generate_key,
            <CASAES128SIV as CASAES128SIVEncryption>::generate_nonce,
            <CASAES128SIV as CASAES128SIVAadEncryption>::encrypt_plaintext_with_aad,
            <CASAES128SIV as CASAES128SIVAadEncryption>::decrypt_ciphertext_with_aad,
        ),
        aead::<CASAES256SIV>(
            "AES-256-GCM-SIV",
            <CASAES256SIV as CASAES256SIVEncryption>::generate_key,
            <CASAES256SIV as CASAES256SIVEncryption>::generate_nonce,
            <CASAES256SIV as CASAES256SIVAadEncryption>::encrypt_plaintext_with_aad,
            <CASAES256SIV as CASAES256SIVAadEncryption>::decrypt_ciphertext_with_aad,
        ),
        aead::<CASChacha20Poly1305>(
            "ChaCha20-Poly1305",
            <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_key,
            <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_nonce,
            <CASChacha20Poly1305 as Chacha20Poly1305AadEncryption>::encrypt_plaintext_with_aad,
            <CASChacha20Poly1305 as Chacha20Poly1305AadEncryption>::decrypt_ciphertext_with_aad,
        ),
        aead::<AsconAead>(
            "Ascon-AEAD128",
            <AsconAead as CASAsconAead>::generate_key,
            <AsconAead as CASAsconAead>::generate_nonce,
            <AsconAead as CASAsconAeadAad>::encrypt_plaintext_with_aad,
            <AsconAead as CASAsconAeadAad>::decrypt_ciphertext_with_aad,
        ),
    ]
}

fn plaintext() -> Vec<u8> {
    std::fs::read("tests/test.docx").unwrap()
}

#[test]
fn nonce_len_matches_generate_nonce() {
    for a in all_aeads() {
        assert_eq!((a.generate_nonce)().len(), a.nonce_len, "{}", a.name);
    }
}

#[test]
fn seal_open_round_trip_without_aad() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let pt = plaintext();
        let sealed = (a.seal)(key.clone(), pt.clone(), None).unwrap();
        assert_eq!(sealed.len(), a.nonce_len + pt.len() + TAG_LEN, "{}", a.name);
        assert_eq!((a.open)(key.clone(), sealed.clone(), None).unwrap(), pt, "{}", a.name);
        // `None` and empty AAD are the same thing.
        assert_eq!((a.open)(key, sealed, Some(Vec::new())).unwrap(), pt, "{}", a.name);
    }
}

#[test]
fn seal_open_round_trip_with_aad() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let pt = plaintext();
        let aad = b"record-id:42".to_vec();
        let sealed = (a.seal)(key.clone(), pt.clone(), Some(aad.clone())).unwrap();
        assert_eq!((a.open)(key, sealed, Some(aad)).unwrap(), pt, "{}", a.name);
    }
}

#[test]
fn seal_open_round_trip_empty_plaintext() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let sealed = (a.seal)(key.clone(), Vec::new(), None).unwrap();
        assert_eq!(sealed.len(), a.nonce_len + TAG_LEN, "{}", a.name);
        assert_eq!((a.open)(key, sealed, None).unwrap(), Vec::<u8>::new(), "{}", a.name);
    }
}

/// The sealed blob is `nonce || ciphertext || tag`, so the caller-nonce API
/// must decrypt it when given the prefix as the nonce, and must produce the
/// same bytes when encrypting under that nonce.
#[test]
fn seal_output_is_nonce_then_ciphertext() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let pt = b"layout check".to_vec();
        let aad = b"header".to_vec();
        let sealed = (a.seal)(key.clone(), pt.clone(), Some(aad.clone())).unwrap();
        let (nonce, ciphertext) = sealed.split_at(a.nonce_len);

        let decrypted =
            (a.decrypt_with_aad)(key.clone(), nonce.to_vec(), ciphertext.to_vec(), aad.clone())
                .unwrap();
        assert_eq!(decrypted, pt, "{}", a.name);

        let reencrypted = (a.encrypt_with_aad)(key, nonce.to_vec(), pt, aad).unwrap();
        assert_eq!(reencrypted, ciphertext, "{}", a.name);
    }
}

#[test]
fn two_seals_use_different_nonces() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let pt = b"same message".to_vec();
        let first = (a.seal)(key.clone(), pt.clone(), None).unwrap();
        let second = (a.seal)(key, pt, None).unwrap();
        assert_ne!(first[..a.nonce_len], second[..a.nonce_len], "{}: nonce repeated", a.name);
        assert_ne!(first, second, "{}: identical sealed output", a.name);
    }
}

#[test]
fn open_rejects_tampered_aad() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let pt = b"bound to its header".to_vec();
        let aad = b"header-v1".to_vec();
        let sealed = (a.seal)(key.clone(), pt, Some(aad)).unwrap();

        let wrong = (a.open)(key.clone(), sealed.clone(), Some(b"header-v2".to_vec()));
        assert_eq!(wrong, Err(CasError::DecryptionFailed), "{}: wrong AAD", a.name);

        let missing = (a.open)(key, sealed, None);
        assert_eq!(missing, Err(CasError::DecryptionFailed), "{}: missing AAD", a.name);
    }
}

#[test]
fn open_rejects_aad_added_after_sealing() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let sealed = (a.seal)(key.clone(), b"no aad".to_vec(), None).unwrap();
        let result = (a.open)(key, sealed, Some(b"extra".to_vec()));
        assert_eq!(result, Err(CasError::DecryptionFailed), "{}", a.name);
    }
}

#[test]
fn open_rejects_tampered_blob() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let sealed = (a.seal)(key.clone(), b"do not modify".to_vec(), None).unwrap();
        // Flip a bit in the nonce, the ciphertext body and the tag in turn.
        for index in [0, a.nonce_len, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 0x01;
            let result = (a.open)(key.clone(), tampered, None);
            assert_eq!(result, Err(CasError::DecryptionFailed), "{}: byte {index}", a.name);
        }
    }
}

#[test]
fn open_rejects_wrong_key() {
    for a in all_aeads() {
        let sealed = (a.seal)((a.generate_key)(), b"secret".to_vec(), None).unwrap();
        let result = (a.open)((a.generate_key)(), sealed, None);
        assert_eq!(result, Err(CasError::DecryptionFailed), "{}", a.name);
    }
}

#[test]
fn open_rejects_truncated_blob_without_panicking() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let sealed = (a.seal)(key.clone(), b"truncate me".to_vec(), None).unwrap();

        // Anything shorter than nonce + tag cannot be a sealed message.
        for len in [0, 1, a.nonce_len - 1, a.nonce_len, a.nonce_len + TAG_LEN - 1] {
            let result = std::panic::catch_unwind(|| (a.open)(key.clone(), sealed[..len].to_vec(), None));
            let result = result.unwrap_or_else(|_| panic!("{}: open panicked on {len} bytes", a.name));
            assert_eq!(result, Err(CasError::InvalidInput), "{}: {len} bytes", a.name);
        }

        // Long enough to parse, but the tag no longer matches.
        let short = sealed[..sealed.len() - 1].to_vec();
        assert_eq!((a.open)(key, short, None), Err(CasError::DecryptionFailed), "{}", a.name);
    }
}

#[test]
fn seal_and_open_reject_bad_key_length() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let sealed = (a.seal)(key.clone(), b"x".to_vec(), None).unwrap();
        for bad_len in [0, key.len() - 1, key.len() + 1] {
            let bad_key = vec![7u8; bad_len];
            assert_eq!((a.seal)(bad_key.clone(), b"x".to_vec(), None), Err(CasError::InvalidKey), "{}", a.name);
            assert_eq!((a.open)(bad_key, sealed.clone(), None), Err(CasError::InvalidKey), "{}", a.name);
        }
    }
}

#[test]
fn aad_api_round_trip() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let nonce = (a.generate_nonce)();
        let pt = plaintext();
        let aad = b"file-id:1234".to_vec();
        let ct = (a.encrypt_with_aad)(key.clone(), nonce.clone(), pt.clone(), aad.clone()).unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_LEN, "{}", a.name);
        assert_eq!((a.decrypt_with_aad)(key, nonce, ct, aad).unwrap(), pt, "{}", a.name);
    }
}

#[test]
fn aad_api_rejects_tampered_aad() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let nonce = (a.generate_nonce)();
        let aad = b"file-id:1234".to_vec();
        let ct = (a.encrypt_with_aad)(key.clone(), nonce.clone(), b"msg".to_vec(), aad).unwrap();

        let wrong = (a.decrypt_with_aad)(key.clone(), nonce.clone(), ct.clone(), b"file-id:1235".to_vec());
        assert_eq!(wrong, Err(CasError::DecryptionFailed), "{}: wrong AAD", a.name);

        let empty = (a.decrypt_with_aad)(key, nonce, ct, Vec::new());
        assert_eq!(empty, Err(CasError::DecryptionFailed), "{}: empty AAD", a.name);
    }
}

#[test]
fn aad_api_rejects_bad_key_and_nonce_lengths() {
    for a in all_aeads() {
        let key = (a.generate_key)();
        let nonce = (a.generate_nonce)();
        let short_nonce = nonce[..nonce.len() - 1].to_vec();
        assert_eq!(
            (a.encrypt_with_aad)(key.clone(), short_nonce.clone(), b"m".to_vec(), Vec::new()),
            Err(CasError::InvalidNonce),
            "{}",
            a.name
        );
        assert_eq!(
            (a.decrypt_with_aad)(key.clone(), short_nonce, vec![0u8; TAG_LEN], Vec::new()),
            Err(CasError::InvalidNonce),
            "{}",
            a.name
        );
        let short_key = key[..key.len() - 1].to_vec();
        assert_eq!(
            (a.encrypt_with_aad)(short_key, nonce, b"m".to_vec(), Vec::new()),
            Err(CasError::InvalidKey),
            "{}",
            a.name
        );
    }
}

/// With empty AAD, the AAD API must match the original API byte for byte.
#[test]
fn empty_aad_matches_non_aad_api() {
    let pt = b"compat".to_vec();

    let key = <CASAES128SIV as CASAES128SIVEncryption>::generate_key();
    let nonce = <CASAES128SIV as CASAES128SIVEncryption>::generate_nonce();
    assert_eq!(
        CASAES128SIV::encrypt_plaintext_with_aad(key.clone(), nonce.clone(), pt.clone(), Vec::new()),
        <CASAES128SIV as CASAES128SIVEncryption>::encrypt_plaintext(key, nonce, pt.clone())
    );

    let key = <CASAES256SIV as CASAES256SIVEncryption>::generate_key();
    let nonce = <CASAES256SIV as CASAES256SIVEncryption>::generate_nonce();
    assert_eq!(
        CASAES256SIV::encrypt_plaintext_with_aad(key.clone(), nonce.clone(), pt.clone(), Vec::new()),
        <CASAES256SIV as CASAES256SIVEncryption>::encrypt_plaintext(key, nonce, pt.clone())
    );

    let key = <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_key();
    let nonce = <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_nonce();
    assert_eq!(
        CASChacha20Poly1305::encrypt_plaintext_with_aad(key.clone(), nonce.clone(), pt.clone(), Vec::new()),
        <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::encrypt_plaintext(key, nonce, pt.clone())
    );

    let key = <AsconAead as CASAsconAead>::generate_key();
    let nonce = <AsconAead as CASAsconAead>::generate_nonce();
    assert_eq!(
        AsconAead::encrypt_plaintext_with_aad(key.clone(), nonce.clone(), pt.clone(), Vec::new()),
        AsconAead::encrypt(key, nonce, pt)
    );
}
