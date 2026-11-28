//! Tests for issue #120: secret-bearing result structs must not print their
//! secrets through `Debug`, must be explicitly zeroizable, and the functions
//! that now zeroize their intermediate buffers must behave as before.

#[cfg(test)]
mod zeroize_tests {
    use std::fmt::Debug;

    use cas_lib::error::CasError;
    use cas_lib::key_exchange::{cas_key_exchange::CASKeyExchange, x25519::X25519};
    use cas_lib::password_hashers::argon2::CASArgon;
    use cas_lib::pqc::cas_pqc::{
        MlDsaKeyPair, MlKemEncapResult, MlKemKeyPair, MlKemSharedSecret, SlhDsaKeyPair,
    };
    use cas_lib::pqc::{ml_dsa, ml_kem, slh_dsa};
    use cas_lib::signatures::ed25519::{
        ed25519_sign_with_key_pair, ed25519_verify_with_key_pair, ed25519_verify_with_public_key,
        get_ed25519_key_pair,
    };
    use cas_lib::symmetric::aes::{CASAES128, CASAES256};
    use cas_lib::symmetric::aes_gcm_siv::{CASAES128SIV, CASAES256SIV};
    use cas_lib::symmetric::cas_symmetric_encryption::{
        CASAES128Encryption, CASAES128SIVEncryption, CASAES256Encryption, CASAES256SIVEncryption,
    };
    use zeroize::Zeroize;

    /// A secret whose bytes (165 = 0xA5) cannot appear in the other fields used
    /// below, so any leak of it in `Debug` output is detectable.
    const SECRET_BYTE: u8 = 0xA5;

    /// Asserts that neither `{:?}` nor `{:#?}` of `value` reveals `secret`, nor
    /// any run of eight consecutive bytes of `secret_only`, the part of `secret`
    /// that does not also appear in a public field.
    fn assert_redacted<T: Debug>(value: &T, secret: &[u8], secret_only: &[u8]) {
        for out in [format!("{:?}", value), format!("{:#?}", value)] {
            assert!(out.contains("REDACTED"), "secret field not redacted: {out}");
            assert!(
                !out.contains(&format!("{:?}", secret)),
                "Debug output contains the secret bytes: {out}"
            );
            assert!(
                !out.contains(&format!("{:#?}", secret)),
                "Debug output contains the secret bytes: {out}"
            );
            for window in secret_only.windows(8) {
                let compact = window.iter().map(u8::to_string).collect::<Vec<_>>().join(", ");
                let pretty = window.iter().map(u8::to_string).collect::<Vec<_>>().join(",\n");
                assert!(!out.contains(&compact), "Debug output contains secret bytes: {out}");
                assert!(!out.contains(&pretty), "Debug output contains secret bytes: {out}");
            }
        }
    }

    #[test]
    fn debug_redacts_known_secret_bytes() {
        let secret = vec![SECRET_BYTE; 32];
        let public = vec![1u8, 2, 3];

        let kem_pair = MlKemKeyPair { secret_key: secret.clone(), public_key: public.clone() };
        let encap = MlKemEncapResult { ciphertext: public.clone(), shared_secret: secret.clone() };
        let shared = MlKemSharedSecret { shared_secret: secret.clone() };
        let slh = SlhDsaKeyPair { signing_key: secret.clone(), verification_key: public.clone() };
        let mldsa = MlDsaKeyPair { signing_key: secret.clone(), verification_key: public.clone() };

        for out in [
            format!("{:?}", kem_pair),
            format!("{:?}", encap),
            format!("{:?}", shared),
            format!("{:?}", slh),
            format!("{:?}", mldsa),
            format!("{:#?}", kem_pair),
            format!("{:#?}", encap),
            format!("{:#?}", shared),
            format!("{:#?}", slh),
            format!("{:#?}", mldsa),
        ] {
            assert!(!out.contains("165"), "secret byte leaked through Debug: {out}");
            assert!(out.contains("[REDACTED; 32 bytes]"), "missing redaction marker: {out}");
        }

        // Non-secret fields are still printed so the impls stay useful.
        assert_eq!(
            format!("{:?}", kem_pair),
            "MlKemKeyPair { secret_key: [REDACTED; 32 bytes], public_key: [1, 2, 3] }"
        );
        assert_eq!(
            format!("{:?}", encap),
            "MlKemEncapResult { ciphertext: [1, 2, 3], shared_secret: [REDACTED; 32 bytes] }"
        );
        assert_eq!(
            format!("{:?}", shared),
            "MlKemSharedSecret { shared_secret: [REDACTED; 32 bytes] }"
        );
        assert_eq!(
            format!("{:?}", slh),
            "SlhDsaKeyPair { signing_key: [REDACTED; 32 bytes], verification_key: [1, 2, 3] }"
        );
        assert_eq!(
            format!("{:?}", mldsa),
            "MlDsaKeyPair { signing_key: [REDACTED; 32 bytes], verification_key: [1, 2, 3] }"
        );
    }

    #[test]
    fn debug_redacts_generated_ml_kem_secrets() {
        let pair = ml_kem::ml_kem_1024_generate();
        // An ML-KEM-1024 decapsulation key is `dk_pke (1536) || ek || H(ek) || z (32)`;
        // `ek` is the public key, so only `dk_pke` and `z` are secret-only.
        let sk = &pair.secret_key;
        assert_redacted(&pair, sk, &sk[..1536]);
        assert_redacted(&pair, sk, &sk[sk.len() - 32..]);

        let encap = ml_kem::ml_kem_1024_encapsulate(pair.public_key.clone()).unwrap();
        assert_redacted(&encap, &encap.shared_secret, &encap.shared_secret);
    }

    #[test]
    fn debug_redacts_generated_signing_keys() {
        let slh = slh_dsa::generate_signing_and_verification_key();
        // An SLH-DSA-SHAKE-128f signing key is `SK.seed (16) || SK.prf (16) || PK`.
        assert_redacted(&slh, &slh.signing_key, &slh.signing_key[..32]);

        let mldsa = ml_dsa::generate_signing_and_verification_key();
        // An ML-DSA signing key is serialized as its 32-byte seed: all secret.
        assert_redacted(&mldsa, &mldsa.signing_key, &mldsa.signing_key);
    }

    #[test]
    fn pqc_structs_zeroize_all_fields() {
        let mut kem_pair = ml_kem::ml_kem_1024_generate();
        let mut encap = ml_kem::ml_kem_1024_encapsulate(kem_pair.public_key.clone()).unwrap();
        let mut shared = MlKemSharedSecret { shared_secret: encap.shared_secret.clone() };
        let mut slh = slh_dsa::generate_signing_and_verification_key();
        let mut mldsa = ml_dsa::generate_signing_and_verification_key();

        kem_pair.zeroize();
        encap.zeroize();
        shared.zeroize();
        slh.zeroize();
        mldsa.zeroize();

        assert!(kem_pair.secret_key.is_empty() && kem_pair.public_key.is_empty());
        assert!(encap.shared_secret.is_empty() && encap.ciphertext.is_empty());
        assert!(shared.shared_secret.is_empty());
        assert!(slh.signing_key.is_empty() && slh.verification_key.is_empty());
        assert!(mldsa.signing_key.is_empty() && mldsa.verification_key.is_empty());
    }

    /// `EcKeyPair` (ECDSA and ECDH) redacts the private key PEM in `Debug`,
    /// still prints the public key, and zeroizes both fields.
    #[test]
    fn ec_key_pairs_redact_and_zeroize() {
        use cas_lib::ecc::cas_ecdh::{CASEcdh, CASEcdhP521};
        use cas_lib::ecc::cas_ecdsa::{CASEcdsa, CASEcdsaP256};
        use cas_lib::ecc::types::EcKeyPair;

        let known = EcKeyPair { private_key: "PRIVATE-PEM".to_string(), public_key: "PUBLIC-PEM".to_string() };
        assert_eq!(
            format!("{:?}", known),
            "EcKeyPair { private_key: [REDACTED; 11 bytes], public_key: \"PUBLIC-PEM\" }"
        );

        for mut pair in [CASEcdsaP256::generate_key_pair().unwrap(), CASEcdhP521::generate_key_pair().unwrap()] {
            // Exactly the redaction marker and the public key: nothing else of
            // the private key can be in the output. (Its PKCS#8 body shares the
            // algorithm identifier and the embedded public key with the SPKI
            // public key, so a substring search of it would be meaningless.)
            assert_eq!(
                format!("{:?}", pair),
                format!(
                    "EcKeyPair {{ private_key: [REDACTED; {} bytes], public_key: {:?} }}",
                    pair.private_key.len(),
                    pair.public_key
                )
            );
            let pretty = format!("{:#?}", pair);
            assert!(pretty.contains("REDACTED") && !pretty.contains(pair.private_key.as_str()), "{pretty}");

            pair.zeroize();
            assert!(pair.private_key.is_empty() && pair.public_key.is_empty());
        }
    }

    #[test]
    fn hkdf_aes_keys_unchanged_by_zeroization() {
        let shared_secret = vec![7u8; 32];
        let pk_a = vec![1u8; 32];
        let pk_b = vec![2u8; 32];

        let k256 = <CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(shared_secret.clone(), pk_a.clone(), pk_b.clone()).unwrap();
        let k128 = <CASAES128 as CASAES128Encryption>::key_from_x25519_shared_secret(shared_secret.clone(), pk_a.clone(), pk_b.clone()).unwrap();
        let s256 = <CASAES256SIV as CASAES256SIVEncryption>::key_from_x25519_shared_secret(shared_secret.clone(), pk_a.clone(), pk_b.clone()).unwrap();
        let s128 = <CASAES128SIV as CASAES128SIVEncryption>::key_from_x25519_shared_secret(shared_secret.clone(), pk_a.clone(), pk_b.clone()).unwrap();

        assert_eq!(k256.len(), 32);
        assert_eq!(k128.len(), 16);
        assert_eq!(s256.len(), 32);
        assert_eq!(s128.len(), 16);
        for key in [&k256, &k128, &s256, &s128] {
            assert!(key.iter().any(|&b| b != 0), "derived key must not be the zeroed buffer");
        }

        // Deterministic for the same input.
        let again = <CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(shared_secret, pk_a, pk_b).unwrap();
        assert_eq!(k256, again);
    }

    #[test]
    #[allow(deprecated)]
    fn argon2_derived_keys_have_expected_length() {
        let k128 = CASArgon::derive_aes_128_key(b"password".to_vec()).unwrap();
        let k256 = CASArgon::derive_aes_256_key(b"password".to_vec()).unwrap();
        assert_eq!(k128.len(), 16);
        assert_eq!(k256.len(), 32);
        assert!(k128.iter().any(|&b| b != 0));
        assert!(k256.iter().any(|&b| b != 0));

        let salt = CASArgon::generate_salt();
        let k128 = CASArgon::derive_aes_128_key_with_salt(b"password".to_vec(), salt.clone()).unwrap();
        let k256 = CASArgon::derive_aes_256_key_with_salt(b"password".to_vec(), salt).unwrap();
        assert_eq!(k128.len(), 16);
        assert_eq!(k256.len(), 32);
        assert!(k128.iter().any(|&b| b != 0));
        assert!(k256.iter().any(|&b| b != 0));
    }

    #[test]
    fn x25519_diffie_hellman_still_agrees_and_rejects_bad_lengths() {
        let alice = X25519::generate_secret_and_public_key();
        let bob = X25519::generate_secret_and_public_key();
        let ab = X25519::diffie_hellman(alice.secret_key.clone(), bob.public_key.clone()).unwrap();
        let ba = X25519::diffie_hellman(bob.secret_key, alice.public_key.clone()).unwrap();
        assert_eq!(ab, ba);

        for bad in [Vec::new(), vec![1u8; 31], vec![1u8; 33]] {
            assert_eq!(X25519::diffie_hellman(bad, alice.public_key.clone()), Err(CasError::InvalidKey));
        }
    }

    #[test]
    fn ed25519_key_pair_paths_still_work_and_reject_bad_lengths() {
        let pair = get_ed25519_key_pair();
        let message = b"zeroize".to_vec();
        let signed = ed25519_sign_with_key_pair(pair.key_pair.clone(), message.clone()).unwrap();
        assert_eq!(signed.public_key, pair.public_key);
        assert!(ed25519_verify_with_key_pair(pair.key_pair.clone(), signed.signature.clone(), message.clone()).unwrap());
        assert!(ed25519_verify_with_public_key(pair.public_key, signed.signature.clone(), message.clone()).unwrap());

        for bad in [Vec::new(), vec![1u8; 31], vec![1u8; 33]] {
            assert!(matches!(ed25519_sign_with_key_pair(bad.clone(), message.clone()), Err(CasError::InvalidKey)));
            assert_eq!(
                ed25519_verify_with_key_pair(bad, signed.signature.clone(), message.clone()),
                Err(CasError::InvalidKey)
            );
        }
    }
}
