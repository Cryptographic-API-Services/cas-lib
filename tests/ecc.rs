//! Tests for `cas_lib::ecc`: ECDSA and ECDH over P-256, P-384, P-521 and
//! secp256k1.
//!
//! Round trips and API behaviour, plus known-answer tests from the files in
//! `tests/data/ecc/` (see its README): NIST CAVP FIPS 186-4 `SigVer` and `PKV`,
//! NIST CAVP ECC CDH, and RFC 6979 deterministic signatures. Wycheproof
//! vectors are in `tests/wycheproof.rs`.

mod common;

use std::collections::HashMap;

use cas_lib::ecc::cas_ecdh::{CASEcdh, CASEcdhP256, CASEcdhP384, CASEcdhP521, CASEcdhSecp256k1};
use cas_lib::ecc::cas_ecdsa::{CASEcdsa, CASEcdsaP256, CASEcdsaP384, CASEcdsaP521, CASEcdsaSecp256k1};
use cas_lib::error::CasError;
use common::ec::{decode_hex, left_pad, Curve};

const ALL_CURVES: [Curve; 4] = [Curve::P256, Curve::P384, Curve::P521, Curve::Secp256k1];

/// Dispatches to the `CASEcdsa` / `CASEcdh` implementation for a curve, so a
/// test can loop over every curve.
struct Ops {
    generate: fn() -> cas_lib::error::CasResult<cas_lib::ecc::types::EcKeyPair>,
    sign: fn(String, Vec<u8>) -> cas_lib::error::CasResult<Vec<u8>>,
    sign_der: fn(String, Vec<u8>) -> cas_lib::error::CasResult<Vec<u8>>,
    verify: fn(String, Vec<u8>, Vec<u8>) -> cas_lib::error::CasResult<bool>,
    verify_der: fn(String, Vec<u8>, Vec<u8>) -> cas_lib::error::CasResult<bool>,
    generate_ecdh: fn() -> cas_lib::error::CasResult<cas_lib::ecc::types::EcKeyPair>,
    diffie_hellman: fn(String, String) -> cas_lib::error::CasResult<Vec<u8>>,
}

fn ops_for<E: CASEcdsa, H: CASEcdh>() -> Ops {
    Ops {
        generate: E::generate_key_pair,
        sign: E::sign,
        sign_der: E::sign_der,
        verify: E::verify,
        verify_der: E::verify_der,
        generate_ecdh: H::generate_key_pair,
        diffie_hellman: H::diffie_hellman,
    }
}

fn ops(curve: Curve) -> Ops {
    match curve {
        Curve::P256 => ops_for::<CASEcdsaP256, CASEcdhP256>(),
        Curve::P384 => ops_for::<CASEcdsaP384, CASEcdhP384>(),
        Curve::P521 => ops_for::<CASEcdsaP521, CASEcdhP521>(),
        Curve::Secp256k1 => ops_for::<CASEcdsaSecp256k1, CASEcdhSecp256k1>(),
    }
}

/// An Ed25519 SPKI public key (RFC 8410, section 10.1): valid SPKI, wrong algorithm.
const ED25519_SPKI_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n";

mod round_trips {
    use super::*;

    #[test]
    fn generated_keys_are_pkcs8_and_spki_pem() {
        for curve in ALL_CURVES {
            for generate in [ops(curve).generate, ops(curve).generate_ecdh] {
                let pair = generate().unwrap();
                assert!(pair.private_key.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{curve:?}");
                assert!(pair.private_key.ends_with("-----END PRIVATE KEY-----\n"), "{curve:?}");
                assert!(pair.public_key.starts_with("-----BEGIN PUBLIC KEY-----\n"), "{curve:?}");
                assert!(pair.public_key.ends_with("-----END PUBLIC KEY-----\n"), "{curve:?}");
            }
            let a = (ops(curve).generate)().unwrap();
            let b = (ops(curve).generate)().unwrap();
            assert_ne!(a.private_key, b.private_key, "{curve:?}: two generated keys are equal");
        }
    }

    /// The test helper that builds SPKI PEMs from raw coordinates must produce
    /// exactly what the library produces, or the KAT tests would test nothing.
    #[test]
    fn spki_builder_matches_generated_public_keys() {
        use elliptic_curve::pkcs8::DecodePublicKey;
        use elliptic_curve::sec1::ToSec1Point;

        fn point<C>(pem: &str) -> Vec<u8>
        where
            C: elliptic_curve::CurveArithmetic + elliptic_curve::pkcs8::AssociatedOid,
            elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromSec1Point<C> + ToSec1Point<C>,
            elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
        {
            let key = elliptic_curve::PublicKey::<C>::from_public_key_pem(pem).unwrap();
            key.to_sec1_point(false).as_bytes().to_vec()
        }

        for curve in ALL_CURVES {
            let pair = (ops(curve).generate)().unwrap();
            let sec1 = match curve {
                Curve::P256 => point::<p256::NistP256>(&pair.public_key),
                Curve::P384 => point::<p384::NistP384>(&pair.public_key),
                Curve::P521 => point::<p521::NistP521>(&pair.public_key),
                Curve::Secp256k1 => point::<k256::Secp256k1>(&pair.public_key),
            };
            let len = curve.field_len();
            assert_eq!(sec1.len(), 1 + 2 * len);
            let rebuilt = curve.public_key_pem(&sec1[1..1 + len], &sec1[1 + len..]).unwrap();
            assert_eq!(rebuilt, pair.public_key, "{curve:?}");
        }
    }

    #[test]
    fn sign_and_verify_both_encodings() {
        for curve in ALL_CURVES {
            let ops = ops(curve);
            let pair = (ops.generate)().unwrap();
            let message = b"message to sign".to_vec();

            let signature = (ops.sign)(pair.private_key.clone(), message.clone()).unwrap();
            assert_eq!(signature.len(), 2 * curve.field_len(), "{curve:?}: P1363 length");
            assert!((ops.verify)(pair.public_key.clone(), message.clone(), signature.clone()).unwrap());

            let der = (ops.sign_der)(pair.private_key.clone(), message.clone()).unwrap();
            assert_eq!(der[0], 0x30, "{curve:?}: DER signature is a SEQUENCE");
            assert!((ops.verify_der)(pair.public_key.clone(), message.clone(), der.clone()).unwrap());
            // Both encodings carry the same deterministic (r, s).
            assert_eq!(curve.p1363_to_der(&signature).unwrap(), der, "{curve:?}");

            // Tampered message, tampered signature.
            assert!(!(ops.verify)(pair.public_key.clone(), b"tampered".to_vec(), signature.clone()).unwrap());
            assert!(!(ops.verify_der)(pair.public_key.clone(), b"tampered".to_vec(), der.clone()).unwrap());
            let mut flipped = signature.clone();
            flipped[5] ^= 1;
            assert!(!(ops.verify)(pair.public_key.clone(), message.clone(), flipped).unwrap());

            // Another key's signature.
            let other = (ops.generate)().unwrap();
            assert!(!(ops.verify)(other.public_key.clone(), message.clone(), signature.clone()).unwrap());
        }
    }

    #[test]
    fn signing_is_deterministic() {
        for curve in ALL_CURVES {
            let ops = ops(curve);
            let pair = (ops.generate)().unwrap();
            let message = b"same message".to_vec();
            let a = (ops.sign)(pair.private_key.clone(), message.clone()).unwrap();
            let b = (ops.sign)(pair.private_key.clone(), message.clone()).unwrap();
            assert_eq!(a, b, "{curve:?}");
            let a = (ops.sign_der)(pair.private_key.clone(), message.clone()).unwrap();
            let b = (ops.sign_der)(pair.private_key.clone(), message).unwrap();
            assert_eq!(a, b, "{curve:?}");
        }
    }

    #[test]
    fn malformed_signatures_verify_as_false() {
        for curve in ALL_CURVES {
            let ops = ops(curve);
            let pair = (ops.generate)().unwrap();
            let message = b"message".to_vec();
            let signature = (ops.sign)(pair.private_key.clone(), message.clone()).unwrap();
            let der = (ops.sign_der)(pair.private_key.clone(), message.clone()).unwrap();
            let len = curve.field_len();

            let malformed: Vec<Vec<u8>> = vec![
                Vec::new(),
                signature[..signature.len() - 1].to_vec(),
                [signature.as_slice(), &[0]].concat(),
                vec![0u8; 2 * len],                                  // r = s = 0
                [vec![0u8; len], signature[len..].to_vec()].concat(), // r = 0
                [signature[..len].to_vec(), curve.order()].concat(),  // s = n
                der.clone(),                                          // DER where P1363 is expected
            ];
            for (i, bad) in malformed.into_iter().enumerate() {
                assert_eq!((ops.verify)(pair.public_key.clone(), message.clone(), bad), Ok(false), "{curve:?} P1363 case {i}");
            }

            let mut trailing = der.clone();
            trailing.push(0);
            let malformed_der: Vec<Vec<u8>> = vec![Vec::new(), der[..der.len() - 1].to_vec(), trailing, signature.clone()];
            for (i, bad) in malformed_der.into_iter().enumerate() {
                assert_eq!((ops.verify_der)(pair.public_key.clone(), message.clone(), bad), Ok(false), "{curve:?} DER case {i}");
            }
        }
    }

    #[test]
    fn ecdh_parties_agree() {
        for curve in ALL_CURVES {
            let ops = ops(curve);
            let alice = (ops.generate_ecdh)().unwrap();
            let bob = (ops.generate_ecdh)().unwrap();
            let ab = (ops.diffie_hellman)(alice.private_key.clone(), bob.public_key.clone()).unwrap();
            let ba = (ops.diffie_hellman)(bob.private_key.clone(), alice.public_key.clone()).unwrap();
            assert_eq!(ab, ba, "{curve:?}");
            assert_eq!(ab.len(), curve.field_len(), "{curve:?}: shared secret length");

            let carol = (ops.generate_ecdh)().unwrap();
            let ac = (ops.diffie_hellman)(alice.private_key.clone(), carol.public_key.clone()).unwrap();
            assert_ne!(ab, ac, "{curve:?}");
        }
    }

    /// A SEC1 `EC PRIVATE KEY` PEM works like its PKCS#8 form.
    #[test]
    fn sec1_private_keys_are_accepted() {
        use elliptic_curve::pkcs8::{DecodePrivateKey, LineEnding};

        fn to_sec1<C>(pkcs8: &str) -> String
        where
            C: elliptic_curve::CurveArithmetic + elliptic_curve::pkcs8::AssociatedOid + elliptic_curve::sec1::ValidatePublicKey,
            elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromSec1Point<C> + elliptic_curve::sec1::ToSec1Point<C>,
            elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
        {
            let key = elliptic_curve::SecretKey::<C>::from_pkcs8_pem(pkcs8).unwrap();
            key.to_sec1_pem(LineEnding::LF).unwrap().to_string()
        }

        for curve in ALL_CURVES {
            let ops = ops(curve);
            let pair = (ops.generate)().unwrap();
            let sec1 = match curve {
                Curve::P256 => to_sec1::<p256::NistP256>(&pair.private_key),
                Curve::P384 => to_sec1::<p384::NistP384>(&pair.private_key),
                Curve::P521 => to_sec1::<p521::NistP521>(&pair.private_key),
                Curve::Secp256k1 => to_sec1::<k256::Secp256k1>(&pair.private_key),
            };
            assert!(sec1.starts_with("-----BEGIN EC PRIVATE KEY-----\n"));
            let message = b"sec1".to_vec();
            assert_eq!(
                (ops.sign)(sec1.clone(), message.clone()).unwrap(),
                (ops.sign)(pair.private_key.clone(), message).unwrap(),
                "{curve:?}"
            );
            let peer = (ops.generate_ecdh)().unwrap();
            assert_eq!(
                (ops.diffie_hellman)(sec1, peer.public_key.clone()).unwrap(),
                (ops.diffie_hellman)(pair.private_key, peer.public_key).unwrap(),
                "{curve:?}"
            );
        }
    }
}

mod key_errors {
    use super::*;

    #[test]
    fn keys_for_another_curve_are_rejected() {
        for key_curve in ALL_CURVES {
            let pair = (ops(key_curve).generate)().unwrap();
            for curve in ALL_CURVES.into_iter().filter(|&c| c != key_curve) {
                let ops = ops(curve);
                let own = (ops.generate)().unwrap();
                let message = b"m".to_vec();
                let signature = (ops.sign)(own.private_key.clone(), message.clone()).unwrap();
                let what = format!("{key_curve:?} key used as {curve:?}");
                assert_eq!((ops.sign)(pair.private_key.clone(), message.clone()), Err(CasError::InvalidPemKey), "{what}");
                assert_eq!((ops.sign_der)(pair.private_key.clone(), message.clone()), Err(CasError::InvalidPemKey), "{what}");
                assert_eq!((ops.verify)(pair.public_key.clone(), message.clone(), signature.clone()), Err(CasError::InvalidPemKey), "{what}");
                assert_eq!((ops.verify_der)(pair.public_key.clone(), message.clone(), signature), Err(CasError::InvalidPemKey), "{what}");
                assert_eq!((ops.diffie_hellman)(pair.private_key.clone(), own.public_key.clone()), Err(CasError::InvalidPemKey), "{what}");
                assert_eq!((ops.diffie_hellman)(own.private_key.clone(), pair.public_key.clone()), Err(CasError::InvalidPemKey), "{what}");
            }
        }
    }

    #[test]
    fn malformed_keys_are_rejected() {
        for curve in ALL_CURVES {
            let ops = ops(curve);
            let pair = (ops.generate)().unwrap();
            let message = b"m".to_vec();
            let signature = (ops.sign)(pair.private_key.clone(), message.clone()).unwrap();

            // Wrong kind of key in each slot, plus garbage.
            let bad_private = [String::new(), "not a pem".to_string(), pair.public_key.clone(), ED25519_SPKI_PEM.to_string()];
            for key in bad_private {
                assert_eq!((ops.sign)(key.clone(), message.clone()), Err(CasError::InvalidPemKey), "{curve:?}");
                assert_eq!((ops.diffie_hellman)(key, pair.public_key.clone()), Err(CasError::InvalidPemKey), "{curve:?}");
            }
            let bad_public = [String::new(), "not a pem".to_string(), pair.private_key.clone(), ED25519_SPKI_PEM.to_string()];
            for key in bad_public {
                assert_eq!((ops.verify)(key.clone(), message.clone(), signature.clone()), Err(CasError::InvalidPemKey), "{curve:?}");
                assert_eq!((ops.diffie_hellman)(pair.private_key.clone(), key), Err(CasError::InvalidPemKey), "{curve:?}");
            }

            // A point off the curve: the generator's x with y + 1.
            let len = curve.field_len();
            let not_on_curve = {
                let good = (ops.generate)().unwrap();
                let sec1 = spki_point(&good.public_key, len);
                let (x, y) = sec1.split_at(len);
                let mut y = y.to_vec();
                *y.last_mut().unwrap() ^= 1;
                curve.public_key_pem(x, &y).unwrap()
            };
            assert_eq!((ops.verify)(not_on_curve.clone(), message.clone(), signature.clone()), Err(CasError::InvalidPemKey), "{curve:?}");
            assert_eq!((ops.diffie_hellman)(pair.private_key.clone(), not_on_curve), Err(CasError::InvalidPemKey), "{curve:?}");

            // The point at infinity can't be encoded as an uncompressed point;
            // (0, 0) is the usual stand-in and is not on any of these curves.
            let zero = curve.public_key_pem(&vec![0; len], &vec![0; len]).unwrap();
            assert_eq!((ops.diffie_hellman)(pair.private_key.clone(), zero), Err(CasError::InvalidPemKey), "{curve:?}");
        }
    }

    /// The `x || y` bytes of a generated SPKI PEM public key.
    fn spki_point(pem: &str, field_len: usize) -> Vec<u8> {
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = base64_decode(&b64);
        der[der.len() - 2 * field_len..].to_vec()
    }

    fn base64_decode(input: &str) -> Vec<u8> {
        const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0;
        for c in input.bytes().filter(|&c| c != b'=') {
            buf = buf << 6 | ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        out
    }
}

mod secp256k1_high_s {
    use super::*;

    #[test]
    fn signing_always_produces_low_s() {
        let pair = CASEcdsaSecp256k1::generate_key_pair().unwrap();
        for i in 0..32u8 {
            let message = vec![i; 10];
            let signature = CASEcdsaSecp256k1::sign(pair.private_key.clone(), message.clone()).unwrap();
            assert!(CASEcdsaSecp256k1::verify_low_s(pair.public_key.clone(), message.clone(), signature).unwrap());
            let der = CASEcdsaSecp256k1::sign_der(pair.private_key.clone(), message.clone()).unwrap();
            assert!(CASEcdsaSecp256k1::verify_der_low_s(pair.public_key.clone(), message, der).unwrap());
        }
    }

    #[test]
    fn verify_accepts_and_low_s_variants_reject_high_s() {
        let curve = Curve::Secp256k1;
        let pair = CASEcdsaSecp256k1::generate_key_pair().unwrap();
        let message = b"malleable".to_vec();
        let low = CASEcdsaSecp256k1::sign(pair.private_key.clone(), message.clone()).unwrap();
        let high = curve.negate_s(&low);
        let high_der = curve.p1363_to_der(&high).unwrap();
        let pk = || pair.public_key.clone();

        assert!(CASEcdsaSecp256k1::verify(pk(), message.clone(), high.clone()).unwrap());
        assert!(CASEcdsaSecp256k1::verify_der(pk(), message.clone(), high_der.clone()).unwrap());
        assert!(!CASEcdsaSecp256k1::verify_low_s(pk(), message.clone(), high).unwrap());
        assert!(!CASEcdsaSecp256k1::verify_der_low_s(pk(), message.clone(), high_der).unwrap());

        // The low-S variants still reject invalid signatures and bad keys.
        assert!(!CASEcdsaSecp256k1::verify_low_s(pk(), b"other".to_vec(), low.clone()).unwrap());
        assert_eq!(CASEcdsaSecp256k1::verify_low_s(String::new(), message, low), Err(CasError::InvalidPemKey));
    }

    /// The NIST curves follow standard ECDSA and accept both forms.
    #[test]
    fn nist_curves_accept_high_s() {
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let ops = ops(curve);
            let pair = (ops.generate)().unwrap();
            let message = b"either form".to_vec();
            let signature = (ops.sign)(pair.private_key.clone(), message.clone()).unwrap();
            let negated = curve.negate_s(&signature);
            assert!((ops.verify)(pair.public_key.clone(), message.clone(), negated.clone()).unwrap(), "{curve:?}");
            let der = curve.p1363_to_der(&negated).unwrap();
            assert!((ops.verify_der)(pair.public_key.clone(), message, der).unwrap(), "{curve:?}");
        }
    }
}

/// Known-answer tests from `tests/data/ecc/` (see its README).
mod known_answers {
    use super::*;

    fn data(file: &str) -> String {
        let path = format!("{}/tests/data/ecc/{file}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path}: {err}"))
    }

    /// Parses a NIST CAVP response file into `(section, fields)` records. A
    /// record ends at the `end_key` line (`Result` or `ZIUT`).
    fn cavp_records(file: &str, end_key: &str) -> Vec<(String, HashMap<String, String>)> {
        let mut records = Vec::new();
        let mut section = String::new();
        let mut fields = HashMap::new();
        for line in data(file).lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.to_string();
                continue;
            }
            let (key, value) = line.split_once(" = ").unwrap_or_else(|| panic!("{file}: unexpected line {line:?}"));
            fields.insert(key.to_string(), value.to_string());
            if key == end_key {
                records.push((section.clone(), std::mem::take(&mut fields)));
            }
        }
        records
    }

    fn curve_named(name: &str) -> Curve {
        match name {
            "P-256" => Curve::P256,
            "P-384" => Curve::P384,
            "P-521" => Curve::P521,
            other => panic!("unexpected curve {other}"),
        }
    }

    fn hex(fields: &HashMap<String, String>, key: &str) -> Vec<u8> {
        decode_hex(fields.get(key).unwrap_or_else(|| panic!("missing {key}")))
    }

    /// FIPS 186-4 SigVer: `Result = P` must verify, `Result = F (...)` must not
    /// (or, for a changed `Q` that is not a valid key, must be rejected).
    #[test]
    fn nist_sigver() {
        let records = cavp_records("SigVer.rsp", "Result");
        assert_eq!(records.len(), 45);
        let (mut pass, mut fail) = (0, 0);
        for (section, fields) in &records {
            let curve = curve_named(section.split(',').next().unwrap());
            let ops = ops(curve);
            let len = curve.field_len();
            let public_key = curve.public_key_pem(&hex(fields, "Qx"), &hex(fields, "Qy")).unwrap();
            let signature = [left_pad(&hex(fields, "R"), len).unwrap(), left_pad(&hex(fields, "S"), len).unwrap()].concat();
            let message = hex(fields, "Msg");
            let expected = fields["Result"].starts_with('P');
            let what = format!("[{section}] Msg = {}", &fields["Msg"][..16]);

            let verified = (ops.verify)(public_key.clone(), message.clone(), signature.clone());
            if expected {
                pass += 1;
                assert_eq!(verified, Ok(true), "{what}");
                let der = curve.p1363_to_der(&signature).unwrap();
                assert_eq!((ops.verify_der)(public_key, message, der), Ok(true), "{what}");
            } else {
                fail += 1;
                assert!(matches!(verified, Ok(false) | Err(CasError::InvalidPemKey)), "{what}: {verified:?}");
            }
        }
        assert_eq!((pass, fail), (9, 36));
    }

    /// FIPS 186-4 PKV (public key validation): `P` keys must be usable, `F` keys
    /// (off the curve, or a coordinate out of range) must be rejected.
    #[test]
    fn nist_public_key_validation() {
        let records = cavp_records("PKV.rsp", "Result");
        assert_eq!(records.len(), 36);
        for (section, fields) in &records {
            let curve = curve_named(section);
            let ops = ops(curve);
            let mine = (ops.generate_ecdh)().unwrap();
            let expected = fields["Result"].starts_with('P');
            let what = format!("[{section}] Qx = {}: {}", fields["Qx"], fields["Result"]);
            let Some(public_key) = curve.public_key_pem(&hex(fields, "Qx"), &hex(fields, "Qy")) else {
                // A coordinate wider than the field can't even be encoded.
                assert!(!expected, "{what}");
                continue;
            };
            let shared = (ops.diffie_hellman)(mine.private_key, public_key.clone());
            let verified = (ops.verify)(public_key, b"m".to_vec(), vec![1; 2 * curve.field_len()]);
            if expected {
                assert!(shared.is_ok(), "{what}");
                assert_eq!(verified, Ok(false), "{what}");
            } else {
                assert_eq!(shared, Err(CasError::InvalidPemKey), "{what}");
                assert_eq!(verified, Err(CasError::InvalidPemKey), "{what}");
            }
        }
    }

    /// NIST SP 800-56A ECC CDH primitive: `dIUT` with `QCAVS` must give `ZIUT`.
    #[test]
    fn nist_ecc_cdh() {
        let records = cavp_records("KAS_ECC_CDH_PrimitiveTest.txt", "ZIUT");
        assert_eq!(records.len(), 75);
        for (section, fields) in &records {
            let curve = curve_named(section);
            let ops = ops(curve);
            let what = format!("[{section}] COUNT = {}", fields["COUNT"]);
            let private_key = curve.private_key_pem(&hex(fields, "dIUT")).unwrap();
            let peer = curve.public_key_pem(&hex(fields, "QCAVSx"), &hex(fields, "QCAVSy")).unwrap();
            let shared = (ops.diffie_hellman)(private_key, peer).unwrap();
            assert_eq!(shared, left_pad(&hex(fields, "ZIUT"), curve.field_len()).unwrap(), "{what}");

            // The other direction, against the IUT's public key.
            let own_public = curve.public_key_pem(&hex(fields, "QIUTx"), &hex(fields, "QIUTy")).unwrap();
            let theirs = (ops.generate_ecdh)().unwrap();
            assert!((ops.diffie_hellman)(theirs.private_key, own_public).is_ok(), "{what}");
        }
    }

    /// One signature from RFC 6979 appendix A.2.
    struct Rfc6979Vector {
        curve: Curve,
        private_key: Vec<u8>,
        public_x: Vec<u8>,
        public_y: Vec<u8>,
        message: String,
        r: Vec<u8>,
        s: Vec<u8>,
    }

    /// Parses the RFC 6979 A.2.5–A.2.7 excerpt, keeping only the signatures
    /// made with each curve's hash (SHA-256 / SHA-384 / SHA-512).
    fn rfc6979_vectors() -> Vec<Rfc6979Vector> {
        let text = data("rfc6979-A.2.5-A.2.7.txt");
        let mut values: Vec<(String, String)> = Vec::new(); // (name, hex) in order
        let mut current: Option<(String, String)> = None;
        let is_hex = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit());
        for line in text.lines() {
            let trimmed = line.trim();
            // Section headings and `With SHA-256, message = "sample":` lines.
            if trimmed.starts_with("A.2.") || trimmed.starts_with("With ") {
                if let Some(done) = current.take() {
                    values.push(done);
                }
                values.push(("marker".to_string(), trimmed.to_string()));
                continue;
            }
            if let Some((name, value)) = trimmed.split_once(" = ") {
                if let Some(done) = current.take() {
                    values.push(done);
                }
                if is_hex(value) {
                    current = Some((name.to_string(), value.to_string()));
                } else {
                    values.push((name.to_string(), value.to_string()));
                }
            } else if let (Some((_, value)), true) = (current.as_mut(), is_hex(trimmed)) {
                value.push_str(trimmed);
            } else if let Some(done) = current.take() {
                values.push(done);
            }
        }
        if let Some(done) = current.take() {
            values.push(done);
        }

        let mut vectors = Vec::new();
        let (mut curve, mut x, mut ux, mut uy) = (None, Vec::new(), Vec::new(), Vec::new());
        let mut pending: Option<(bool, String)> = None; // (uses the curve's hash, message)
        let mut r = Vec::new();
        for (name, value) in values {
            match name.as_str() {
                "marker" if value.starts_with("A.2.5") => curve = Some((Curve::P256, "SHA-256")),
                "marker" if value.starts_with("A.2.6") => curve = Some((Curve::P384, "SHA-384")),
                "marker" if value.starts_with("A.2.7") => curve = Some((Curve::P521, "SHA-512")),
                "marker" => {
                    // `With SHA-256, message = "sample":`
                    let hash = value.trim_start_matches("With ").split(',').next().unwrap();
                    let message = value.split('"').nth(1).unwrap().to_string();
                    pending = Some((hash == curve.unwrap().1, message));
                }
                "x" => x = decode_hex(&value),
                "Ux" => ux = decode_hex(&value),
                "Uy" => uy = decode_hex(&value),
                "r" => r = decode_hex(&value),
                "s" => {
                    if let Some((true, message)) = pending.take() {
                        vectors.push(Rfc6979Vector {
                            curve: curve.unwrap().0,
                            private_key: x.clone(),
                            public_x: ux.clone(),
                            public_y: uy.clone(),
                            message,
                            r: r.clone(),
                            s: decode_hex(&value),
                        });
                    }
                }
                _ => {}
            }
        }
        vectors
    }

    /// RFC 6979 pins deterministic signing byte for byte.
    #[test]
    fn rfc6979_deterministic_signatures() {
        let vectors = rfc6979_vectors();
        let found: Vec<_> = vectors.iter().map(|v| (v.curve, v.message.as_str())).collect();
        assert_eq!(
            found,
            [
                (Curve::P256, "sample"),
                (Curve::P256, "test"),
                (Curve::P384, "sample"),
                (Curve::P384, "test"),
                (Curve::P521, "sample"),
                (Curve::P521, "test"),
            ]
        );
        for v in vectors {
            let ops = ops(v.curve);
            let len = v.curve.field_len();
            let what = format!("{:?} {:?}", v.curve, v.message);
            let private_key = v.curve.private_key_pem(&v.private_key).unwrap();
            let public_key = v.curve.public_key_pem(&v.public_x, &v.public_y).unwrap();
            let expected = [left_pad(&v.r, len).unwrap(), left_pad(&v.s, len).unwrap()].concat();
            let message = v.message.as_bytes().to_vec();

            assert_eq!((ops.sign)(private_key.clone(), message.clone()).unwrap(), expected, "{what}");
            let expected_der = v.curve.p1363_to_der(&expected).unwrap();
            assert_eq!((ops.sign_der)(private_key, message.clone()).unwrap(), expected_der, "{what}");
            assert!((ops.verify)(public_key.clone(), message.clone(), expected).unwrap(), "{what}");
            assert!((ops.verify_der)(public_key, message, expected_der).unwrap(), "{what}");
        }
    }
}
