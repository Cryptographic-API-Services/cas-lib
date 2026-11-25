//! Project Wycheproof known-answer tests.
//!
//! Each test downloads one or more upstream vector files (see
//! `tests/common/wycheproof.rs`) and runs every case the public API can
//! express. Cases the API cannot express are skipped and counted, and every
//! test asserts that `run + skipped` equals the file's `numberOfTests`, so a
//! case can never be dropped silently. See `tests/data/wycheproof/README.md`
//! for what is covered and why the rest is skipped.
//!
//! The AES-KW / AES-KWP and ML-DSA Wycheproof suites live next to their
//! algorithms in `tests/aes_kw.rs` and `tests/pqc.rs`.

mod common;

use cas_lib::error::CasResult;
use common::wycheproof::load;
use serde_json::Value;

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex input must have an even length");
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}

fn str_field<'a>(obj: &'a Value, key: &str) -> &'a str {
    obj[key].as_str().unwrap_or_else(|| panic!("missing string field `{key}`"))
}

fn hex_field(obj: &Value, key: &str) -> Vec<u8> {
    decode_hex(str_field(obj, key))
}

fn int_field(obj: &Value, key: &str) -> usize {
    obj[key].as_u64().unwrap_or_else(|| panic!("missing integer field `{key}`")) as usize
}

fn groups(file: &Value) -> &Vec<Value> {
    file["testGroups"].as_array().expect("testGroups array")
}

fn tests(group: &Value) -> &Vec<Value> {
    group["tests"].as_array().expect("tests array")
}

fn label(test: &Value) -> String {
    format!("tcId {} ({})", test["tcId"], test["comment"].as_str().unwrap_or(""))
}

/// Tallies one vector file and reports every failing case at once, so a single
/// run shows the full extent of a problem.
struct Tally {
    file_name: String,
    number_of_tests: usize,
    run: usize,
    skipped: usize,
    failures: Vec<String>,
}

impl Tally {
    fn new(file_name: &str, file: &Value) -> Self {
        Tally {
            file_name: file_name.to_string(),
            number_of_tests: int_field(file, "numberOfTests"),
            run: 0,
            skipped: 0,
            failures: Vec::new(),
        }
    }

    fn check(&mut self, passed: bool, test: &Value, what: &str) {
        if !passed {
            self.failures.push(format!("{}: {what}", label(test)));
        }
    }

    fn finish(self) {
        let Tally { file_name, number_of_tests, run, skipped, failures } = self;
        assert!(
            failures.is_empty(),
            "{file_name}: {} of {run} vectors failed:\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
        assert!(run > 0, "{file_name}: no vectors were run");
        assert_eq!(
            run + skipped,
            number_of_tests,
            "{file_name}: {run} run + {skipped} skipped does not account for every test"
        );
        println!("{file_name}: {run} vectors run, {skipped} skipped");
    }
}

// ---------------------------------------------------------------------------
// AEADs
// ---------------------------------------------------------------------------

/// `(key, nonce, data, aad) -> output`.
type AeadFn = dyn Fn(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) -> CasResult<Vec<u8>>;

struct AeadCipher<'a> {
    key_bits: usize,
    nonce_bits: usize,
    /// Whether the API under test takes additional authenticated data.
    supports_aad: bool,
    encrypt: &'a AeadFn,
    decrypt: &'a AeadFn,
}

/// Runs a Wycheproof AEAD file. The library appends the 128-bit tag to the
/// ciphertext, so the expected output is `ct || tag`.
///
/// - `valid`: encryption must reproduce `ct || tag` and decryption must return `msg`.
/// - `invalid`: decryption must fail.
/// - Groups with a nonce size the API does not accept must be rejected by both
///   encryption and decryption, whatever the expected result.
///
/// Skipped: key sizes the library does not expose, and (for APIs without an
/// AAD parameter) cases with non-empty AAD.
fn run_aead(file_name: &str, ciphers: &[AeadCipher]) {
    let file = load(file_name);
    let mut tally = Tally::new(file_name, &file);

    for group in groups(&file) {
        let cipher = ciphers.iter().find(|c| c.key_bits == int_field(group, "keySize"));
        let Some(cipher) = cipher.filter(|_| int_field(group, "tagSize") == 128) else {
            tally.skipped += tests(group).len();
            continue;
        };
        let nonce_supported = int_field(group, "ivSize") == cipher.nonce_bits;

        for test in tests(group) {
            let aad = hex_field(test, "aad");
            if !aad.is_empty() && !cipher.supports_aad {
                tally.skipped += 1;
                continue;
            }
            tally.run += 1;

            let key = hex_field(test, "key");
            let nonce = hex_field(test, "iv");
            let msg = hex_field(test, "msg");
            let mut ct_with_tag = hex_field(test, "ct");
            ct_with_tag.extend(hex_field(test, "tag"));

            let encrypted = (cipher.encrypt)(key.clone(), nonce.clone(), msg.clone(), aad.clone());
            let decrypted = (cipher.decrypt)(key, nonce, ct_with_tag.clone(), aad);

            if !nonce_supported {
                tally.check(encrypted.is_err(), test, "encrypt accepted an unsupported nonce size");
                tally.check(decrypted.is_err(), test, "decrypt accepted an unsupported nonce size");
            } else if str_field(test, "result") == "valid" {
                tally.check(encrypted.as_ref() == Ok(&ct_with_tag), test, "ciphertext||tag mismatch");
                tally.check(decrypted.as_ref() == Ok(&msg), test, "plaintext mismatch");
            } else {
                tally.check(decrypted.is_err(), test, "decrypt accepted an invalid ciphertext/tag");
            }
        }
    }

    tally.finish();
}

mod aes_gcm {
    use super::*;
    use cas_lib::symmetric::aes::{CASAES128, CASAES256};
    use cas_lib::symmetric::cas_symmetric_encryption::{
        CASAES128AadEncryption, CASAES128Encryption, CASAES256AadEncryption, CASAES256Encryption,
    };

    /// The AAD API can express every 96-bit-nonce case for AES-128 and AES-256.
    #[test]
    fn aes_gcm_aad_api_vectors() {
        run_aead(
            "aes_gcm_test.json",
            &[
                AeadCipher {
                    key_bits: 128,
                    nonce_bits: 96,
                    supports_aad: true,
                    encrypt: &|k, n, d, aad| CASAES128::encrypt_plaintext_with_aad(k, n, d, aad),
                    decrypt: &|k, n, d, aad| CASAES128::decrypt_ciphertext_with_aad(k, n, d, aad),
                },
                AeadCipher {
                    key_bits: 256,
                    nonce_bits: 96,
                    supports_aad: true,
                    encrypt: &|k, n, d, aad| CASAES256::encrypt_plaintext_with_aad(k, n, d, aad),
                    decrypt: &|k, n, d, aad| CASAES256::decrypt_ciphertext_with_aad(k, n, d, aad),
                },
            ],
        );
    }

    /// The API without an AAD parameter is a separate code path; it covers the
    /// empty-AAD cases.
    #[test]
    fn aes_gcm_vectors() {
        run_aead(
            "aes_gcm_test.json",
            &[
                AeadCipher {
                    key_bits: 128,
                    nonce_bits: 96,
                    supports_aad: false,
                    encrypt: &|k, n, d, _| CASAES128::encrypt_plaintext(k, n, d),
                    decrypt: &|k, n, d, _| CASAES128::decrypt_ciphertext(k, n, d),
                },
                AeadCipher {
                    key_bits: 256,
                    nonce_bits: 96,
                    supports_aad: false,
                    encrypt: &|k, n, d, _| CASAES256::encrypt_plaintext(k, n, d),
                    decrypt: &|k, n, d, _| CASAES256::decrypt_ciphertext(k, n, d),
                },
            ],
        );
    }
}

mod aes_gcm_siv {
    use super::*;
    use cas_lib::symmetric::aes_gcm_siv::{CASAES128SIV, CASAES256SIV};
    use cas_lib::symmetric::cas_symmetric_encryption::{
        CASAES128SIVAadEncryption, CASAES128SIVEncryption, CASAES256SIVAadEncryption,
        CASAES256SIVEncryption,
    };

    /// The AAD API can express every 96-bit-nonce case for AES-128 and AES-256.
    #[test]
    fn aes_gcm_siv_aad_api_vectors() {
        run_aead(
            "aes_gcm_siv_test.json",
            &[
                AeadCipher {
                    key_bits: 128,
                    nonce_bits: 96,
                    supports_aad: true,
                    encrypt: &|k, n, d, aad| CASAES128SIV::encrypt_plaintext_with_aad(k, n, d, aad),
                    decrypt: &|k, n, d, aad| CASAES128SIV::decrypt_ciphertext_with_aad(k, n, d, aad),
                },
                AeadCipher {
                    key_bits: 256,
                    nonce_bits: 96,
                    supports_aad: true,
                    encrypt: &|k, n, d, aad| CASAES256SIV::encrypt_plaintext_with_aad(k, n, d, aad),
                    decrypt: &|k, n, d, aad| CASAES256SIV::decrypt_ciphertext_with_aad(k, n, d, aad),
                },
            ],
        );
    }

    #[test]
    fn aes_gcm_siv_vectors() {
        run_aead(
            "aes_gcm_siv_test.json",
            &[
                AeadCipher {
                    key_bits: 128,
                    nonce_bits: 96,
                    supports_aad: false,
                    encrypt: &|k, n, d, _| CASAES128SIV::encrypt_plaintext(k, n, d),
                    decrypt: &|k, n, d, _| CASAES128SIV::decrypt_ciphertext(k, n, d),
                },
                AeadCipher {
                    key_bits: 256,
                    nonce_bits: 96,
                    supports_aad: false,
                    encrypt: &|k, n, d, _| CASAES256SIV::encrypt_plaintext(k, n, d),
                    decrypt: &|k, n, d, _| CASAES256SIV::decrypt_ciphertext(k, n, d),
                },
            ],
        );
    }
}

mod chacha20_poly1305 {
    use super::*;
    use cas_lib::symmetric::cas_symmetric_encryption::{
        Chacha20Poly1305AadEncryption, Chacha20Poly1305Encryption,
    };
    use cas_lib::symmetric::chacha20poly1305::CASChacha20Poly1305;

    #[test]
    fn chacha20_poly1305_aad_api_vectors() {
        run_aead(
            "chacha20_poly1305_test.json",
            &[AeadCipher {
                key_bits: 256,
                nonce_bits: 96,
                supports_aad: true,
                encrypt: &|k, n, d, aad| CASChacha20Poly1305::encrypt_plaintext_with_aad(k, n, d, aad),
                decrypt: &|k, n, d, aad| CASChacha20Poly1305::decrypt_ciphertext_with_aad(k, n, d, aad),
            }],
        );
    }

    #[test]
    fn chacha20_poly1305_vectors() {
        run_aead(
            "chacha20_poly1305_test.json",
            &[AeadCipher {
                key_bits: 256,
                nonce_bits: 96,
                supports_aad: false,
                encrypt: &|k, n, d, _| CASChacha20Poly1305::encrypt_plaintext(k, n, d),
                decrypt: &|k, n, d, _| CASChacha20Poly1305::decrypt_ciphertext(k, n, d),
            }],
        );
    }
}

mod ascon_aead128 {
    use super::*;
    use cas_lib::sponges::ascon_aead::AsconAead;
    use cas_lib::sponges::cas_ascon_aead::{CASAsconAead, CASAsconAeadAad};

    /// NIST SP 800-232 Ascon-AEAD128 through the AAD API.
    #[test]
    fn ascon_aead128_aad_api_vectors() {
        run_aead(
            "ascon_sp800_232_aead128_test.json",
            &[AeadCipher {
                key_bits: 128,
                nonce_bits: 128,
                supports_aad: true,
                encrypt: &|k, n, d, aad| AsconAead::encrypt_plaintext_with_aad(k, n, d, aad),
                decrypt: &|k, n, d, aad| AsconAead::decrypt_ciphertext_with_aad(k, n, d, aad),
            }],
        );
    }

    /// NIST SP 800-232 Ascon-AEAD128.
    #[test]
    fn ascon_aead128_vectors() {
        run_aead(
            "ascon_sp800_232_aead128_test.json",
            &[AeadCipher {
                key_bits: 128,
                nonce_bits: 128,
                supports_aad: false,
                encrypt: &|k, n, d, _| AsconAead::encrypt(k, n, d),
                decrypt: &|k, n, d, _| AsconAead::decrypt(k, n, d),
            }],
        );
    }
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

mod hmac {
    use super::*;
    use cas_lib::message::cas_hmac::CASHMAC;
    use cas_lib::message::hmac::{HMACSha512, HMAC};

    /// The library always produces and verifies the full-length tag. Groups
    /// with a truncated `tagSize` are checked against the leading bytes of the
    /// computed tag; `verify` is exercised only for full-length tags.
    fn run_hmac<H: CASHMAC>(file_name: &str, full_tag_bits: usize) {
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            let tag_bytes = int_field(group, "tagSize") / 8;
            let full_tag = int_field(group, "tagSize") == full_tag_bits;

            for test in tests(group) {
                tally.run += 1;
                let key = hex_field(test, "key");
                let msg = hex_field(test, "msg");
                let tag = hex_field(test, "tag");
                let valid = str_field(test, "result") == "valid";

                let computed = H::sign(key.clone(), msg.clone());
                let Ok(computed) = computed else {
                    tally.check(false, test, "sign returned an error");
                    continue;
                };
                tally.check(
                    (computed[..tag_bytes] == tag[..]) == valid,
                    test,
                    if valid { "tag mismatch" } else { "invalid tag matched the computed tag" },
                );
                if full_tag {
                    tally.check(
                        H::verify(key, msg, tag) == Ok(valid),
                        test,
                        "verify disagreed with the expected result",
                    );
                }
            }
        }

        tally.finish();
    }

    #[test]
    fn hmac_sha256_vectors() {
        run_hmac::<HMAC>("hmac_sha256_test.json", 256);
    }

    #[test]
    fn hmac_sha512_vectors() {
        run_hmac::<HMACSha512>("hmac_sha512_test.json", 512);
    }
}

// ---------------------------------------------------------------------------
// X25519 / Ed25519
// ---------------------------------------------------------------------------

mod x25519 {
    use super::*;
    use cas_lib::error::CasError;
    use cas_lib::key_exchange::cas_key_exchange::CASKeyExchange;
    use cas_lib::key_exchange::x25519::X25519;

    /// x25519-dalek clamps the private key and masks the public key's high bit
    /// per RFC 7748, so every case has exactly one correct output.
    ///
    /// - A low-order public key forces the all-zero shared secret. Wycheproof
    ///   flags those cases `ZeroSharedSecret` and allows rejecting them, and
    ///   `diffie_hellman` does (#112): when the expected secret is all zeros,
    ///   the result must be `Err(CasError::InvalidKey)`.
    /// - Every other case, `valid` or `acceptable`, must produce exactly the
    ///   expected shared secret.
    #[test]
    fn x25519_vectors() {
        let file_name = "x25519_test.json";
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            for test in tests(group) {
                tally.run += 1;
                let expected = hex_field(test, "shared");
                let shared = X25519::diffie_hellman(hex_field(test, "private"), hex_field(test, "public"));
                if expected.iter().all(|&b| b == 0) {
                    tally.check(
                        shared == Err(CasError::InvalidKey),
                        test,
                        "low-order public key (all-zero shared secret) was not rejected",
                    );
                } else {
                    tally.check(shared == Ok(expected), test, "shared secret mismatch");
                }
            }
        }

        tally.finish();
    }
}

mod ed25519 {
    use super::*;
    use cas_lib::signatures::ed25519::ed25519_verify_with_public_key;

    /// The vector file carries public keys only, so this drives verification.
    ///
    /// - `valid` signatures must verify.
    /// - `invalid` signatures must not (an error for a malformed signature or
    ///   key counts as a rejection).
    /// - `acceptable` cases use small-order or mixed-order public keys, which
    ///   implementations may either accept or reject; the library verifies
    ///   strictly, and either outcome passes here.
    #[test]
    fn ed25519_verify_vectors() {
        let file_name = "ed25519_test.json";
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            let public_key = hex_field(&group["publicKey"], "pk");

            for test in tests(group) {
                tally.run += 1;
                let verified = ed25519_verify_with_public_key(
                    public_key.clone(),
                    hex_field(test, "sig"),
                    hex_field(test, "msg"),
                )
                .unwrap_or(false);

                match str_field(test, "result") {
                    "valid" => tally.check(verified, test, "valid signature rejected"),
                    "invalid" => tally.check(!verified, test, "invalid signature accepted"),
                    "acceptable" => {}
                    other => panic!("unexpected result `{other}` for {}", label(test)),
                }
            }
        }

        tally.finish();
    }
}

// ---------------------------------------------------------------------------
// ML-KEM-1024
// ---------------------------------------------------------------------------

mod ml_kem_1024 {
    use super::*;
    use cas_lib::pqc::ml_kem::{ml_kem_1024_decapsulate, ml_kem_1024_encapsulate};

    /// Decapsulation with the expanded 3168-byte key the API takes. Invalid
    /// cases (wrong lengths, and keys that fail the FIPS 203 section 7.3
    /// decapsulation key check) must be rejected.
    #[test]
    fn ml_kem_1024_decapsulation_vectors() {
        let file_name = "mlkem_1024_semi_expanded_decaps_test.json";
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            for test in tests(group) {
                tally.run += 1;
                let shared = ml_kem_1024_decapsulate(hex_field(test, "dk"), hex_field(test, "c"));
                if str_field(test, "result") == "valid" {
                    tally.check(shared == Ok(hex_field(test, "K")), test, "shared secret mismatch");
                } else {
                    tally.check(shared.is_err(), test, "decapsulation accepted an invalid input");
                }
            }
        }

        tally.finish();
    }

    /// Encapsulation is randomized and the API takes no `m`, so the `valid`
    /// cases cannot be reproduced and are skipped. The `invalid` cases are
    /// encapsulation keys of the wrong length or that fail the FIPS 203
    /// section 7.2 modulus check; all of them must be rejected.
    #[test]
    fn ml_kem_1024_encapsulation_rejects_invalid_keys() {
        let file_name = "mlkem_1024_encaps_test.json";
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            for test in tests(group) {
                if str_field(test, "result") != "invalid" {
                    tally.skipped += 1;
                    continue;
                }
                tally.run += 1;
                tally.check(
                    ml_kem_1024_encapsulate(hex_field(test, "ek")).is_err(),
                    test,
                    "encapsulation accepted an invalid key",
                );
            }
        }

        tally.finish();
    }
}

// ---------------------------------------------------------------------------
// RSA (RSASSA-PKCS1-v1_5)
// ---------------------------------------------------------------------------

/// `CASRSA` signs and verifies with `Pkcs1v15Sign::new_unprefixed()`: the caller
/// supplies the fully encoded `DigestInfo` (ASN.1 prefix || digest) and the
/// library applies the PKCS#1 v1.5 padding. Building that `DigestInfo` here
/// from each vector's `msg` makes the standard RSASSA-PKCS1-v1_5 vectors apply.
mod rsa_pkcs1v15 {
    use super::*;
    use cas_lib::asymmetric::{cas_rsa::CASRSA, types::CASRSAEncryption};
    use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

    /// Returns the DER `DigestInfo` for `msg`, or `None` for a hash this test
    /// does not build (SHA-1, SHA-512/t and SHA-3 groups are skipped).
    fn digest_info(sha: &str, msg: &[u8]) -> Option<Vec<u8>> {
        let (prefix, digest) = match sha {
            "SHA-224" => ("302d300d06096086480165030402040500041c", Sha224::digest(msg).to_vec()),
            "SHA-256" => ("3031300d060960864801650304020105000420", Sha256::digest(msg).to_vec()),
            "SHA-384" => ("3041300d060960864801650304020205000430", Sha384::digest(msg).to_vec()),
            "SHA-512" => ("3051300d060960864801650304020305000440", Sha512::digest(msg).to_vec()),
            _ => return None,
        };
        let mut encoded = decode_hex(prefix);
        encoded.extend(digest);
        Some(encoded)
    }

    /// - `valid` signatures must verify.
    /// - `invalid` signatures must not.
    /// - `acceptable` cases are legacy encodings (e.g. a `DigestInfo` without
    ///   the NULL parameter) that implementations may accept or reject.
    fn run_verify(file_name: &str) {
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            // The library takes a PKCS#1 PEM public key; `publicKeyAsn` is the
            // PKCS#1 DER encoding of the same key.
            let public_key = RsaPublicKey::from_pkcs1_der(&hex_field(group, "publicKeyAsn"))
                .expect("PKCS#1 public key")
                .to_pkcs1_pem(LineEnding::LF)
                .expect("PEM encoding");

            for test in tests(group) {
                let Some(encoded) = digest_info(str_field(group, "sha"), &hex_field(test, "msg")) else {
                    tally.skipped += 1;
                    continue;
                };
                tally.run += 1;
                let verified = CASRSA::verify(public_key.clone(), encoded, hex_field(test, "sig"))
                    .unwrap_or(false);

                match str_field(test, "result") {
                    "valid" => tally.check(verified, test, "valid signature rejected"),
                    "invalid" => tally.check(!verified, test, "invalid signature accepted"),
                    "acceptable" => {}
                    other => panic!("unexpected result `{other}` for {}", label(test)),
                }
            }
        }

        tally.finish();
    }

    /// PKCS#1 v1.5 signing is deterministic, so every case must reproduce the
    /// expected signature byte for byte.
    fn run_sign(file_name: &str) {
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            // The library takes a PKCS#8 PEM private key.
            let private_key = RsaPrivateKey::from_pkcs8_der(&hex_field(group, "privateKeyPkcs8"))
                .expect("PKCS#8 private key")
                .to_pkcs8_pem(LineEnding::LF)
                .expect("PEM encoding")
                .to_string();

            for test in tests(group) {
                let Some(encoded) = digest_info(str_field(group, "sha"), &hex_field(test, "msg")) else {
                    tally.skipped += 1;
                    continue;
                };
                tally.run += 1;
                let signature = CASRSA::sign(private_key.clone(), encoded);
                tally.check(signature == Ok(hex_field(test, "sig")), test, "signature mismatch");
            }
        }

        tally.finish();
    }

    #[test]
    fn rsa_2048_verify_vectors() {
        for sha in ["sha224", "sha256", "sha384", "sha512"] {
            run_verify(&format!("rsa_signature_2048_{sha}_test.json"));
        }
    }

    #[test]
    fn rsa_3072_verify_vectors() {
        for sha in ["sha256", "sha384", "sha512"] {
            run_verify(&format!("rsa_signature_3072_{sha}_test.json"));
        }
    }

    #[test]
    fn rsa_4096_verify_vectors() {
        for sha in ["sha256", "sha384", "sha512"] {
            run_verify(&format!("rsa_signature_4096_{sha}_test.json"));
        }
    }

    #[test]
    fn rsa_sign_vectors() {
        for bits in [2048, 3072, 4096] {
            run_sign(&format!("rsa_pkcs1_{bits}_sig_gen_test.json"));
        }
    }
}
