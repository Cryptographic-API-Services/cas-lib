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
    use cas_lib::message::hmac::{
        HMACSha256, HMACSha384, HMACSha3_256, HMACSha3_384, HMACSha3_512, HMACSha512,
    };

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
        run_hmac::<HMACSha256>("hmac_sha256_test.json", 256);
    }

    #[test]
    fn hmac_sha384_vectors() {
        run_hmac::<HMACSha384>("hmac_sha384_test.json", 384);
    }

    #[test]
    fn hmac_sha512_vectors() {
        run_hmac::<HMACSha512>("hmac_sha512_test.json", 512);
    }

    #[test]
    fn hmac_sha3_256_vectors() {
        run_hmac::<HMACSha3_256>("hmac_sha3_256_test.json", 256);
    }

    #[test]
    fn hmac_sha3_384_vectors() {
        run_hmac::<HMACSha3_384>("hmac_sha3_384_test.json", 384);
    }

    #[test]
    fn hmac_sha3_512_vectors() {
        run_hmac::<HMACSha3_512>("hmac_sha3_512_test.json", 512);
    }
}

// ---------------------------------------------------------------------------
// CMAC
// ---------------------------------------------------------------------------

mod cmac {
    use super::*;
    use cas_lib::error::CasError;
    use cas_lib::message::cmac::CASCMAC;
    use cas_lib::message::cas_cmac::{CMACAES128, CMACAES256};

    /// Groups are dispatched on `keySize`:
    /// - 128 and 256 bits run against `CMACAES128` / `CMACAES256`. The library
    ///   always produces and verifies the full 16-byte tag, so groups with a
    ///   truncated `tagSize` are checked against the leading bytes of the
    ///   computed tag and `verify` runs only for full-length tags.
    /// - 192 bits is skipped: the library has no AES-192 CMAC.
    /// - Any other size is an invalid AES key, which both implementations must
    ///   reject with `CasError::InvalidKey`.
    fn check_case<M: CASCMAC>(tally: &mut Tally, test: &Value, tag_bytes: usize) {
        let key = hex_field(test, "key");
        let msg = hex_field(test, "msg");
        let tag = hex_field(test, "tag");
        let valid = str_field(test, "result") == "valid";

        let Ok(computed) = M::sign(key.clone(), msg.clone()) else {
            tally.check(false, test, "sign returned an error");
            return;
        };
        tally.check(
            (computed[..tag_bytes] == tag[..]) == valid,
            test,
            if valid { "tag mismatch" } else { "invalid tag matched the computed tag" },
        );
        if tag_bytes == 16 {
            tally.check(
                M::verify(key, msg, tag) == Ok(valid),
                test,
                "verify disagreed with the expected result",
            );
        }
    }

    #[test]
    fn aes_cmac_vectors() {
        let file_name = "aes_cmac_test.json";
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            let key_size = int_field(group, "keySize");
            let tag_bytes = int_field(group, "tagSize") / 8;

            for test in tests(group) {
                match key_size {
                    128 => {
                        tally.run += 1;
                        check_case::<CMACAES128>(&mut tally, test, tag_bytes);
                    }
                    256 => {
                        tally.run += 1;
                        check_case::<CMACAES256>(&mut tally, test, tag_bytes);
                    }
                    192 => tally.skipped += 1,
                    _ => {
                        tally.run += 1;
                        assert_eq!(str_field(test, "result"), "invalid", "{}", label(test));
                        let key = hex_field(test, "key");
                        let msg = hex_field(test, "msg");
                        let tag = hex_field(test, "tag");
                        let rejected = CMACAES128::sign(key.clone(), msg.clone()) == Err(CasError::InvalidKey)
                            && CMACAES256::sign(key.clone(), msg.clone()) == Err(CasError::InvalidKey)
                            && CMACAES128::verify(key.clone(), msg.clone(), tag.clone()) == Err(CasError::InvalidKey)
                            && CMACAES256::verify(key, msg, tag) == Err(CasError::InvalidKey);
                        tally.check(rejected, test, "invalid key size was not rejected with InvalidKey");
                    }
                }
            }
        }

        tally.finish();
    }
}

// ---------------------------------------------------------------------------
// HKDF
// ---------------------------------------------------------------------------

mod hkdf {
    use super::*;
    use cas_lib::error::CasError;
    use cas_lib::kdf::cas_hkdf::{CASHkdfSha256, CASHkdfSha512, CASHKDF};

    /// - `valid`: `derive`, and `extract` followed by `expand`, must both
    ///   reproduce `okm`.
    /// - `invalid` (every one is an output size above `255 * HashLen`): both must
    ///   return `CasError::InvalidParameters`.
    fn run_hkdf<H: CASHKDF>(file_name: &str) {
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            for test in tests(group) {
                tally.run += 1;
                let ikm = hex_field(test, "ikm");
                let salt = hex_field(test, "salt");
                let info = hex_field(test, "info");
                let size = int_field(test, "size");
                let expected = match str_field(test, "result") {
                    "valid" => Ok(hex_field(test, "okm")),
                    _ => Err(CasError::InvalidParameters),
                };

                let derived = H::derive(salt.clone(), ikm.clone(), info.clone(), size);
                tally.check(derived == expected, test, "derive disagreed with the expected result");

                let prk = H::extract(salt, ikm);
                let expanded = H::expand(prk, info, size);
                tally.check(
                    expanded == expected,
                    test,
                    "extract + expand disagreed with the expected result",
                );
            }
        }

        tally.finish();
    }

    #[test]
    fn hkdf_sha256_vectors() {
        run_hkdf::<CASHkdfSha256>("hkdf_sha256_test.json");
    }

    #[test]
    fn hkdf_sha512_vectors() {
        run_hkdf::<CASHkdfSha512>("hkdf_sha512_test.json");
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
// ECDSA / ECDH (P-256, P-384, P-521, secp256k1)
// ---------------------------------------------------------------------------

mod ecdsa {
    use super::*;
    use cas_lib::ecc::cas_ecdsa::{CASEcdsa, CASEcdsaP256, CASEcdsaP384, CASEcdsaP521, CASEcdsaSecp256k1};

    /// `(public key PEM, message, signature) -> verified`.
    type VerifyFn = fn(String, Vec<u8>, Vec<u8>) -> CasResult<bool>;

    /// Runs a Wycheproof ECDSA verification file against `verify`, using each
    /// group's `publicKeyPem` (SPKI).
    ///
    /// - `valid` signatures must verify.
    /// - `invalid` ones must not: `Ok(false)`, or an error for a public key the
    ///   library refuses to parse.
    /// - `acceptable` passes either way (none of the files used has any).
    ///
    /// Each file must use the hash the API hashes with (`hash`), which the test
    /// checks against every group's `sha`.
    fn run_ecdsa(file_name: &str, hash: &str, verify: VerifyFn) {
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            assert_eq!(str_field(group, "sha"), hash, "{file_name}: unexpected hash");
            let public_key = str_field(group, "publicKeyPem").to_string();
            for test in tests(group) {
                tally.run += 1;
                let verified = verify(public_key.clone(), hex_field(test, "msg"), hex_field(test, "sig"));
                match str_field(test, "result") {
                    "valid" => tally.check(verified == Ok(true), test, &format!("valid signature rejected: {verified:?}")),
                    "invalid" => tally.check(verified != Ok(true), test, "invalid signature accepted"),
                    "acceptable" => {}
                    other => panic!("unexpected result `{other}` for {}", label(test)),
                }
            }
        }

        tally.finish();
    }

    #[test]
    fn p256_der_vectors() {
        run_ecdsa("ecdsa_secp256r1_sha256_test.json", "SHA-256", CASEcdsaP256::verify_der);
    }

    #[test]
    fn p256_p1363_vectors() {
        run_ecdsa("ecdsa_secp256r1_sha256_p1363_test.json", "SHA-256", CASEcdsaP256::verify);
    }

    #[test]
    fn p384_der_vectors() {
        run_ecdsa("ecdsa_secp384r1_sha384_test.json", "SHA-384", CASEcdsaP384::verify_der);
    }

    #[test]
    fn p384_p1363_vectors() {
        run_ecdsa("ecdsa_secp384r1_sha384_p1363_test.json", "SHA-384", CASEcdsaP384::verify);
    }

    #[test]
    fn p521_der_vectors() {
        run_ecdsa("ecdsa_secp521r1_sha512_test.json", "SHA-512", CASEcdsaP521::verify_der);
    }

    #[test]
    fn p521_p1363_vectors() {
        run_ecdsa("ecdsa_secp521r1_sha512_p1363_test.json", "SHA-512", CASEcdsaP521::verify);
    }

    /// The plain file follows standard ECDSA, where high-S signatures are
    /// valid: `verify_der` accepts them.
    #[test]
    fn secp256k1_der_vectors() {
        run_ecdsa("ecdsa_secp256k1_sha256_test.json", "SHA-256", CASEcdsaSecp256k1::verify_der);
    }

    #[test]
    fn secp256k1_p1363_vectors() {
        run_ecdsa("ecdsa_secp256k1_sha256_p1363_test.json", "SHA-256", CASEcdsaSecp256k1::verify);
    }

    /// The bitcoin file marks high-S signatures invalid (BIP-62 / BIP-146):
    /// exactly what `verify_der_low_s` enforces.
    #[test]
    fn secp256k1_bitcoin_low_s_vectors() {
        run_ecdsa(
            "ecdsa_secp256k1_sha256_bitcoin_test.json",
            "SHA-256",
            CASEcdsaSecp256k1::verify_der_low_s,
        );
    }
}

mod ecdh {
    use super::*;
    use cas_lib::ecc::cas_ecdh::{CASEcdh, CASEcdhP256, CASEcdhP384, CASEcdhP521, CASEcdhSecp256k1};
    use crate::common::ec::{pem, Curve};

    /// `(my private key PEM, peer public key PEM) -> shared secret`.
    type DhFn = fn(String, String) -> CasResult<Vec<u8>>;

    /// Runs a Wycheproof ECDH file. `keys` turns a test's `private` and
    /// `public` fields into the PEM keys the API takes.
    ///
    /// - `valid`: the shared secret must equal `shared`.
    /// - `invalid` (invalid or wrong-curve public keys, invalid-curve attacks):
    ///   `diffie_hellman` must return an error.
    /// - `acceptable` (compressed points, unusual but harmless encodings): may
    ///   be rejected, but if accepted the shared secret must still be `shared`.
    fn run_ecdh(file_name: &str, dh: DhFn, keys: impl Fn(&Value) -> (String, String)) {
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            for test in tests(group) {
                tally.run += 1;
                let (private_key, public_key) = keys(test);
                let shared = dh(private_key, public_key);
                let expected = hex_field(test, "shared");
                match str_field(test, "result") {
                    "valid" => tally.check(shared == Ok(expected), test, &format!("shared secret mismatch: {shared:?}")),
                    "invalid" => tally.check(shared.is_err(), test, "invalid public key accepted"),
                    "acceptable" => tally.check(
                        shared.as_ref().map_or(true, |s| *s == expected),
                        test,
                        "accepted, but with the wrong shared secret",
                    ),
                    other => panic!("unexpected result `{other}` for {}", label(test)),
                }
            }
        }

        tally.finish();
    }

    /// The `_pem` files give both keys as PEM, exactly what the API takes.
    fn pem_keys(test: &Value) -> (String, String) {
        (str_field(test, "private").to_string(), str_field(test, "public").to_string())
    }

    #[test]
    fn p256_vectors() {
        run_ecdh("ecdh_secp256r1_pem_test.json", CASEcdhP256::diffie_hellman, pem_keys);
    }

    #[test]
    fn p384_vectors() {
        run_ecdh("ecdh_secp384r1_pem_test.json", CASEcdhP384::diffie_hellman, pem_keys);
    }

    #[test]
    fn p521_vectors() {
        run_ecdh("ecdh_secp521r1_pem_test.json", CASEcdhP521::diffie_hellman, pem_keys);
    }

    /// There is no `_pem` file for secp256k1. This one gives the private key as
    /// a raw scalar, which the test wraps in PKCS#8, and the public key as SPKI
    /// DER, which it PEM-armors unchanged (malformed DER included).
    #[test]
    fn secp256k1_vectors() {
        run_ecdh("ecdh_secp256k1_test.json", CASEcdhSecp256k1::diffie_hellman, |test| {
            let private_key = Curve::Secp256k1
                .private_key_pem(&hex_field(test, "private"))
                .unwrap_or_else(|| panic!("{}: private key is not a valid scalar", label(test)));
            (private_key, pem("PUBLIC KEY", &hex_field(test, "public")))
        });
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
// RSA (RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-256)
// ---------------------------------------------------------------------------

/// `CASRSA::sign` / `verify` are RSASSA-PKCS1-v1_5 with SHA-256 (RS256) and
/// `sign_pss` / `verify_pss` are RSASSA-PSS with SHA-256, MGF1-SHA-256 and a
/// 32-byte salt (PS256). Both hash the message themselves, so each vector's
/// `msg` is passed as is.
mod rsa_signatures {
    use super::*;
    use cas_lib::asymmetric::{cas_rsa::CASRSA, types::CASRSAEncryption};
    use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
    use rsa::pkcs8::{DecodePrivateKey, LineEnding};
    use rsa::{PrivateKey, PublicKey};

    type VerifyFn = fn(String, Vec<u8>, Vec<u8>) -> CasResult<bool>;

    /// The library takes a PKCS#1 PEM public key; `publicKeyAsn` is the PKCS#1
    /// DER encoding of the same key.
    fn public_key_pem(group: &Value) -> String {
        PublicKey::from_pkcs1_der(&hex_field(group, "publicKeyAsn"))
            .expect("PKCS#1 public key")
            .to_pkcs1_pem(LineEnding::LF)
            .expect("PEM encoding")
    }

    /// Runs a verify file whose groups all match the scheme under test.
    ///
    /// - `valid` signatures must verify.
    /// - `invalid` signatures must not.
    /// - `acceptable` cases are legacy encodings (e.g. a `DigestInfo` without
    ///   the NULL parameter) that implementations may accept or reject.
    fn run_verify(file_name: &str, verify: VerifyFn, check_group: fn(&Value)) {
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            check_group(group);
            let public_key = public_key_pem(group);

            for test in tests(group) {
                tally.run += 1;
                let verified = verify(public_key.clone(), hex_field(test, "msg"), hex_field(test, "sig"))
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

    /// Runs a verify file made for different parameters (another hash or salt
    /// length). Its `valid` signatures are correct for those parameters, so
    /// none of them may verify under the scheme under test. Its `invalid` and
    /// `acceptable` cases are skipped: some are deliberately correct
    /// signatures for the parameters under test (e.g. "hashed with SHA-256
    /// instead of SHA-224").
    fn run_verify_rejects_valid(file_name: &str, verify: VerifyFn) {
        let file = load(file_name);
        let mut tally = Tally::new(file_name, &file);

        for group in groups(&file) {
            let public_key = public_key_pem(group);
            for test in tests(group) {
                if str_field(test, "result") != "valid" {
                    tally.skipped += 1;
                    continue;
                }
                tally.run += 1;
                let verified = verify(public_key.clone(), hex_field(test, "msg"), hex_field(test, "sig"))
                    .unwrap_or(false);
                tally.check(!verified, test, "signature for other parameters accepted");
            }
        }

        tally.finish();
    }

    fn rs256_group(group: &Value) {
        assert_eq!(str_field(group, "sha"), "SHA-256");
    }

    fn ps256_group(group: &Value) {
        assert_eq!(str_field(group, "sha"), "SHA-256");
        assert_eq!(str_field(group, "mgf"), "MGF1");
        assert_eq!(str_field(group, "mgfSha"), "SHA-256");
        assert_eq!(int_field(group, "sLen"), 32);
    }

    #[test]
    fn rs256_verify_vectors() {
        for bits in [2048, 3072, 4096, 8192] {
            run_verify(&format!("rsa_signature_{bits}_sha256_test.json"), CASRSA::verify, rs256_group);
        }
    }

    /// A signature made with another hash carries that hash's `DigestInfo`,
    /// so RS256 verification must reject it.
    #[test]
    fn rs256_rejects_other_hashes() {
        for sha in ["sha224", "sha384", "sha512"] {
            run_verify_rejects_valid(&format!("rsa_signature_2048_{sha}_test.json"), CASRSA::verify);
        }
    }

    /// PKCS#1 v1.5 signing is deterministic, so every SHA-256 case must
    /// reproduce the expected signature byte for byte.
    ///
    /// Skipped: groups for other hashes, and groups whose key `rsa` 0.10
    /// refuses to decode (the e = 3 keys with unbalanced 1364/684-bit primes).
    /// Signing with such a key must fail cleanly with `InvalidPemKey`.
    #[test]
    fn rs256_sign_vectors() {
        for bits in [2048, 3072, 4096] {
            let file_name = format!("rsa_pkcs1_{bits}_sig_gen_test.json");
            let file = load(&file_name);
            let mut tally = Tally::new(&file_name, &file);

            for group in groups(&file) {
                if str_field(group, "sha") != "SHA-256" {
                    tally.skipped += tests(group).len();
                    continue;
                }
                // The library takes a PKCS#8 PEM private key.
                let der = hex_field(group, "privateKeyPkcs8");
                let private_key = rsa::pkcs8::der::pem::encode_string("PRIVATE KEY", LineEnding::LF, &der)
                    .expect("PEM encoding");
                if PrivateKey::from_pkcs8_der(&der).is_err() {
                    assert_eq!(
                        CASRSA::sign(private_key, b"msg".to_vec()),
                        Err(cas_lib::error::CasError::InvalidPemKey)
                    );
                    tally.skipped += tests(group).len();
                    continue;
                }

                for test in tests(group) {
                    tally.run += 1;
                    let signature = CASRSA::sign(private_key.clone(), hex_field(test, "msg"));
                    tally.check(signature == Ok(hex_field(test, "sig")), test, "signature mismatch");
                }
            }

            tally.finish();
        }
    }

    #[test]
    fn ps256_verify_vectors() {
        for bits in [2048, 3072, 4096] {
            run_verify(&format!("rsa_pss_{bits}_sha256_mgf1_32_test.json"), CASRSA::verify_pss, ps256_group);
        }
    }

    /// `verify_pss` requires a 32-byte salt, so signatures with no salt must
    /// not verify.
    #[test]
    fn ps256_rejects_other_salt_lengths() {
        run_verify_rejects_valid("rsa_pss_2048_sha256_mgf1_0_test.json", CASRSA::verify_pss);
    }
}
