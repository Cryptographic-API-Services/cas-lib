# Wycheproof test vectors

The Project Wycheproof JSON files are **not checked in**. The tests download
them, unmodified, from [C2SP/wycheproof](https://github.com/C2SP/wycheproof)
(`testvectors_v1/`) and cache them under `target/tmp/wycheproof/<commit>/`. The
helper is [`tests/common/wycheproof.rs`](../../common/wycheproof.rs).

- **Always latest:** every run, local or CI, resolves upstream `main` to its
  current commit (logged as `Wycheproof vectors: C2SP/wycheproof@<sha> (main)`)
  and tests against it. Files are only downloaded again when that commit
  changes. This matches the cas-dotnet-sdk and cas-typescript-sdk approach.
- **New failures:** a Wycheproof test that fails without any change here means
  upstream added a case the library (or the test) does not handle yet. That is
  intended: the build fails until it is fixed.
- **Reproducing a run:** set `WYCHEPROOF_REF` to the commit from its log. A tag
  or another branch works too.

  ```bash
  WYCHEPROOF_REF=<sha-or-tag> cargo test --test pqc --test aes_kw
  ```

- **Requirements:** `git` (to resolve the ref) and `curl` (to download) on
  `PATH`, plus network access.
- **Offline:** if the ref cannot be resolved and vectors were downloaded
  before, the last resolved commit is reused with a warning. `cargo clean`
  empties the cache.
- **Adding a file:** call `common::wycheproof::load("<upstream file name>")`
  from the test and add a row below.

Wycheproof is licensed under the Apache License 2.0; see
<https://github.com/C2SP/wycheproof/blob/main/LICENSE>.

| File | Exercised by |
|---|---|
| `aes_gcm_test.json` | `aes_gcm` in [`tests/wycheproof.rs`](../../wycheproof.rs) (AAD and non-AAD APIs) |
| `aes_gcm_siv_test.json` | `aes_gcm_siv` in `tests/wycheproof.rs` |
| `chacha20_poly1305_test.json` | `chacha20_poly1305` in `tests/wycheproof.rs` |
| `ascon_sp800_232_aead128_test.json` | `ascon_aead128` in `tests/wycheproof.rs` |
| `hmac_sha256_test.json`, `hmac_sha512_test.json` | `hmac` in `tests/wycheproof.rs` |
| `x25519_test.json` | `x25519` in `tests/wycheproof.rs` |
| `ed25519_test.json` | `ed25519` in `tests/wycheproof.rs` |
| `mlkem_1024_semi_expanded_decaps_test.json` | `ml_kem_1024` in `tests/wycheproof.rs` |
| `mlkem_1024_encaps_test.json` | `ml_kem_1024` in `tests/wycheproof.rs` (invalid keys only) |
| `rsa_signature_2048_sha{224,256,384,512}_test.json` | `rsa_pkcs1v15` in `tests/wycheproof.rs` |
| `rsa_signature_{3072,4096}_sha{256,384,512}_test.json` | `rsa_pkcs1v15` in `tests/wycheproof.rs` |
| `rsa_pkcs1_{2048,3072,4096}_sig_gen_test.json` | `rsa_pkcs1v15` in `tests/wycheproof.rs` |
| `aes_wrap_test.json` | `aes_kw_wycheproof_vectors` in [`tests/aes_kw.rs`](../../aes_kw.rs) |
| `aes_kwp_test.json` | `aes_kwp_wycheproof_vectors` in [`tests/aes_kw.rs`](../../aes_kw.rs) |
| `mldsa_65_sign_seed_test.json` | `ml_dsa_kat::sign_seed_vectors_reproduce_signatures` in [`tests/pqc.rs`](../../pqc.rs) |
| `mldsa_65_verify_test.json` | `ml_dsa_kat::verify_vectors_accept_valid_reject_invalid` in [`tests/pqc.rs`](../../pqc.rs) |

Every test in `tests/wycheproof.rs` asserts that the cases it ran plus the cases
it skipped equal the file's `numberOfTests`, and prints both counts (visible
with `-- --nocapture`).

## Result semantics

Wycheproof's `result` is three-way. `valid` and `invalid` are asserted.
`acceptable` passes either way, except where the algorithm defines a single
correct output: X25519 `acceptable` cases must still produce the expected
shared secret.

## Skipped cases

Only what the public API cannot express is skipped.

- **AES-GCM, AES-KW / AES-KWP: 192-bit keys** — the library exposes only 128-
  and 256-bit keys.
- **AES-GCM-SIV, ChaCha20-Poly1305, Ascon-AEAD128: cases with AAD** — those
  APIs take no AAD. AES-GCM has an AAD API, so its AAD cases run.
- **Nonce sizes the API does not accept** are not skipped: the test asserts
  that encryption and decryption reject them.
- **HMAC truncated-tag groups** — the library returns the full tag, so these
  compare the leading bytes and do not call `verify`.
- **ML-KEM `valid` encapsulation cases** — encapsulation is randomized and
  takes no `m`, so only the invalid-key cases can be checked.
- **RSA SHA-1 groups in the `sig_gen` files** — the test builds the
  `DigestInfo` itself and only does so for SHA-224/256/384/512.
- **ML-DSA** — `cas_lib::pqc::ml_dsa` uses ML-DSA-65, the pure (non-prehashed)
  external interface, and deterministic signing with an empty context. Cases
  with a non-empty `ctx`, a precomputed `mu`, or a randomized (hedged)
  signature cannot be expressed through that API.

RSA applies because `CASRSA` signs and verifies the caller-supplied
`DigestInfo` with PKCS#1 v1.5 padding (`Pkcs1v15Sign::new_unprefixed()`); the
test builds that `DigestInfo` from each vector's `msg`.

The ML-DSA `sign_seed` file is used rather than a NIST ACVP `sigGen` file
because ACVP supplies the expanded private key, whereas the API is seed-based:
each group's 32-byte `privateSeed` is exactly what the signing key serializes
to, so deterministic signing must reproduce the expected `sig` byte for byte.

## Not covered

- **HPKE** — the library uses DHKEM(X25519, HKDF-SHA256) with HKDF-SHA512 and
  AES-256-GCM. The `hpke_x25519_*` files have no group with that combination.
- **ML-KEM seed-form files** (`mlkem_1024_test.json`, `mlkem_1024_keygen_seed_test.json`)
  — the API takes the expanded 3168-byte key and has no seed-based key generation.
- **Other ML-DSA files** (`mldsa_65_sign_noseed`, ML-DSA-44 / 87) — the API is
  seed-based and exposes only ML-DSA-65.
- **RSA 1024 / 1536-bit `sig_gen`, RSA-PSS, RSA-OAEP, SHA-3 and SHA-512/t
  `rsa_signature_*` files** — below the 2048-bit minimum the library generates,
  or schemes the library does not implement; the remaining hash variants only
  change the `DigestInfo` the test itself builds.
- **PBKDF2** — the library uses HMAC-SHA3-256; Wycheproof has PBKDF2 vectors
  for HMAC-SHA1/224/256/384/512 only.
- **HKDF** — used internally with a fixed `info`; not exposed.
- **SHA-2 / SHA-3 / BLAKE2, SLH-DSA, Argon2, bcrypt, scrypt, Zstandard** —
  Wycheproof has no vectors for them. SHA-2 and SHA-3 are covered by the NIST
  files in `tests/data/hashers/`.
