# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.2](https://github.com/Cryptographic-API-Services/cas-lib/compare/v0.7.1...v0.7.2) - 2026-11-27

### Other

- Merge pull request #176: chore(deps): upgrade argon2 to 0.6 and scrypt to 0.12
- Merge pull request #174: chore(deps): upgrade zstd to 0.14
- Merge deps/rustcrypto-upgrades ([#175](https://github.com/Cryptographic-API-Services/cas-lib/pull/175)) into deps/168-password-hash-0.6
- *(deps)* upgrade argon2 to 0.6 and scrypt to 0.12
- *(deps)* upgrade ed25519-dalek to 3.0 and curve25519-dalek to 5
- *(deps)* upgrade zstd to 0.14
- *(deps)* upgrade sha2, sha3, blake2, hmac and pbkdf2 to digest 0.11

## [0.7.1](https://github.com/Cryptographic-API-Services/cas-lib/compare/v0.7.0...v0.7.1) - 2026-11-26

### Added

- add HKDF-SHA256 and HKDF-SHA512 (extract, expand, derive) ([#152](https://github.com/Cryptographic-API-Services/cas-lib/pull/152))

## [0.7.0](https://github.com/Cryptographic-API-Services/cas-lib/compare/v0.6.0...v0.7.0) - 2026-11-25

Upgrades every AEAD dependency to `aead` 0.6 (#85), so the crate builds one `aead`/`aes` stack. The public API is unchanged, and so are the key, nonce and ciphertext formats: keys and data from 0.6.0 keep working.

### Changed

- **AEAD dependencies on `aead` 0.6** (#85): `aes-gcm` 0.11 (`aes` 0.9), `aes-gcm-siv` 0.12, `chacha20poly1305` 0.11, `ascon-aead` 0.6, `hpke` 0.15 and `aes-kw` 0.3.

### Fixed

- **HPKE `info` length** (#85): `CASHPKE::encrypt` / `decrypt` return `CasError::InvalidInput` for an `info` longer than 65,530 bytes. `hpke` panics on one that long, and a panic must not unwind across the FFI boundary.

### Security

- AES-KW / AES-KWP unwrap zeroizes its intermediate buffer holding the unwrapped key.

## [0.6.0](https://github.com/Cryptographic-API-Services/cas-lib/compare/v0.5.1...v0.6.0) - 2026-11-25

Fixes the two Info-level findings from the November 2026 security review (#121, #122), the last open items from #103 and #104.

### Breaking changes

- **PQC result structs are no longer `#[repr(C)]`** (#122): `MlKemKeyPair`, `MlKemEncapResult`, `MlKemSharedSecret`, `SlhDsaKeyPair` and `MlDsaKeyPair`. They hold `Vec<u8>`, which has no stable layout, so the attribute never made them FFI-safe. Rust code is unaffected. FFI layers must copy the fields into their own types (the binding crates already do).

### Added

- **Re-derivable Argon2 AES keys** (#121): `CASArgon::generate_salt`, `derive_aes_128_key_with_salt` and `derive_aes_256_key_with_salt`. The same password and salt always give the same key. Argon2id runs with fixed parameters (`KDF_MEMORY_COST_KIB` 19 MiB, `KDF_ITERATIONS` 2, `KDF_PARALLELISM` 1), pinned by a libargon2 known-answer test so a stored salt keeps working across dependency updates. Salts shorter than `MIN_SALT_LENGTH` (16 bytes) return `InvalidParameters`.

### Deprecated

- `CASArgon::derive_aes_128_key` / `derive_aes_256_key` (#121): they use a random salt and discard it, so the key can never be derived again. Use `generate_salt` and the `*_with_salt` functions.

### Security

- **HPKE** (#122): key generation and encryption draw randomness from `OsRng` directly, like the rest of the crate, instead of seeding a `StdRng`. The docs now say that `generate_info_str` (and the random `info` from `generate_key_pair`) is not domain separation: pass a fixed, application-specific `info`.
- **Smaller published crate** (#122): an `include` list limits the package to `src/`, `LICENSE`, `README.md`, `CHANGELOG.md` and `docs/EXAMPLES.md`. Workflows, tests, test vectors and editor config are no longer uploaded to crates.io.
- Wycheproof test downloads only use HTTPS, including after redirects (#122).

### Documentation

- `docs/EXAMPLES.md`: the Argon2 key-derivation example uses `generate_salt` and `derive_aes_256_key_with_salt`, the HPKE examples use application-specific `info` strings, and the post-quantum section notes that the PQC crates are pre-1.0 and unaudited and that the result structs are not FFI types.

## [0.5.1](https://github.com/Cryptographic-API-Services/cas-lib/compare/v0.5.0...v0.5.1) - 2026-11-25

Dependency updates only. The public API is unchanged, and so are the key, ciphertext and signature formats: keys and data from 0.5.0 keep working.

### Security

- **ml-kem 0.3.4** ([#149](https://github.com/Cryptographic-API-Services/cas-lib/pull/149)): hardened zeroization and constant-time equality checks, and secret key material is redacted from `Debug` output. `Cargo.toml` now requires 0.3.4, so downstream builds can't resolve 0.3.3.
- **ML-KEM buffers are zeroized** ([#148](https://github.com/Cryptographic-API-Services/cas-lib/pull/148)): ml-kem's `zeroize` feature is enabled, and the intermediate expanded decapsulation key, the consumed secret-key input and the shared-secret buffers are wiped after use.

### Other

- Dependency updates ([#148](https://github.com/Cryptographic-API-Services/cas-lib/pull/148)): bcrypt 0.18 → 0.19, ml-kem 0.2 → 0.3, x25519-dalek 2 → 3, hkdf 0.12 → 0.13, and patch updates to getrandom (0.4.3), ml-dsa (0.1.2) and serde_json (1.0.154).
- ML-KEM-1024 secret keys keep the 3168-byte expanded encoding. ml-kem 0.3 deprecates it in favour of 64-byte seeds, and moving to seeds will be a separate, breaking release.
- HKDF-SHA256 in the X25519 key-derivation helpers now uses sha2 0.11 (required by hkdf 0.13), through a `sha2-hkdf` dependency alias. Derived keys are unchanged.

## [0.5.0](https://github.com/Cryptographic-API-Services/cas-lib/compare/v0.4.0...v0.5.0) - 2026-11-25

Fixes the five Medium-severity findings from the November 2026 security review (#103): #108–#112. With 0.3.0 (Low, #106) and 0.4.0 (High), every Low-or-above finding is fixed, and `cargo audit` reports no advisories. The Info-level notes are tracked in #121 and #122.

### Breaking changes

- **RSA signatures are now standard RS256** ([#141](https://github.com/Cryptographic-API-Services/cas-lib/pull/141), #111): `sign` / `verify` take the **message** and use RSASSA-PKCS1-v1_5 with SHA-256 and a DigestInfo prefix. They interoperate with OpenSSL, WebCrypto and JWS `RS256`, and messages of any length work. Signatures made by 0.4 and earlier (unprefixed PKCS#1 v1.5 over caller bytes) **no longer verify**.
- **RSA keys:** `rsa` 0.10 refuses imported private keys whose two primes differ greatly in size (`InvalidPemKey`). `verify` now accepts public keys up to 8192 bits (was 4096). Key generation still allows 2048, 3072 and 4096 bits.
- **X25519** ([#140](https://github.com/Cryptographic-API-Services/cas-lib/pull/140), #112): `X25519::diffie_hellman` returns `CasError::InvalidKey` for low-order peer public keys, which force an all-zero shared secret.
- **X25519 key-derivation helpers** ([#140](https://github.com/Cryptographic-API-Services/cas-lib/pull/140), #112): every `key_from_x25519_shared_secret` (AES-128/256-GCM, AES-128/256-GCM-SIV) now takes `(shared_secret, public_key_a, public_key_b)`. The public keys can be passed in either order. The derived key is bound to the cipher and to both public keys, so it differs from 0.4's: **both peers must upgrade together.**
- **Password-hasher cost bounds** ([#138](https://github.com/Cryptographic-API-Services/cas-lib/pull/138), #110). Out-of-range values return `InvalidParameters`:
  - Argon2: memory 19–4096 MiB, iterations 1–10, parallelism 1–16.
  - scrypt: log₂N 10–20, `r` 1–32, `p` 1–16.
  - bcrypt: cost 10–16. The docs used to say 4–31.

  `verify_password` checks the costs in the stored hash against the **upper** bounds before doing any work, so hostile hashes such as `$2b$31$…` are refused. Older hashes below the minimums still verify.

### Added

- `CASRSAEncryption::sign_pss` / `verify_pss`: RSASSA-PSS with SHA-256 (PS256), recommended for new designs ([#141](https://github.com/Cryptographic-API-Services/cas-lib/pull/141)).
- Cost-bound constants: `argon2::{MIN,MAX}_MEMORY_COST_MIB`, `argon2::{MIN,MAX}_ITERATIONS`, `argon2::{MIN,MAX}_PARALLELISM`, `scrypt::{MIN_LOG_N, MAX_LOG_N, MAX_BLOCK_SIZE, MAX_PARALLELISM}` and `bcrypt::{BCRYPT_MIN_COST, BCRYPT_MAX_COST}` ([#138](https://github.com/Cryptographic-API-Services/cas-lib/pull/138)).

### Fixed

- Argon2 `hash_password_parameters` no longer wraps `memory_cost * 1024` in release builds or panics in debug builds; it returns `InvalidParameters`. The rustdoc now says the unit is MiB, not KiB ([#137](https://github.com/Cryptographic-API-Services/cas-lib/pull/137), #109).

### Security

- **All `cargo audit` advisories cleared** ([#139](https://github.com/Cryptographic-API-Services/cas-lib/pull/139), [#141](https://github.com/Cryptographic-API-Services/cas-lib/pull/141), #108): from 7 vulnerabilities and 13 warnings to **none**.
  - RUSTSEC-2023-0071 (Marvin): `rsa` 0.10.
  - RUSTSEC-2026-0387: `hpke` without the unused `p256` feature.
  - The zstd stack: floor raised to `zstd` 0.13.6, so downstream lockfiles get `zstd-safe` 7.4.2 / `zstd-sys` 2.2.0.
  - `ctutils`, `anyhow`, and the yanked `der` / `spin`: lockfile updates.

### CI

- New `cargo audit` workflow on every PR, on pushes to `main` and weekly. Unsound and yanked warnings fail it. Dependabot now covers Cargo and GitHub Actions ([#139](https://github.com/Cryptographic-API-Services/cas-lib/pull/139)).

## [0.4.0](https://github.com/Cryptographic-API-Services/cas-lib/compare/v0.3.0...v0.4.0) - 2026-11-25

Fixes the last High-severity finding from the November 2026 security review (#103): a decompression bomb in `compression::zstd::decompress` (#107). The Medium findings are tracked in #108–#112.

### Breaking changes

- **zstd output limit:** `decompress` produces at most `DEFAULT_MAX_DECOMPRESSED_SIZE` (64 MiB) and returns `CasError::DecompressionLimitExceeded` for anything larger, instead of growing its buffer until allocation fails and the process aborts. Callers with larger trusted data should use `decompress_with_limit`. ([#135](https://github.com/Cryptographic-API-Services/cas-lib/pull/135))
- **New `CasError` variant:** `DecompressionLimitExceeded`, FFI error code **13**, appended per the ABI contract. Exhaustive matches, including the FFI binding crates' error-code mappings, must handle it. ([#135](https://github.com/Cryptographic-API-Services/cas-lib/pull/135))
- **Legacy zstd frames rejected:** zstd's default features are disabled, which removes the pre-v0.8 legacy-format decoders. ([#135](https://github.com/Cryptographic-API-Services/cas-lib/pull/135))

### Added

- `compression::zstd::decompress_with_limit(data, max_output_size)` and the `DEFAULT_MAX_DECOMPRESSED_SIZE` constant. ([#135](https://github.com/Cryptographic-API-Services/cas-lib/pull/135))

### Security

- Decompression output is capped (above), and frames that declare a back-reference window larger than 128 MiB are refused before the window is allocated. ([#135](https://github.com/Cryptographic-API-Services/cas-lib/pull/135))

### Documentation

- `docs/EXAMPLES.md` documents the limit with a `decompress_with_limit` example, and adds the missing Compression entry to the table of contents.

## [0.3.0](https://github.com/Cryptographic-API-Services/cas-lib/compare/v0.2.95...v0.3.0) - 2026-11-25

Fixes the Low-severity findings from the November 2026 security review (#103). The publish-pipeline High finding (#106) is also fixed in this release; the remaining High and Medium findings are tracked in #107–#112.

### Breaking changes

- **PBKDF2:** `pbkdf2::derivation` now returns `CasResult<Pbkdf2Result>` and `pbkdf2::derivation_with_salt` returns `CasResult<Vec<u8>>`. Both reject fewer than 600,000 iterations (`MIN_ITERATIONS`), and `derivation_with_salt` rejects salts shorter than 16 bytes (`MIN_SALT_LENGTH`). Keys stored with weaker parameters can no longer be re-derived and must be migrated. ([#127](https://github.com/Cryptographic-API-Services/cas-lib/pull/127))
- **HPKE:** `CASHybrid::encrypt` and `decrypt` take a new trailing `aad: Vec<u8>` argument. Pass `vec![]` to keep the old behaviour. ([#132](https://github.com/Cryptographic-API-Services/cas-lib/pull/132))
- **bcrypt:** hashing and verifying return `CasError::InvalidParameters` for passwords longer than 72 UTF-8 bytes instead of silently truncating them. Existing hashes of passwords up to 72 bytes still verify. ([#130](https://github.com/Cryptographic-API-Services/cas-lib/pull/130))
- **RSA:** `sign` and `verify` return `CasError::InvalidParameters` for keys under 2048 bits. ([#125](https://github.com/Cryptographic-API-Services/cas-lib/pull/125))
- **Ed25519:** `ed25519_verify_with_key_pair` uses strict verification, like `ed25519_verify_with_public_key`. Malleable or crafted signatures that used to verify now return `Ok(false)`. ([#129](https://github.com/Cryptographic-API-Services/cas-lib/pull/129))
- **PQC key types:** `MlKemKeyPair`, `MlKemEncapResult`, `MlKemSharedSecret`, `SlhDsaKeyPair` and `MlDsaKeyPair` no longer derive `Debug`; their `Debug` output redacts the secret bytes. ([#131](https://github.com/Cryptographic-API-Services/cas-lib/pull/131))

### Added

- `CASAeadSeal` with `seal` / `open` for AES-128/256-GCM, AES-128/256-GCM-SIV, ChaCha20-Poly1305 and Ascon-AEAD. `seal` generates the nonce internally and returns `nonce || ciphertext || tag`. This is now the recommended AEAD API. ([#132](https://github.com/Cryptographic-API-Services/cas-lib/pull/132))
- AAD variants for every AEAD: `CASAES128SIVAadEncryption`, `CASAES256SIVAadEncryption`, `Chacha20Poly1305AadEncryption` and `CASAsconAeadAad`. ([#132](https://github.com/Cryptographic-API-Services/cas-lib/pull/132))
- Constants `pbkdf2::MIN_ITERATIONS`, `pbkdf2::MIN_SALT_LENGTH` and `bcrypt::BCRYPT_MAX_PASSWORD_BYTES`.

### Security

- Hash `verify_*` functions compare digests in constant time. ([#124](https://github.com/Cryptographic-API-Services/cas-lib/pull/124))
- Intermediate key material allocated by the crate is zeroized, and PQC key types implement `Zeroize`. Secrets returned to the caller are still plain `Vec<u8>`: FFI binding layers must zero them before freeing. ([#131](https://github.com/Cryptographic-API-Services/cas-lib/pull/131))

### Documentation

- `CASSHA` rustdoc names SHA3-256 / SHA3-512 instead of SHA-256 / SHA-512. ([#126](https://github.com/Cryptographic-API-Services/cas-lib/pull/126))

### Other

- Releases are now made with release-plz, and the publish workflow is hardened. ([#106](https://github.com/Cryptographic-API-Services/cas-lib/issues/106))
- New dependencies: `subtle` 2.6 and `zeroize` 1.8.
