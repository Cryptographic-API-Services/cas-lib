# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
