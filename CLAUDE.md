# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`cas-lib` is a Rust cryptographic abstraction library that wraps [RustCrypto](https://github.com/RustCrypto) and [Dalek-Cryptography](https://github.com/dalek-cryptography) crates behind a unified trait-based API. It targets FFI consumers (C, TypeScript, Python, .NET) and is published to crates.io.

## Commands

```bash
# Build
cargo build --release

# Run all tests
cargo test

# Run a single test file (e.g. symmetric, password_hashers, hashers, etc.)
cargo test --test symmetric

# Run a specific test by name within a file
cargo test --test password_hashers argon2

# Publish (requires CARGO_REGISTRY_TOKEN)
cargo publish
```

## Architecture

### Trait-Based Module Pattern

Every cryptographic module follows the same two-file pattern:

- `cas_<module>.rs` — defines the public trait(s) and the concrete unit struct(s) that implement them
- `<algorithm>.rs` — contains the trait `impl` block with the actual cryptographic logic

For example, `password_hashers/cas_password_hasher.rs` declares the `CASPasswordHasher` trait and the `CASArgon2` / `CASBcrypt` / etc. unit structs; `password_hashers/argon2.rs` provides the implementation.

All modules are declared in [src/lib.rs](src/lib.rs) and re-exported from there.

### Modules

| Module | Algorithms |
|---|---|
| `symmetric` | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| `hashers` | BLAKE2b, BLAKE2s, SHA-2, SHA-3 |
| `password_hashers` | Argon2, bcrypt, scrypt, PBKDF2 |
| `asymmetric` | RSA (encrypt/decrypt, sign/verify) |
| `signatures` | Ed25519 |
| `key_exchange` | X25519 |
| `hybrid` | HPKE |
| `sponges` | ASCON-AEAD |
| `message` | HMAC |
| `pqc` | ML-KEM, SLH-DSA |
| `compression` | Zstandard |

### Data Conventions

- Binary inputs/outputs use `Vec<u8>`.
- Asymmetric keys are PEM-encoded strings.
- Nonces/IVs are generated internally via `OsRng` — callers do not supply them.
- Post-quantum operations (ML-KEM, SLH-DSA) return `Result` types; most other operations panic on internal crypto errors.

### Test Vectors

NIST/FIPS known-answer test vectors live in [tests/data/](tests/data/) and are consumed by the integration tests in [tests/symmetric.rs](tests/symmetric.rs) and [tests/hashers.rs](tests/hashers.rs). When adding a new algorithm or variant, add the corresponding test vectors there.

### CI

- PRs run `cargo build --release` on both Linux and Windows (`.github/workflows/linux-pr.yml`, `.github/workflows/windows-pr.yml`).
- Pushes to `main` trigger an automatic `cargo publish` (`.github/workflows/publish-main.yml`).
- OWASP Dependency Check runs on PRs and `main` (`.github/workflows/owasp-dc.yml`).

The dev profile sets `opt-level = 3` for `num-bigint-dig` (used by the RSA crate) to keep RSA key-generation fast during local development.
