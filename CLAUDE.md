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

Most cryptographic modules follow the same two-file pattern:

- `cas_<module>.rs` — defines the public trait(s) and the concrete unit struct(s) that implement them
- `<algorithm>.rs` — contains the trait `impl` block with the actual cryptographic logic

For example, `password_hashers/cas_password_hasher.rs` declares the `CASPasswordHasher` trait and the `CASArgon2` / `CASBcrypt` / etc. unit structs; `password_hashers/argon2.rs` provides the implementation.

A few modules deviate: `asymmetric` puts its trait in `types.rs` with the `impl` in `cas_rsa.rs` (inverting the naming), and `pqc` (`ml_kem`, `slh_dsa`) exposes free functions rather than trait methods.

All modules are declared and made public in [src/lib.rs](src/lib.rs). Note that `lib.rs` only declares the module tree — it does not add any top-level `pub use` re-exports, so consumers reference items by their full module path (e.g. `cas_lib::symmetric::cas_symmetric_encryption::CASAES256Encryption`).

### Modules

| Module | Algorithms |
|---|---|
| `symmetric` | AES-128-GCM, AES-256-GCM, AES-KW/KWP, ChaCha20-Poly1305 |
| `hashers` | BLAKE2b, BLAKE2s, SHA-2, SHA-3 |
| `password_hashers` | Argon2, bcrypt, scrypt, PBKDF2 |
| `asymmetric` | RSA (key generation, RS256 and PS256 sign/verify) |
| `signatures` | Ed25519 |
| `key_exchange` | X25519 |
| `hybrid` | HPKE |
| `sponges` | ASCON-AEAD |
| `message` | HMAC, CMAC (AES-128, AES-256) |
| `kdf` | HKDF-SHA256, HKDF-SHA512 (extract, expand, derive) |
| `pqc` | ML-KEM, SLH-DSA, ML-DSA |
| `compression` | Zstandard |

### Data Conventions

- Binary inputs/outputs use `Vec<u8>`.
- Asymmetric keys are PEM-encoded strings.
- Every AEAD (AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, Ascon-AEAD) implements `CASAeadSeal` (`symmetric/cas_symmetric_encryption.rs`): `seal` draws the nonce internally from the OS random number generator (`getrandom`) and returns `nonce || ciphertext || tag`, and `open` splits it back apart. Both take optional AAD. This is the recommended API.
- The older `encrypt_plaintext` / `decrypt_ciphertext` (Ascon: `encrypt` / `decrypt`) and `*_with_aad` functions take a caller-supplied nonce (from `generate_nonce`); the caller must never reuse a nonce under the same key, and each such function documents that risk. Every AEAD has an `*_with_aad` variant; HPKE `encrypt` / `decrypt` take an `aad` argument.
- Secret key material: zeroize intermediate secret buffers the crate allocates (use `zeroize::Zeroizing`; to return such a buffer without a copy, `std::mem::take(&mut *buf)`). Returned secrets stay plain `Vec<u8>`/`String` owned by the caller: the FFI binding layers must zero them before freeing. Structs holding secrets must not derive `Debug`; write a `Debug` impl that redacts the secret fields (see `src/pqc/cas_pqc.rs`).
- Never decode untrusted input into an unbounded buffer: an abort on allocation failure can't be caught across the FFI boundary. `compression::zstd::decompress` caps output at `DEFAULT_MAX_DECOMPRESSED_SIZE` (64 MiB) and the decoder window at 2^27 bytes; `decompress_with_limit` takes an explicit cap and returns `CasError::DecompressionLimitExceeded` past it.
- Fallible operations return `CasResult<T>` (`Result<T, CasError>` from [src/error.rs](src/error.rs)) rather than panicking — a panic unwinding across the FFI boundary is undefined behavior. Infallible operations (e.g. hashing in `hashers`) return their value directly. The `CasError` variants map to stable numeric codes consumed by the FFI binding crates; that mapping is an append-only ABI contract (see the doc comment on `CasError`).

### Test Vectors

NIST/FIPS known-answer test vectors are committed in [tests/data/](tests/data/) and are consumed by the integration tests in [tests/symmetric.rs](tests/symmetric.rs), [tests/hashers.rs](tests/hashers.rs), [tests/message.rs](tests/message.rs) (HMAC, CMAC), and [tests/asymmetric.rs](tests/asymmetric.rs). When adding a new algorithm or variant, add the corresponding test vectors there.

Project Wycheproof vectors are **not** committed. [tests/common/wycheproof.rs](tests/common/wycheproof.rs) resolves upstream `main` of `C2SP/wycheproof` to its current commit on every test run (via `git ls-remote`), downloads the files with `curl`, and caches them per commit under `target/tmp/wycheproof/`. Tests therefore need network access, and a new upstream case the library gets wrong fails the build by design; set `WYCHEPROOF_REF` to a commit SHA to reproduce an earlier run. They are consumed by [tests/wycheproof.rs](tests/wycheproof.rs), [tests/aes_kw.rs](tests/aes_kw.rs) and [tests/pqc.rs](tests/pqc.rs); see [tests/data/wycheproof/README.md](tests/data/wycheproof/README.md) for details and adding files.

### Usage Examples

Usage examples for every public API live in [docs/EXAMPLES.md](docs/EXAMPLES.md). **Whenever you add, change, or remove a public API (a new algorithm, a new trait method or free function, a changed signature or return type), update the examples in the same change**: add a complete, runnable `fn main()` example for anything new, fix any example that no longer compiles, and keep the Table of Contents in sync. Examples must use the real module paths and handle `CasResult` (e.g. `.unwrap()` or `?`) so they compile when pasted into a fresh crate that depends on `cas-lib`.

### CI and releases

- The toolchain is pinned in [rust-toolchain.toml](rust-toolchain.toml); rustup installs it on first use. Every workflow runs cargo with `--locked`, and actions are pinned to commit SHAs (keep the `# vX.Y.Z` comment when bumping one).
- PRs run `cargo build --release --locked` and `cargo test --release --locked` on Linux, Windows, and macOS (`.github/workflows/linux-pr.yml`, `.github/workflows/windows-pr.yml`, `.github/workflows/macos-pr.yml`).
- `cargo audit` (`.github/workflows/audit.yml`) checks `Cargo.lock` against the RustSec database on every PR, on pushes to `main`, and weekly, since new advisories land without any change here. Vulnerabilities and `unsound`/`yanked` warnings fail it; `unmaintained` ones don't. cargo-audit's version is pinned in the workflow. Run it locally with `cargo install cargo-audit --locked` and then `cargo audit --deny unsound --deny yanked`. Fix an advisory with a targeted `cargo update -p <crate>`, not a blanket `cargo update`, and raise the floor in `Cargo.toml` when downstream crates must not resolve the vulnerable version. Don't ignore an advisory without saying why in the PR.
- Dependabot (`.github/dependabot.yml`) opens weekly PRs for `cargo` and `github-actions` after a 7-day cooldown. Cargo patch updates come grouped in one PR, minor and major updates come one PR each (a minor bump of a 0.x crate is breaking), and action updates come in one PR. Titles are `chore(deps): …` / `ci(deps): …`, so they pass the PR title check.
- **PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/)** (`.github/workflows/pr-title.yml`). PRs are squash-merged, so the title becomes the commit that release-plz turns into a `CHANGELOG.md` line: `feat:` → Added, `fix:` → Fixed, `security:` → Security, `docs:` → Documentation, anything else → Other. Use `!` (e.g. `feat!:`) for a breaking change.
- Releases use [release-plz](https://release-plz.dev) (`release-plz.toml`, `.github/workflows/publish-main.yml`). Each push to `main` tests and packages the crate, publishes to crates.io only if the `Cargo.toml` version isn't published yet (then tags `v<version>` and creates a GitHub Release from the `CHANGELOG.md` entry), and opens or updates a release PR that bumps the version and writes the changelog. **Don't bump the version or edit `CHANGELOG.md` by hand in feature PRs**; merge the release PR instead. `publish-main.yml` keeps that name because the crates.io trusted publisher is bound to it.

The dev profile sets `opt-level = 3` for `crypto-bigint` and `crypto-primes` (used by the `rsa` crate) to keep RSA key generation fast during local development.
