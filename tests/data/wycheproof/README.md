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
  intended: it fails PR builds and the publish on `main` until it is fixed.
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
| `aes_wrap_test.json` | `aes_kw_wycheproof_vectors` in [`tests/aes_kw.rs`](../../aes_kw.rs) |
| `aes_kwp_test.json` | `aes_kwp_wycheproof_vectors` in [`tests/aes_kw.rs`](../../aes_kw.rs) |
| `mldsa_65_sign_seed_test.json` | `ml_dsa_kat::sign_seed_vectors_reproduce_signatures` in [`tests/pqc.rs`](../../pqc.rs) |
| `mldsa_65_verify_test.json` | `ml_dsa_kat::verify_vectors_accept_valid_reject_invalid` in [`tests/pqc.rs`](../../pqc.rs) |

## Skipped cases

- **AES-KW / AES-KWP, 192-bit KEK groups** — the library exposes only 128- and
  256-bit KEKs.
- **ML-DSA** — `cas_lib::pqc::ml_dsa` uses ML-DSA-65, the pure (non-prehashed)
  external interface, and deterministic signing with an empty context. Cases
  with a non-empty `ctx`, a precomputed `mu`, or a randomized (hedged)
  signature cannot be expressed through that API.

The `sign_seed` file is used rather than a NIST ACVP `sigGen` file because ACVP
supplies the expanded private key, whereas the API is seed-based: each group's
32-byte `privateSeed` is exactly what the signing key serializes to, so
deterministic signing must reproduce the expected `sig` byte for byte.
