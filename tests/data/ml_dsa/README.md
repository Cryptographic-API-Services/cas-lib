# ML-DSA (FIPS 204) Wycheproof test vectors

These are the **Project Wycheproof** known-answer test vectors for ML-DSA-65
(FIPS 204), consumed by the `ml_dsa_kat` module in
[`tests/pqc.rs`](../../pqc.rs). They match `cas_lib::pqc::ml_dsa`, which uses the
`MlDsa65` parameter set, the **pure** (non-prehashed) **external** signing
interface, and the deterministic signing variant with an **empty context**.

| File | Wycheproof test type | Drives |
|---|---|---|
| `mldsa_65_sign_seed_test.json` | `MlDsaSign` | `sign_message` — each group's 32-byte `privateSeed` is exactly the seed our signing key serializes to, so deterministic signing must reproduce the expected `sig` byte-for-byte. |
| `mldsa_65_verify_test.json` | `MlDsaVerify` | `verify_signature` — `valid` cases must verify, `invalid` cases must not. |

Only the empty-`ctx` cases are exercised, since the public API signs/verifies
with an empty context. Cases with a non-empty `ctx` are skipped (the API does
not expose a context parameter). The `sign_seed` file is preferred over a
NIST ACVP `sigGen` file because ACVP supplies the *expanded* private key, whereas
our API is seed-based — Wycheproof's `privateSeed` is the matching representation.

## Source

Project Wycheproof, `testvectors_v1/`:

- <https://github.com/C2SP/wycheproof/blob/master/testvectors_v1/mldsa_65_sign_seed_test.json>
- <https://github.com/C2SP/wycheproof/blob/master/testvectors_v1/mldsa_65_verify_test.json>

These are the same vector files RustCrypto's `ml-dsa` crate validates against.
