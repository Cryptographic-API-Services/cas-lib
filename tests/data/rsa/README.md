# RSA NIST/CAVS test vectors

`SigGen15_186-3.txt` is the CAVS **"SigGen RSA (PKCS#1 Ver 1.5)"** response file
for FIPS 186-4 (mod 2048 / 3072, SHA-224/256/384/512). It is consumed by the
`rsa_pkcs1v15_kat` module in [`tests/asymmetric.rs`](../../asymmetric.rs).

`CASRSA::sign` / `verify` are RSASSA-PKCS1-v1_5 with SHA-256 over the message
(RS256), so the file's `Msg` is passed to the library as is:

- **SHA-256 cases** (20): `verify` must accept `S`, and `sign` must reproduce
  `S` byte for byte with the private key rebuilt from `(n, e, d)` (the primes
  are recovered from them; PKCS#1 v1.5 signing is deterministic).
- **SHA-224/384/512 cases** (60): `verify` must reject them, since their
  `DigestInfo` names another hash.

The PSS (`SigGenPSS_*`) and X9.31 (`SigGen931_*`) files are not committed:
RSASSA-PSS (`sign_pss` / `verify_pss`) is covered by the Wycheproof
`rsa_pss_*_sha256_mgf1_32` files (see [`../wycheproof/README.md`](../wycheproof/README.md)).
The `KeyGen_*` files cannot be used as known-answer tests because keys are
generated from the OS RNG.

## Source

NIST CAVP "RSA2 Validation System" example vectors
(<https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss2/rsa2vs.pdf>
references the format; the example `.txt` files ship in the FIPS 186-3 RSA
example archive). Each case provides `n, e, d, SHAAlg, Msg, S`.
