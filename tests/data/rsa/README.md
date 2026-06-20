# RSA NIST/CAVS test vectors

`SigGen15_186-3.txt` is the CAVS **"SigGen RSA (PKCS#1 Ver 1.5)"** response file
for FIPS 186-4 (mod 2048 / 3072, SHA-224/256/384/512). It is consumed by the
`rsa_pkcs1v15_kat` module in [`tests/asymmetric.rs`](../../asymmetric.rs).

It is the matching scheme for `CASRSA`, which signs/verifies with
`Pkcs1v15Sign::new_unprefixed()` (RSASSA-PKCS#1 v1.5). The PSS (`SigGenPSS_*`) and
X9.31 (`SigGen931_*`) files do **not** apply, and the `KeyGen_*` files cannot be
used as known-answer tests because keys are generated from `OsRng`.

## Adding the file

Place the CAVS file at:

    tests/data/rsa/SigGen15_186-3.txt

Source: NIST CAVP "RSA2 Validation System" example vectors
(<https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss2/rsa2vs.pdf>
references the format; the example `.txt` files ship in the FIPS 186-3 RSA
example archive). Each case provides `n, e, d, Msg, S`; the tests rebuild a
public key from `(n, e)` and exercise the `verify` path, since the file omits the
primes `p, q` needed to reconstruct a private-key PEM.
