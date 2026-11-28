# ECDSA and ECDH known-answer test vectors

The `cas_lib::ecc` module (`CASEcdsa*`, `CASEcdh*`) is checked against the
files committed here, consumed by `known_answers` in
[`tests/ecc.rs`](../../ecc.rs), and against Project Wycheproof (downloaded at
test time, see [`../wycheproof/README.md`](../wycheproof/README.md)).

NIST has no vectors for secp256k1, so for that curve the coverage is the
Wycheproof files plus the round-trip tests.

| File | Source | Exercised by | Records |
|---|---|---|---|
| `SigVer.rsp` | NIST CAVP FIPS 186-4 ECDSA | `nist_sigver` | 15 per curve (`[P-256,SHA-256]`, `[P-384,SHA-384]`, `[P-521,SHA-512]`) |
| `PKV.rsp` | NIST CAVP FIPS 186-4 ECDSA | `nist_public_key_validation` | 12 per curve (`[P-256]`, `[P-384]`, `[P-521]`) |
| `KAS_ECC_CDH_PrimitiveTest.txt` | NIST CAVP SP 800-56A ECC CDH | `nist_ecc_cdh` | 25 per curve (`[P-256]`, `[P-384]`, `[P-521]`) |
| `rfc6979-A.2.5-A.2.7.txt` | RFC 6979 appendix A.2.5–A.2.7 | `rfc6979_deterministic_signatures` | "sample" and "test" with each curve's hash (6 signatures) |

## NIST CAVP files

From NIST CAVP:

- [`186-4ecdsatestvectors.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip)
  for `SigVer.rsp` and `PKV.rsp`;
- [`ecccdhtestvectors.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors.zip)
  for `KAS_ECC_CDH_PrimitiveTest.txt`.

The header comments and the kept blocks are byte-for-byte NIST's, apart from
CRLF line endings converted to LF. The blocks for other curves (P-192, P-224,
the binary K- and B- curves) are left out, because cas-lib has no ECC over
them. `SigVer.rsp` also leaves out the P-256/384/521 blocks for hashes other
than each curve's own: the library always hashes with SHA-256 for P-256,
SHA-384 for P-384 and SHA-512 for P-521.

The tests turn the raw values into the PEM keys the API takes: `Qx`/`Qy` and
`QCAVSx`/`QCAVSy` become an SPKI PEM, assembled byte by byte so that the PKV
file's invalid points reach the library instead of being rejected by the test
helper. `dIUT` becomes a PKCS#8 PEM, and `R`/`S` a P1363 `r || s` signature
(and its DER form). See [`tests/common/ec.rs`](../../common/ec.rs).

## RFC 6979

Lines 1799–2302 of [`rfc6979.txt`](https://www.rfc-editor.org/rfc/rfc6979.txt)
(sections A.2.5 to A.2.7, including the page breaks), unmodified. Only the
signatures made with each curve's own hash are checked; the others use a hash
the API does not offer.

## Checksums

| File | SHA-256 |
|---|---|
| `SigVer.rsp` | `f90f4018fee2eda59ddc52175a97ac4ec2a743851abe3b747b6db1055fb0ce2b` |
| `PKV.rsp` | `e9017abc2c2b02cd274c6a039dd856daa3204bd9f82087d347209520cd37ba09` |
| `KAS_ECC_CDH_PrimitiveTest.txt` | `18f23c594113151b3bb13b5bba69c2d3f25c1cc76399bf0dbbc2a091262767fe` |
| `rfc6979-A.2.5-A.2.7.txt` | `b72d0b63d8fb5681439d347491d404881df3c8c9ce4b913acc121a05497632de` |

The upstream files, before trimming:

| Upstream file | SHA-256 |
|---|---|
| `186-4ecdsatestvectors.zip` | `fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752` |
| `186-4ecdsatestvectors/SigVer.rsp` | `e9841c3d12e323042751460d0b8ef4bc59c2640105ec7da4852775f80ab10191` |
| `186-4ecdsatestvectors/PKV.rsp` | `1d33551c1a199b1fc2b0e4075cdfd52d4830503ef37e6b16f04ce617d524f3f1` |
| `ecccdhtestvectors.zip` | `5fff092551f2d72e89a3d9362711878708f9a14b502f0dfae819649105b0ea39` |
| `KAS_ECC_CDH_PrimitiveTest.txt` | `456068d3f8aad8ac62a03d19ed3173f00ad51f42b51aeab4753c20f30c01cf23` |
| `rfc6979.txt` | `456e8f17558fdbd206f968b96fc6f1b4a71ea331ab30ad17f711ab3adaa7d701` |
