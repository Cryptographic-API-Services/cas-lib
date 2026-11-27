# HMAC known-answer test vectors

Every `CASHMAC` implementation in `src/message/hmac.rs` is checked against
NIST vectors committed here, consumed by [`tests/message.rs`](../../message.rs),
and against Project Wycheproof (downloaded at test time, see
[`../wycheproof/README.md`](../wycheproof/README.md)).

| Struct | NIST vectors | Other committed vectors |
|---|---|---|
| `HMACSha256` | `HMAC.txt` `[L=32]` (CAVP) | |
| `HMACSha384` | `HMAC.txt` `[L=48]` (CAVP) | |
| `HMACSha512` | `HMAC.txt` `[L=64]` (CAVP) | `HMAC-SHA512-RFC4231.txt` |
| `HMACSha3_256` | `acvp/HMAC-SHA3-256.json` (ACVP) | |
| `HMACSha3_384` | `acvp/HMAC-SHA3-384.json` (ACVP) | |
| `HMACSha3_512` | `acvp/HMAC-SHA3-512.json` (ACVP) | |

The library always returns the full-length tag. A vector with a shorter tag is
checked against the leading bytes of the computed tag. `verify` takes only a
full-length tag, so the tests call it only for full-length vectors.

## `HMAC.txt`: NIST CAVP HMACVS

The CAVS 11.0 HMAC response file `HMAC.rsp` from NIST CAVP's
[`hmactestvectors.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip)
(format: [HMACVS](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/HMACVS.pdf)).
Only the header comments were edited. The `[L=32]` (SHA-256), `[L=48]` (SHA-384)
and `[L=64]` (SHA-512) blocks are byte-for-byte NIST's, apart from CRLF line
endings converted to LF. The `[L=20]` (SHA-1) and `[L=28]` (SHA-224) blocks are
left out because cas-lib has no HMAC over those hashes. `L` is the hash
output size and `Tlen` the tag length in bytes:

| Block | Records | Full-length (`Tlen = L`) | `Tlen` values |
|---|---|---|---|
| `[L=32]` SHA-256 | 225 | 75 | 16, 24, 32 |
| `[L=48]` SHA-384 | 300 | 75 | 24, 32, 40, 48 |
| `[L=64]` SHA-512 | 375 | 75 | 32, 40, 48, 56, 64 |

CAVP has no HMAC-SHA3 response files, so the SHA-3 vectors come from ACVP.

## `acvp/`: NIST ACVP HMAC-SHA3

The `internalProjection.json` files of
[usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server) at commit
`975de31eb83d87039ec88934fdc47d8c312b892d`, committed unmodified and renamed:

| File | Upstream path | SHA-256 |
|---|---|---|
| `acvp/HMAC-SHA3-256.json` | `gen-val/json-files/HMAC-SHA3-256-2.0/internalProjection.json` | `a13ad967cf3752a11d5cb9bcb3e8eb10ea808f7c9087b768e434ccc6bbed4c89` |
| `acvp/HMAC-SHA3-384.json` | `gen-val/json-files/HMAC-SHA3-384-2.0/internalProjection.json` | `3d4746555e0b50e8ffad167f93d42460499dcb5590eae76d7d4fcfb73a77e71d` |
| `acvp/HMAC-SHA3-512.json` | `gen-val/json-files/HMAC-SHA3-512-2.0/internalProjection.json` | `d80da2085d5f2fcaabf96282b9d20737af4184de1aa749efa93b262612f6fced` |

Each file has one `AFT` test group of 150 cases with `key`, `msg` and the
expected `mac`. Lengths (`keyLen`, `msgLen`, `macLen`) are in bits and are all
whole bytes. Keys run from 1 to 256 bytes, and two cases per file have an empty
message. Every `mac` is truncated (10 to 20 bytes), so these files check `sign`
but never call `verify`. Wycheproof covers `verify` with full-length HMAC-SHA3
tags.
