# Examples

This document provides runnable examples for each cryptographic module in `cas-lib`.
Most examples follow the same pattern described in
[issue #7](https://github.com/Cryptographic-API-Services/cas-lib/issues/7): read a file
from disk, get its bytes, and perform the cryptographic operation on them.

To try any of these:

```bash
cargo new cas-demo
cd cas-demo
cargo add cas-lib
# paste an example into src/main.rs, then:
cargo run
```

> **Note on "Digital Signature" and "ecdsa".** These two items appeared on the
> original checklist in issue #7 but the standalone Digital Signature
> implementation was removed from the library (it did little beyond what the
> hashers already provide), and a dedicated ECDSA module was never shipped.
> Use [Ed25519 signatures](#signatures-ed25519) or
> [RSA sign/verify](#asymmetric-rsa) instead.

## Table of Contents

- [Password Hashers](#password-hashers)
- [Symmetric](#symmetric)
- [Hashers](#hashers)
- [Asymmetric (RSA)](#asymmetric-rsa)
- [Signatures (Ed25519)](#signatures-ed25519)
- [Key Exchange (X25519)](#key-exchange-x25519)
- [Message Authentication (HMAC)](#message-authentication-hmac)
- [Hybrid (HPKE)](#hybrid-hpke)
- [Sponges (ASCON-AEAD)](#sponges-ascon-aead)
- [Post-Quantum (ML-KEM, ML-DSA, SLH-DSA)](#post-quantum-ml-kem-ml-dsa-slh-dsa)
- [Error Handling](#error-handling)

## Password Hashers

`CASArgon`, `CASBCrypt`, and `CASScrypt` each expose `hash_password` (with a
random salt and sensible default parameters), a customized variant, and
`verify_password`. Hashes are returned as self-describing PHC / modular-crypt
strings that embed the salt and parameters, so store the string as-is and pass
it back to `verify_password` later. `verify_password` returns `Ok(false)` for a
wrong password and an `Err` only when the stored hash cannot be parsed.

### Argon2
```rust
use cas_lib::password_hashers::argon2::CASArgon;

fn main() {
    let password = "HashThisBadPassword".to_string();

    // Argon2id with the library defaults.
    let hash = CASArgon::hash_password(password.clone()).unwrap();
    println!("{}", hash);

    println!("correct: {}", CASArgon::verify_password(hash.clone(), password.clone()).unwrap()); // true
    println!("wrong:   {}", CASArgon::verify_password(hash, "nope".to_string()).unwrap()); // false

    // Custom parameters: memory cost in MiB, iterations, parallelism.
    let tuned_hash = CASArgon::hash_password_parameters(64, 3, 4, password.clone()).unwrap();
    println!("tuned verifies: {}", CASArgon::verify_password(tuned_hash, password).unwrap()); // true
}
```

#### Deriving an AES key from a password

`derive_aes_128_key` / `derive_aes_256_key` stretch a password into a 16- or
32-byte key with Argon2. A fresh random salt is used on every call and is not
returned, so the derived key cannot be re-derived later — keep the key itself
(for example, wrapped with [AES-KW](#aes-key-wrapping-aes-kw--aes-kwp)). Use
[PBKDF2](#pbkdf2) when you need to re-derive the same key from the password.

```rust
use cas_lib::password_hashers::argon2::CASArgon;
use cas_lib::symmetric::{aes::CASAES256, cas_symmetric_encryption::CASAES256Encryption};

fn main() {
    let key = CASArgon::derive_aes_256_key(b"correct horse battery staple".to_vec()).unwrap();
    assert_eq!(key.len(), 32);

    let nonce = <CASAES256 as CASAES256Encryption>::generate_nonce();
    let ciphertext =
        <CASAES256 as CASAES256Encryption>::encrypt_plaintext(key.clone(), nonce.clone(), b"hello".to_vec())
            .unwrap();
    let plaintext =
        <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(key, nonce, ciphertext).unwrap();
    assert_eq!(plaintext, b"hello");
}
```

### BCrypt
```rust
use cas_lib::password_hashers::bcrypt::CASBCrypt;

fn main() {
    let password = "HashThisBadPassword".to_string();

    // Default cost (12).
    let hash = CASBCrypt::hash_password(password.clone()).unwrap();
    println!("{}", hash);
    println!("verified: {}", CASBCrypt::verify_password(hash, password.clone()).unwrap()); // true

    // Custom cost (4-31); each +1 doubles the work.
    let hash = CASBCrypt::hash_password_customized(password.clone(), 10).unwrap();
    println!("verified: {}", CASBCrypt::verify_password(hash, password).unwrap()); // true
}
```

### SCrypt
```rust
use cas_lib::password_hashers::scrypt::CASScrypt;

fn main() {
    let password = "HashThisBadPassword".to_string();

    let hash = CASScrypt::hash_password(password.clone()).unwrap();
    println!("{}", hash);
    println!("verified: {}", CASScrypt::verify_password(hash, password.clone()).unwrap()); // true

    // Custom parameters: log2(N) = 15, r = 8, p = 1.
    let hash = CASScrypt::hash_password_customized(password.clone(), 15, 8, 1).unwrap();
    println!("verified: {}", CASScrypt::verify_password(hash, password).unwrap()); // true
}
```

### PBKDF2

The `pbkdf2` module exposes free functions that derive a 32-byte key with
PBKDF2-HMAC-SHA3-256. `derivation` generates a salt and returns it alongside
the key; store the salt and iteration count so `derivation_with_salt` can
re-derive the identical key later.

```rust
use cas_lib::password_hashers::pbkdf2::{derivation, derivation_with_salt};

fn main() {
    let password = b"HashThisBadPassword".to_vec();
    let iterations = 600_000;

    // First time: derive a key and get a fresh salt back.
    let result = derivation(password.clone(), iterations);
    println!("key length: {}", result.password.len()); // 32

    // Later: the same password + salt + iterations re-derives the same key.
    let rederived = derivation_with_salt(password, iterations, result.salt);
    assert_eq!(result.password, rederived);
}
```


## Symmetric

The symmetric module exposes AES-128-GCM, AES-256-GCM, AES-128/256-GCM-SIV,
ChaCha20-Poly1305, and AES key wrapping.
Nonces and keys are generated for you via `OsRng` — you never supply them
yourself. `encrypt_plaintext` returns the ciphertext with the authentication tag
appended; pass that same output back to `decrypt_ciphertext`. Each operation
returns a `Result`, so handle the error (here with `.unwrap()`).

### AES-256 GCM Mode
```rust
use std::{fs::File, io::Write, path::Path};

use cas_lib::symmetric::{aes::CASAES256, cas_symmetric_encryption::CASAES256Encryption};

fn main() {
    // Read the original file from disk.
    let path = Path::new("MikeMulchrone_Resume2024.docx");
    let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

    // Generate a fresh key and nonce, then encrypt and write the ciphertext to disk.
    let aes_nonce = <CASAES256 as CASAES256Encryption>::generate_nonce();
    let aes_key = <CASAES256 as CASAES256Encryption>::generate_key();
    let encrypted_bytes = <CASAES256 as CASAES256Encryption>::encrypt_plaintext(
        aes_key.clone(),
        aes_nonce.clone(),
        file_bytes.clone(),
    )
    .unwrap();
    let mut file = File::create("encrypted.docx").unwrap();
    file.write_all(&encrypted_bytes).unwrap();

    // Decrypt with the same key and nonce; the result matches the original file.
    let decrypted_bytes =
        <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(aes_key, aes_nonce, encrypted_bytes)
            .unwrap();
    let mut file = File::create("decrypted.docx").unwrap();
    file.write_all(&decrypted_bytes).unwrap();

    assert_eq!(file_bytes, decrypted_bytes);
}
```

### AES-128 GCM Mode
```rust
use std::{fs::File, io::Write, path::Path};

use cas_lib::symmetric::{aes::CASAES128, cas_symmetric_encryption::CASAES128Encryption};

fn main() {
    let path = Path::new("MikeMulchrone_Resume2024.docx");
    let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

    let aes_nonce = <CASAES128 as CASAES128Encryption>::generate_nonce();
    let aes_key = <CASAES128 as CASAES128Encryption>::generate_key();
    let encrypted_bytes = <CASAES128 as CASAES128Encryption>::encrypt_plaintext(
        aes_key.clone(),
        aes_nonce.clone(),
        file_bytes.clone(),
    )
    .unwrap();
    let mut file = File::create("encrypted.docx").unwrap();
    file.write_all(&encrypted_bytes).unwrap();

    let decrypted_bytes =
        <CASAES128 as CASAES128Encryption>::decrypt_ciphertext(aes_key, aes_nonce, encrypted_bytes)
            .unwrap();
    let mut file = File::create("decrypted.docx").unwrap();
    file.write_all(&decrypted_bytes).unwrap();

    assert_eq!(file_bytes, decrypted_bytes);
}
```

### AES GCM Mode with AAD

Both AES types also implement the `CASAES256AadEncryption` / `CASAES128AadEncryption`
traits, which take additional authenticated data (AAD). The AAD is not encrypted, but
it is bound to the authentication tag: decryption only succeeds when the same AAD is
supplied, so any tampering with it is detected.

```rust
use cas_lib::symmetric::{
    aes::CASAES256,
    cas_symmetric_encryption::{CASAES256AadEncryption, CASAES256Encryption},
};

fn main() {
    let plaintext: Vec<u8> = std::fs::read("MikeMulchrone_Resume2024.docx").unwrap();
    let aad = b"file-id:1234".to_vec();

    let aes_nonce = <CASAES256 as CASAES256Encryption>::generate_nonce();
    let aes_key = <CASAES256 as CASAES256Encryption>::generate_key();
    let encrypted_bytes = <CASAES256 as CASAES256AadEncryption>::encrypt_plaintext_with_aad(
        aes_key.clone(),
        aes_nonce.clone(),
        plaintext.clone(),
        aad.clone(),
    )
    .unwrap();

    // Decryption requires the same AAD; a different AAD returns an error.
    let decrypted_bytes = <CASAES256 as CASAES256AadEncryption>::decrypt_ciphertext_with_aad(
        aes_key,
        aes_nonce,
        encrypted_bytes,
        aad,
    )
    .unwrap();

    assert_eq!(plaintext, decrypted_bytes);
}
```

### ChaCha20-Poly1305
```rust
use std::{fs::File, io::Write, path::Path};

use cas_lib::symmetric::{
    cas_symmetric_encryption::Chacha20Poly1305Encryption, chacha20poly1305::CASChacha20Poly1305,
};

fn main() {
    let path = Path::new("MikeMulchrone_Resume2024.docx");
    let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

    let nonce = <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_nonce();
    let key = <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_key();
    let encrypted_bytes = <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::encrypt_plaintext(
        key.clone(),
        nonce.clone(),
        file_bytes.clone(),
    )
    .unwrap();
    let mut file = File::create("encrypted.docx").unwrap();
    file.write_all(&encrypted_bytes).unwrap();

    let decrypted_bytes =
        <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::decrypt_ciphertext(
            key,
            nonce,
            encrypted_bytes,
        )
        .unwrap();
    let mut file = File::create("decrypted.docx").unwrap();
    file.write_all(&decrypted_bytes).unwrap();

    assert_eq!(file_bytes, decrypted_bytes);
}
```

### AES Key Wrapping (AES-KW / AES-KWP)

The `CASAES256KeyWrap` / `CASAES128KeyWrap` traits implement AES Key Wrap
(RFC 3394 / NIST SP 800-38F KW) and AES Key Wrap with Padding (RFC 5649 / KWP).
They protect a data key under a key-encryption key (KEK), so the KEK can be
rotated by re-wrapping the data key instead of re-encrypting all the data.
`wrap_key` requires key data that is a multiple of 8 bytes and at least 16
bytes; `wrap_key_with_padding` accepts any length from 1 byte up.

```rust
use cas_lib::symmetric::{
    aes_kw::CASAES256KW, cas_symmetric_encryption::CASAES256KeyWrap,
};

fn main() {
    // The data key encrypts your data; the KEK only ever wraps the data key.
    let kek = <CASAES256KW as CASAES256KeyWrap>::generate_kek();
    let data_key = <CASAES256KW as CASAES256KeyWrap>::generate_kek();

    let wrapped =
        <CASAES256KW as CASAES256KeyWrap>::wrap_key(kek.clone(), data_key.clone()).unwrap();

    // Rotate the KEK: unwrap with the old KEK, re-wrap with a new one.
    // The data key never changes, so the data does not need re-encrypting.
    let new_kek = <CASAES256KW as CASAES256KeyWrap>::generate_kek();
    let recovered = <CASAES256KW as CASAES256KeyWrap>::unwrap_key(kek, wrapped).unwrap();
    let rewrapped =
        <CASAES256KW as CASAES256KeyWrap>::wrap_key(new_kek.clone(), recovered).unwrap();

    let unwrapped =
        <CASAES256KW as CASAES256KeyWrap>::unwrap_key(new_kek, rewrapped).unwrap();
    assert_eq!(unwrapped, data_key);
}
```

Use the padded variant (KWP) for key material whose length is not a multiple of
8 bytes, such as a 5-byte secret or a serialized private key. A value wrapped
with `wrap_key_with_padding` must be unwrapped with `unwrap_key_with_padding`.
`CASAES128KW` implements the same API with a 16-byte KEK.

```rust
use cas_lib::symmetric::{
    aes_kw::CASAES128KW, cas_symmetric_encryption::CASAES128KeyWrap,
};

fn main() {
    let kek = <CASAES128KW as CASAES128KeyWrap>::generate_kek();
    assert_eq!(kek.len(), 16);

    // 5 bytes: not a multiple of 8, so plain wrap_key would reject it.
    let secret = b"hello".to_vec();
    assert!(<CASAES128KW as CASAES128KeyWrap>::wrap_key(kek.clone(), secret.clone()).is_err());

    let wrapped =
        <CASAES128KW as CASAES128KeyWrap>::wrap_key_with_padding(kek.clone(), secret.clone())
            .unwrap();
    let unwrapped =
        <CASAES128KW as CASAES128KeyWrap>::unwrap_key_with_padding(kek, wrapped).unwrap();
    assert_eq!(unwrapped, secret);
}
```

### AES-GCM-SIV

`CASAES256SIV` / `CASAES128SIV` provide AES-GCM-SIV (RFC 8452), a
nonce-misuse-resistant AEAD. Accidentally reusing a nonce with GCM-SIV only
reveals whether two messages were identical, instead of breaking
confidentiality and authenticity as it does with plain GCM. Still generate a
fresh nonce for each message. The API mirrors the AES-GCM types.

```rust
use cas_lib::symmetric::{
    aes_gcm_siv::CASAES256SIV, cas_symmetric_encryption::CASAES256SIVEncryption,
};

fn main() {
    let file_bytes: Vec<u8> = std::fs::read("secret.docx").unwrap();

    let key = <CASAES256SIV as CASAES256SIVEncryption>::generate_key();
    let nonce = <CASAES256SIV as CASAES256SIVEncryption>::generate_nonce();

    let encrypted_bytes = <CASAES256SIV as CASAES256SIVEncryption>::encrypt_plaintext(
        key.clone(),
        nonce.clone(),
        file_bytes.clone(),
    )
    .unwrap();
    let decrypted_bytes =
        <CASAES256SIV as CASAES256SIVEncryption>::decrypt_ciphertext(key, nonce, encrypted_bytes)
            .unwrap();

    assert_eq!(file_bytes, decrypted_bytes);
}
```

### Importing and deriving AES keys

Every AES type also offers `key_from_vec`, which validates an existing key
(returning `CasError::InvalidKey` on the wrong length), and
`key_from_x25519_shared_secret`, which runs HKDF-SHA256 over an
[X25519](#key-exchange-x25519) shared secret to produce a key of the right size.
This is how two parties turn a key exchange into a shared encryption key.

```rust
use cas_lib::key_exchange::{cas_key_exchange::CASKeyExchange, x25519::X25519};
use cas_lib::symmetric::{aes::CASAES256, cas_symmetric_encryption::CASAES256Encryption};

fn main() {
    // Alice and Bob agree on a shared secret.
    let alice = X25519::generate_secret_and_public_key();
    let bob = X25519::generate_secret_and_public_key();
    let alice_shared = X25519::diffie_hellman(alice.secret_key, bob.public_key).unwrap();
    let bob_shared = X25519::diffie_hellman(bob.secret_key, alice.public_key).unwrap();

    // Each side derives the same AES-256 key from it.
    let alice_key =
        <CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(alice_shared).unwrap();
    let bob_key =
        <CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(bob_shared).unwrap();
    assert_eq!(alice_key, bob_key);

    // Alice encrypts, Bob decrypts. The nonce travels alongside the ciphertext.
    let nonce = <CASAES256 as CASAES256Encryption>::generate_nonce();
    let ciphertext = <CASAES256 as CASAES256Encryption>::encrypt_plaintext(
        alice_key,
        nonce.clone(),
        b"meet at noon".to_vec(),
    )
    .unwrap();
    let plaintext =
        <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(bob_key, nonce, ciphertext).unwrap();
    assert_eq!(plaintext, b"meet at noon");

    // key_from_vec validates key bytes you already have (e.g. loaded from storage).
    let stored_key = vec![7u8; 32];
    let key = <CASAES256 as CASAES256Encryption>::key_from_vec(stored_key).unwrap();
    assert_eq!(key.len(), 32);
    assert!(<CASAES256 as CASAES256Encryption>::key_from_vec(vec![0u8; 31]).is_err());
}
```


## Hashers

The hashers module provides SHA-2 / SHA-3 style digests (256- and 512-bit) via
the `CASHasher` trait. A digest is deterministic, so hashing the same file twice
produces equal output, while two different files produce different output. The
example below reads two files from disk and demonstrates both the `true`
(identical content) and `false` (different content) comparison cases described in
issue #7. `verify_256` / `verify_512` re-hash the data and compare it against a
previously produced digest.

```rust
use std::path::Path;

use cas_lib::hashers::{cas_hasher::CASHasher, sha::CASSHA};

fn main() {
    // Hash the first file.
    let path = Path::new("file_a.docx");
    let file_a: Vec<u8> = std::fs::read(path).unwrap();
    let hash_a = <CASSHA as CASHasher>::hash_256(file_a.clone());

    // Hashing the SAME file again yields the SAME digest -> true.
    let hash_a_again = <CASSHA as CASHasher>::hash_256(file_a.clone());
    println!("same file matches: {}", hash_a == hash_a_again); // true

    // Hashing a DIFFERENT file yields a DIFFERENT digest -> false.
    let path_b = Path::new("file_b.docx");
    let file_b: Vec<u8> = std::fs::read(path_b).unwrap();
    let hash_b = <CASSHA as CASHasher>::hash_256(file_b);
    println!("different file matches: {}", hash_a == hash_b); // false

    // verify_256 re-hashes the data and checks it against an existing digest.
    let verified = <CASSHA as CASHasher>::verify_256(hash_a, file_a);
    println!("verify_256: {}", verified); // true

    // 512-bit variants are also available:
    //   <CASSHA as CASHasher>::hash_512(data);
    //   <CASSHA as CASHasher>::verify_512(digest, data);
}
```

### SHA-2 (SHA-256 / SHA-512)

`CASSHA` above uses SHA-3. For SHA-2 (FIPS 180-4) use `CASSHA2`, which implements
the same `CASHasher` trait: `hash_256` / `verify_256` use SHA-256 (32-byte digest)
and `hash_512` / `verify_512` use SHA-512 (64-byte digest).

```rust
use cas_lib::hashers::{cas_hasher::CASHasher, sha2::CASSHA2};

fn main() {
    let data = b"abc".to_vec();

    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let digest = <CASSHA2 as CASHasher>::hash_256(data.clone());
    println!("sha-256 length: {}", digest.len()); // 32

    let verified = <CASSHA2 as CASHasher>::verify_256(digest, data.clone());
    println!("verify_256: {}", verified); // true

    let digest_512 = <CASSHA2 as CASHasher>::hash_512(data.clone());
    println!("sha-512 length: {}", digest_512.len()); // 64
    println!("verify_512: {}", <CASSHA2 as CASHasher>::verify_512(digest_512, data)); // true
}
```

### BLAKE2 (BLAKE2s-256 / BLAKE2b-512)

`CASBlake2` implements `CASHasher` too: `hash_256` / `verify_256` use
BLAKE2s-256 and `hash_512` / `verify_512` use BLAKE2b-512. BLAKE2 is a fast
alternative to SHA-2/SHA-3 for checksums and content addressing.

```rust
use cas_lib::hashers::{blake2::CASBlake2, cas_hasher::CASHasher};

fn main() {
    let file_bytes: Vec<u8> = std::fs::read("file_a.docx").unwrap();

    let digest = <CASBlake2 as CASHasher>::hash_256(file_bytes.clone());
    println!("blake2s-256 length: {}", digest.len()); // 32
    println!("verify_256: {}", <CASBlake2 as CASHasher>::verify_256(digest, file_bytes.clone())); // true

    let digest_512 = <CASBlake2 as CASHasher>::hash_512(file_bytes.clone());
    println!("blake2b-512 length: {}", digest_512.len()); // 64
    println!("verify_512: {}", <CASBlake2 as CASHasher>::verify_512(digest_512, file_bytes)); // true
}
```


## Asymmetric (RSA)

The asymmetric module wraps RSA. Keys are PEM-encoded strings. Key sizes below
2048 bits are rejected. RSA here is used for signing and verifying a document's
bytes; every operation returns a `Result`.

```rust
use cas_lib::asymmetric::{
    cas_rsa::CASRSA,
    types::{CASRSAEncryption, RSAKeyPairResult},
};

fn main() {
    // Generate a 2048-bit RSA key pair (PEM-encoded strings).
    let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(2048).unwrap();

    // Read the document to sign.
    let document: Vec<u8> = std::fs::read("contract.pdf").unwrap();

    // Sign with the private key.
    let signature = CASRSA::sign(key_pair.private_key, document.clone()).unwrap();

    // Verify with the public key -> true when the document is unmodified.
    let is_valid = CASRSA::verify(key_pair.public_key, document, signature).unwrap();
    println!("signature valid: {}", is_valid); // true
}
```


## Signatures (Ed25519)

The signatures module provides Ed25519. `get_ed25519_key_pair` returns a key
pair; signing produces a 64-byte signature plus the 32-byte verification
(public) key. You can verify either with the full key pair or with just the
public key — the latter is what a remote verifier would typically hold.

```rust
use cas_lib::signatures::ed25519::{
    ed25519_sign_with_key_pair, ed25519_verify_with_public_key, get_ed25519_key_pair,
};

fn main() {
    // Generate a key pair.
    let key_pair = get_ed25519_key_pair();

    // Read the message/document to sign from disk.
    let message: Vec<u8> = std::fs::read("message.txt").unwrap();

    // Sign with the key pair.
    let signature = ed25519_sign_with_key_pair(key_pair.key_pair, message.clone()).unwrap();

    // A verifier holding only the public key can confirm the signature -> true.
    let is_valid =
        ed25519_verify_with_public_key(signature.public_key, signature.signature, message).unwrap();
    println!("signature valid: {}", is_valid); // true
}
```

The signer can also verify with the key pair it holds, via
`ed25519_verify_with_key_pair`. Verification returns `Ok(false)` for a valid
signature over different bytes, and an `Err` only for malformed keys or
signatures.

```rust
use cas_lib::signatures::ed25519::{
    ed25519_sign_with_key_pair, ed25519_verify_with_key_pair, get_ed25519_key_pair,
};

fn main() {
    let key_pair = get_ed25519_key_pair();
    let message = b"pay bob 10".to_vec();

    let signature = ed25519_sign_with_key_pair(key_pair.key_pair.clone(), message.clone()).unwrap();

    let ok = ed25519_verify_with_key_pair(
        key_pair.key_pair.clone(),
        signature.signature.clone(),
        message,
    )
    .unwrap();
    println!("original message: {}", ok); // true

    let tampered =
        ed25519_verify_with_key_pair(key_pair.key_pair, signature.signature, b"pay bob 1000".to_vec())
            .unwrap();
    println!("tampered message: {}", tampered); // false
}
```


## Key Exchange (X25519)

The key_exchange module implements X25519 Diffie-Hellman. Each party generates a
secret/public key pair; combining your secret key with the other party's public
key yields a shared secret that is identical on both sides. That shared secret
can then be turned into a symmetric key (see
[`key_from_x25519_shared_secret`](#symmetric) on the AES types).

```rust
use cas_lib::key_exchange::{
    cas_key_exchange::CASKeyExchange,
    x25519::{X25519, X25519SecretPublicKeyResult},
};

fn main() {
    // Each party generates a secret + public key pair.
    let alice: X25519SecretPublicKeyResult = X25519::generate_secret_and_public_key();
    let bob: X25519SecretPublicKeyResult = X25519::generate_secret_and_public_key();

    // Each side combines their own secret with the other's public key.
    let alice_shared = X25519::diffie_hellman(alice.secret_key, bob.public_key).unwrap();
    let bob_shared = X25519::diffie_hellman(bob.secret_key, alice.public_key).unwrap();

    // Both sides derive the SAME shared secret -> true.
    println!("shared secrets match: {}", alice_shared == bob_shared); // true
}
```


## Message Authentication (HMAC)

The message module provides HMAC. `sign` produces a tag over a message using a
shared key; `verify` recomputes the tag and confirms it matches. A correct
key + message + signature triple verifies as `true`. `HMAC` uses SHA2-256
(32-byte tag) and `HMACSha512` uses SHA2-512 (64-byte tag); both implement
the same `CASHMAC` trait.

```rust
use cas_lib::message::{cas_hmac::CASHMAC, hmac::{HMAC, HMACSha512}};

fn main() {
    // Shared secret key and the message bytes (read a file here in practice).
    let key: Vec<u8> = vec![1, 2, 3, 4, 5];
    let message: Vec<u8> = std::fs::read("message.txt").unwrap();

    // Produce an authentication tag (HMAC-SHA256).
    let signature = HMAC::sign(key.clone(), message.clone()).unwrap();

    // Verify the tag with the same key and message -> true.
    let is_valid = HMAC::verify(key.clone(), message.clone(), signature).unwrap();
    println!("hmac-sha256 valid: {}", is_valid); // true

    // Same API with HMAC-SHA512.
    let signature = HMACSha512::sign(key.clone(), message.clone()).unwrap();
    let is_valid = HMACSha512::verify(key, message, signature).unwrap();
    println!("hmac-sha512 valid: {}", is_valid); // true
}
```


## Hybrid (HPKE)

The hybrid module implements HPKE (Hybrid Public Key Encryption). The recipient
generates a key pair and an `info` string. A sender encrypts to the recipient's
public key, producing an encapsulated key, the ciphertext, and an authentication
tag. The recipient decrypts using their private key plus those three values.

```rust
use std::path::Path;

use cas_lib::hybrid::{cas_hybrid::CASHybrid, hpke::CASHPKE};

fn main() {
    // Read the file to encrypt.
    let file_bytes: Vec<u8> = std::fs::read(Path::new("secret.docx")).unwrap();

    // Recipient generates a key pair and info string.
    let (private_key, public_key, info_str) = CASHPKE::generate_key_pair();

    // Sender encrypts to the recipient's public key.
    let (encapped_key, ciphertext, tag) =
        CASHPKE::encrypt(file_bytes.clone(), public_key, info_str.clone()).unwrap();

    // Recipient decrypts with their private key + the encapsulated key + tag.
    let decrypted_bytes =
        CASHPKE::decrypt(ciphertext, private_key, encapped_key, tag, info_str).unwrap();

    assert_eq!(file_bytes, decrypted_bytes);
    println!("hpke round-trip succeeded");
}
```

The `info` value binds the ciphertext to a context, and decryption fails if a
different one is supplied. `generate_key_pair` hands you a random one, but you
can create another with `CASHPKE::generate_info_str()` (a random 16-byte UUID) or
pass any application-specific bytes, as long as sender and recipient agree.

```rust
use cas_lib::hybrid::{cas_hybrid::CASHybrid, hpke::CASHPKE};

fn main() {
    let (private_key, public_key, _) = CASHPKE::generate_key_pair();
    let info = CASHPKE::generate_info_str();

    let (encapped_key, ciphertext, tag) =
        CASHPKE::encrypt(b"hello".to_vec(), public_key, info.clone()).unwrap();

    // A mismatched info string is rejected.
    let wrong_info = CASHPKE::generate_info_str();
    assert!(CASHPKE::decrypt(
        ciphertext.clone(),
        private_key.clone(),
        encapped_key.clone(),
        tag.clone(),
        wrong_info
    )
    .is_err());

    let plaintext = CASHPKE::decrypt(ciphertext, private_key, encapped_key, tag, info).unwrap();
    assert_eq!(plaintext, b"hello");
}
```


## Sponges (ASCON-AEAD)

The sponges module provides ASCON-AEAD, a lightweight authenticated cipher. As
with the symmetric module, the key and nonce are generated for you, and
`encrypt` / `decrypt` round-trip the file bytes.

```rust
use std::{fs::File, io::Write, path::Path};

use cas_lib::sponges::{ascon_aead::AsconAead, cas_ascon_aead::CASAsconAead};

fn main() {
    let path = Path::new("secret.docx");
    let file_bytes: Vec<u8> = std::fs::read(path).unwrap();

    let nonce = <AsconAead as CASAsconAead>::generate_nonce();
    let key = <AsconAead as CASAsconAead>::generate_key();

    let encrypted_bytes =
        <AsconAead as CASAsconAead>::encrypt(key.clone(), nonce.clone(), file_bytes.clone())
            .unwrap();
    let mut file = File::create("encrypted.docx").unwrap();
    file.write_all(&encrypted_bytes).unwrap();

    let decrypted_bytes =
        <AsconAead as CASAsconAead>::decrypt(key, nonce, encrypted_bytes).unwrap();
    let mut file = File::create("decrypted.docx").unwrap();
    file.write_all(&decrypted_bytes).unwrap();

    assert_eq!(file_bytes, decrypted_bytes);
}
```


## Compression (Zstandard)

The compression module wraps Zstandard. `compress` takes the data and a
compression level (0-22; higher means smaller but slower); `decompress` restores
the original bytes exactly.

```rust
use cas_lib::compression::zstd::{compress, decompress};

fn main() {
    // Read a file from disk.
    let original: Vec<u8> = std::fs::read("large_log.txt").unwrap();

    // Compress at level 9.
    let compressed: Vec<u8> = compress(original.clone(), 9).unwrap();
    println!(
        "compressed {} bytes down to {} bytes",
        original.len(),
        compressed.len()
    );

    // Decompress back to the original bytes.
    let decompressed: Vec<u8> = decompress(compressed).unwrap();
    assert_eq!(original, decompressed);
}
```


## Post-Quantum (ML-KEM, ML-DSA, SLH-DSA)

The `pqc` module exposes free functions (not trait methods) for NIST's
post-quantum standards. Keys, ciphertexts, and signatures are raw bytes.

### ML-KEM-1024 (FIPS 203)

ML-KEM is a key-encapsulation mechanism: the sender encapsulates to the
recipient's public key, producing a ciphertext and a 32-byte shared secret; the
recipient decapsulates the ciphertext to recover the same secret. Use the shared
secret as a symmetric key, for example with AES-256-GCM.

```rust
use cas_lib::pqc::ml_kem::{ml_kem_1024_decapsulate, ml_kem_1024_encapsulate, ml_kem_1024_generate};
use cas_lib::symmetric::{aes::CASAES256, cas_symmetric_encryption::CASAES256Encryption};

fn main() {
    // Recipient generates a key pair and publishes the public key.
    let recipient = ml_kem_1024_generate();

    // Sender encapsulates: the ciphertext goes to the recipient, the secret stays local.
    let encap = ml_kem_1024_encapsulate(recipient.public_key).unwrap();

    // Recipient recovers the same shared secret.
    let shared_secret = ml_kem_1024_decapsulate(recipient.secret_key, encap.ciphertext).unwrap();
    assert_eq!(shared_secret, encap.shared_secret);

    // The 32-byte secret works directly as an AES-256 key.
    let key = <CASAES256 as CASAES256Encryption>::key_from_vec(shared_secret).unwrap();
    let nonce = <CASAES256 as CASAES256Encryption>::generate_nonce();
    let file_bytes: Vec<u8> = std::fs::read("secret.docx").unwrap();
    let ciphertext =
        <CASAES256 as CASAES256Encryption>::encrypt_plaintext(key, nonce, file_bytes).unwrap();
    println!("encrypted {} bytes", ciphertext.len());
}
```

### ML-DSA-65 (FIPS 204)

ML-DSA is a lattice-based signature scheme with small signatures and fast
signing. The signing key is serialized as its 32-byte seed.

```rust
use cas_lib::pqc::ml_dsa::{generate_signing_and_verification_key, sign_message, verify_signature};

fn main() {
    let key_pair = generate_signing_and_verification_key();
    let document: Vec<u8> = std::fs::read("contract.pdf").unwrap();

    let signature = sign_message(document.clone(), key_pair.signing_key).unwrap();

    let is_valid =
        verify_signature(document, signature.clone(), key_pair.verification_key.clone()).unwrap();
    println!("signature valid: {}", is_valid); // true

    let tampered = verify_signature(b"other".to_vec(), signature, key_pair.verification_key).unwrap();
    println!("tampered valid: {}", tampered); // false
}
```

### SLH-DSA-SHAKE-128f (FIPS 205)

SLH-DSA is a stateless hash-based signature scheme. It relies only on the
security of the underlying hash function, which makes it a conservative choice,
at the cost of much larger signatures than ML-DSA. The API is the same shape as
ML-DSA.

```rust
use cas_lib::pqc::slh_dsa::{generate_signing_and_verification_key, sign_message, verify_signature};

fn main() {
    let key_pair = generate_signing_and_verification_key();
    let message: Vec<u8> = std::fs::read("message.txt").unwrap();

    let signature = sign_message(message.clone(), key_pair.signing_key).unwrap();
    println!("signature length: {}", signature.len());

    let is_valid = verify_signature(message, signature, key_pair.verification_key).unwrap();
    println!("signature valid: {}", is_valid); // true
}
```


## Error Handling

Every fallible operation returns `CasResult<T>` (an alias for
`Result<T, CasError>`) rather than panicking. The examples above call
`.unwrap()` for brevity; in real code, match on the error or propagate it with
`?`. `CasError` implements `std::error::Error` and `Display`, and
`error_code()` returns the stable numeric code that the FFI bindings expose.

```rust
use cas_lib::error::{CasError, CasResult};
use cas_lib::symmetric::{aes::CASAES256, cas_symmetric_encryption::CASAES256Encryption};

fn decrypt_file(key: Vec<u8>, nonce: Vec<u8>, path: &str) -> CasResult<Vec<u8>> {
    let ciphertext = std::fs::read(path).map_err(|_| CasError::InvalidInput)?;
    <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(key, nonce, ciphertext)
}

fn main() {
    let key = <CASAES256 as CASAES256Encryption>::generate_key();
    let nonce = <CASAES256 as CASAES256Encryption>::generate_nonce();
    let ciphertext =
        <CASAES256 as CASAES256Encryption>::encrypt_plaintext(key, nonce.clone(), b"hi".to_vec())
            .unwrap();
    std::fs::write("encrypted.bin", &ciphertext).unwrap();

    // Decrypting with the wrong key fails authentication instead of panicking.
    let wrong_key = <CASAES256 as CASAES256Encryption>::generate_key();
    match decrypt_file(wrong_key, nonce, "encrypted.bin") {
        Ok(_) => println!("unexpected success"),
        Err(CasError::DecryptionFailed) => println!("tag mismatch, as expected"),
        Err(e) => println!("other error {} (code {})", e, e.error_code()),
    }

    // Wrong-length inputs are rejected up front.
    let err = <CASAES256 as CASAES256Encryption>::encrypt_plaintext(vec![0; 5], vec![0; 12], vec![])
        .unwrap_err();
    assert_eq!(err, CasError::InvalidKey);
    println!("{} (code {})", err, err.error_code()); // invalid key: ... (code 1)
}
```
