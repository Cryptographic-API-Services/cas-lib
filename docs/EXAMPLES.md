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
- [Compression (Zstandard)](#compression-zstandard)

## Password Hashers
### Argon2
```rust
use cas_lib::password_hashers::{argon2::CASArgon, cas_password_hasher::CASPasswordHasher};

fn main() {
let password_to_hash = "HashThisBadPassword".to_string();
let hash = CASArgon::hash_password(password_to_hash);
println!("{}", hash)
}
```
### BCrypt
```rust
use cas_lib::password_hashers::{bcrypt::CASBCrypt, cas_password_hasher::CASPasswordHasher};

let password_to_hash = "HashThisBadPassword".to_string();
let hash = CASBCrypt::hash_password(password_to_hash);
println!("{}", hash);
```
### SCrypt
```rust
use cas_lib::password_hashers::{bcrypt::CASScrypt, cas_password_hasher::CASPasswordHasher};

let password_to_hash = "HashThisBadPassword".to_string();
let hash = CASScrypt::hash_password(password_to_hash);
println!("{}", hash);
```


## Symmetric

The symmetric module exposes AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
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
key + message + signature triple verifies as `true`.

```rust
use cas_lib::message::{cas_hmac::CASHMAC, hmac::HMAC};

fn main() {
    // Shared secret key and the message bytes (read a file here in practice).
    let key: Vec<u8> = vec![1, 2, 3, 4, 5];
    let message: Vec<u8> = std::fs::read("message.txt").unwrap();

    // Produce an authentication tag.
    let signature = HMAC::sign(key.clone(), message.clone()).unwrap();

    // Verify the tag with the same key and message -> true.
    let is_valid = HMAC::verify(key, message, signature).unwrap();
    println!("hmac valid: {}", is_valid); // true
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
