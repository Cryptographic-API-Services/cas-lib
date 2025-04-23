# Examples 

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
### AES-256 GCM Mode
```rust
use std::{fs::{File}, io::Write, path::Path};

use cas_lib::symmetric::{aes::CASAES256, cas_symmetric_encryption::CASAESEncryption};

fn main() {
    let path = Path::new("MikeMulchrone_Resume2024.docx");
    let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
    let aes_nonce = <CASAES256 as CASAESEncryption>::generate_nonce();
    let aes_key = <CASAES256 as CASAESEncryption>::generate_key();
    let encrypted_bytes = <CASAES256 as CASAESEncryption>::encrypt_plaintext(aes_key.clone(), aes_nonce.clone(), file_bytes);
    let mut file =  File::create("encrypted.docx").unwrap();
    file.write_all(&decrypted_bytes).unwrap();

    let path = Path::new("encrypted.docx");
    let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
    let decrypted_bytes = <CASAES256 as CASAESEncryption>::decrypt_ciphertext(aes_key, aes_nonce, file_bytes);
    let mut file =  File::create("decrypted.docx").unwrap();
    file.write_all(&decrypted_bytes).unwrap();
}
```