use std::{fs::{File}, io::Write, path::Path};

use cas_lib::symmetric::{aes::CASAES256, cas_symmetric_encryption::CASAES256Encryption};

#[cfg(test)]
mod tests {
    use cas_lib::symmetric::{aes::CASAES128, cas_symmetric_encryption::CASAES128Encryption};

    use super::*;
    #[test]
    fn test_aes_256() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let aes_nonce = <CASAES256 as CASAES256Encryption>::generate_nonce();
        let aes_key = <CASAES256 as CASAES256Encryption>::generate_key();
        let encrypted_bytes = <CASAES256 as CASAES256Encryption>::encrypt_plaintext(aes_key, aes_nonce, file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes);

        let decrypted_bytes = <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(aes_key, aes_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes);
        assert_eq!(file_bytes, decrypted_bytes);
    }

    #[test]
    fn test_aes_128() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let aes_nonce = <CASAES128 as CASAES128Encryption>::generate_nonce();
        let aes_key = <CASAES128 as CASAES128Encryption>::generate_key();
        let encrypted_bytes = <CASAES128 as CASAES128Encryption>::encrypt_plaintext(aes_key, aes_nonce, file_bytes.clone());
        let mut file =  File::create("encrypted.docx").unwrap();
        file.write_all(&encrypted_bytes);


        let decrypted_bytes = <CASAES128 as CASAES128Encryption>::decrypt_ciphertext(aes_key, aes_nonce, encrypted_bytes);
        let mut file =  File::create("decrypted.docx").unwrap();
        file.write_all(&decrypted_bytes);
        assert_eq!(file_bytes, decrypted_bytes);
    }
}