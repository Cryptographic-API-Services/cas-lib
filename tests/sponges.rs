mod common;

#[cfg(test)]
mod sponges {
    use std::{fs::File, io::Write, path::Path};
    use cas_lib::sponges::{ascon_aead::AsconAead, cas_ascon_aead::CASAsconAead};
    use crate::common::temp_output_path;
    
    #[test]
    fn test_ascon_128() {
        let path = Path::new("tests/test.docx");
        let file_bytes: Vec<u8> = std::fs::read(path).unwrap();
        let ascon_nonce = <AsconAead as CASAsconAead>::generate_nonce();
        let ascon_key = <AsconAead as CASAsconAead>::generate_key();
        let encrypted_bytes = <AsconAead as CASAsconAead>::encrypt(ascon_key.clone(), ascon_nonce.clone(), file_bytes.clone()).unwrap();
        let mut file =  File::create(temp_output_path("encrypted.docx")).unwrap();
        file.write_all(&encrypted_bytes).unwrap();

        let decrypted_bytes = <AsconAead as CASAsconAead>::decrypt(ascon_key, ascon_nonce, encrypted_bytes).unwrap();
        let mut file =  File::create(temp_output_path("decrypted.docx")).unwrap();
        file.write_all(&decrypted_bytes).unwrap();
        assert_eq!(file_bytes, decrypted_bytes);
    }
}