#[cfg(test)]
mod asymmetric {
    use cas_lib::asymmetric::{cas_rsa::CASRSA, types::{CASRSAEncryption, RSAKeyPairResult}};

    #[test]
    pub fn generate_rsa_keys() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(2048).unwrap();
        assert!(!key_pair.private_key.is_empty());
        assert!(!key_pair.public_key.is_empty());
    }

    #[test]
    pub fn rejects_small_key_size() {
        let result = CASRSA::generate_rsa_keys(1024);
        assert!(result.is_err(), "RSA key sizes below 2048 bits should be rejected");
    }

    #[test]
    pub fn signature() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(3072).unwrap();
        let document = b"Hello, world!".to_vec();
        let signature = CASRSA::sign(key_pair.private_key, document.clone()).unwrap();
        assert!(document != signature, "Signature should not be the same as the document");
    }

    #[test]
    pub fn verification() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(4096).unwrap();
        let document = b"Hello, world!".to_vec();
        let signature = CASRSA::sign(key_pair.private_key.clone(), document.clone()).unwrap();
        let verification = CASRSA::verify(key_pair.public_key, document, signature).unwrap();
        assert!(verification, "Signature should be valid");
    }
}
