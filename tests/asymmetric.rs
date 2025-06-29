#[cfg(test)]
mod asymmetric {
    use cas_lib::asymmetric::{cas_rsa::CASRSA, types::{CASRSAEncryption, RSAKeyPairResult}};

    #[test]
    pub fn generate_rsa_keys() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(2048);
        assert!(!key_pair.private_key.is_empty());
        assert!(!key_pair.public_key.is_empty());
    }

    #[test]
    pub fn generate_rsa_keys_threadpool() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys_threadpool(4096);
        assert!(!key_pair.private_key.is_empty());
        assert!(!key_pair.public_key.is_empty());
    }

    #[test]
    pub fn signature() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(1024);
        let document = b"Hello, world!".to_vec();
        let signature = CASRSA::sign(key_pair.private_key, document.clone());
        assert!(document != signature, "Signature should not be the same as the document");
    }

    #[test]
    pub fn signature_threadpool() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(2048);
        let document = b"Hello, world!".to_vec();
        let signature = CASRSA::sign_threadpool(key_pair.private_key, document.clone());
        assert!(document != signature, "Signature should not be the same as the document");
    }

    #[test]
    pub fn verification() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(2048);
        let document = b"Hello, world!".to_vec();
        let signature = CASRSA::sign(key_pair.private_key.clone(), document.clone());
        let verification = CASRSA::verify(key_pair.public_key, document, signature);
        assert!(verification, "Signature should be valid");
    }

    #[test]
    pub fn verification_threadpool() {
        let key_pair: RSAKeyPairResult = CASRSA::generate_rsa_keys(4096);
        let document = b"Hello, world!".to_vec();
        let signature = CASRSA::sign_threadpool(key_pair.private_key.clone(), document.clone());
        let verification = CASRSA::verify(key_pair.public_key, document, signature);
        assert!(verification, "Signature should be valid");
    }
}