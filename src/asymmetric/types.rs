pub struct RSAKeyPairResult {
    pub private_key: String,
    pub public_key: String,
}

pub trait CASRSAEncryption {
    fn generate_rsa_keys(key_size: usize) -> RSAKeyPairResult;
    fn sign(private_key: String, hash: Vec<u8>) -> Vec<u8>;
    fn verify(public_key: String, hash: Vec<u8>, signed_text: Vec<u8>) -> bool;
}