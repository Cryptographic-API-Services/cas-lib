pub trait CASHybrid {
    fn generate_key_pair() -> (Vec<u8>, Vec<u8>, Vec<u8>);
    fn generate_info_str() -> Vec<u8>;
    fn encrypt(plaintext: Vec<u8>, public_key: Vec<u8>, info_str: Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>);
    fn decrypt(ciphertext: Vec<u8>, private_key: Vec<u8>, encapped_key: Vec<u8>, tag: Vec<u8>, info_str: Vec<u8>) -> Vec<u8>;
}