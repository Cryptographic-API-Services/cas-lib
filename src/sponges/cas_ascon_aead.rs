pub trait CASAsconAead {
    fn generate_key() -> Vec<u8>;
    fn generate_key_threadpool() -> Vec<u8>;
    fn generate_nonce() -> Vec<u8>;
    fn generate_nonce_threadpool() -> Vec<u8>;
    fn encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8>;
    fn encrypt_threadpool(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8>;
    fn decrypt_threadpool(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8>;
}