pub trait CASAsconAead {
    fn generate_key() -> [u8; 16];
    fn generate_key_threadpool() -> [u8; 16];
    fn generate_nonce() -> [u8; 16];
    fn generate_nonce_threadpool() -> [u8; 16];
    fn encrypt(key: [u8; 16], nonce: [u8; 16], plaintext: Vec<u8>) -> Vec<u8>;
    fn encrypt_threadpool(key: [u8; 16], nonce: [u8; 16], plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt(key: [u8; 16], nonce: [u8; 16], ciphertext: Vec<u8>) -> Vec<u8>;
    fn decrypt_threadpool(key: [u8; 16], nonce: [u8; 16], ciphertext: Vec<u8>) -> Vec<u8>;
}