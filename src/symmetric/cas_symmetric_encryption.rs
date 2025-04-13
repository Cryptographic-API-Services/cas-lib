pub struct AesKeyFromX25519SharedSecret {
    pub aes_key: Vec<u8>,
    pub aes_nonce: Vec<u8>,
}

pub trait CASAES256Encryption {
    fn generate_key() -> [u8; 32];
    fn generate_key_threadpool() -> [u8; 32];
    fn encrypt_plaintext(aes_key: [u8; 32], nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8>;
    fn encrypt_plaintext_threadpool(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt_ciphertext(aes_key: [u8; 32], nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8>;
    fn decrypt_ciphertext_threadpool(aes_key: [u8; 32], nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8>;
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret;
    fn key_from_x25519_shared_secret_threadpool(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret;
    fn generate_nonce() -> Vec<u8>;
    fn generate_nonce_threadpool() -> Vec<u8>;
    fn key_from_vec(key_slice: Vec<u8>) -> Vec<u8>;
    fn key_from_vec_threadpool(key_slice: Vec<u8>) -> Vec<u8>;
}

pub trait CASAES128Encryption {
    fn generate_key() -> [u8; 16];
    fn generate_key_threadpool() -> [u8; 16];
    fn encrypt_plaintext(aes_key: [u8; 16], nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8>;
    fn encrypt_plaintext_threadpool(aes_key: [u8; 16], nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt_ciphertext(aes_key: [u8; 16], nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8>;
    fn decrypt_ciphertext_threadpool(aes_key: [u8; 16], nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8>;
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret;
    fn key_from_x25519_shared_secret_threadpool(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret;
    fn generate_nonce() -> Vec<u8>;
    fn generate_nonce_threadpool() -> Vec<u8>;
    fn key_from_vec(key_slice: Vec<u8>) -> Vec<u8>;
    fn key_from_vec_threadpool(key_slice: Vec<u8>) -> Vec<u8>;
}