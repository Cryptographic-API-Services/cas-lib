pub struct Aes256KeyFromX25519SharedSecret {
    pub aes_key: [u8; 32],
    pub aes_nonce: [u8; 12],
}

pub struct Aes128KeyFromX25519SharedSecret {
    pub aes_key: [u8; 16],
    pub aes_nonce: [u8; 12],
}

pub trait CASAES256Encryption {
    fn generate_key() -> [u8; 32];
    fn generate_key_threadpool() -> [u8; 32];
    fn encrypt_plaintext(aes_key: [u8; 32], nonce: [u8; 12], plaintext: Vec<u8>) -> Vec<u8>;
    fn encrypt_plaintext_threadpool(aes_key: [u8; 32], nonce: [u8; 12], plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt_ciphertext(aes_key: [u8; 32], nonce: [u8; 12], ciphertext: Vec<u8>) -> Vec<u8>;
    fn decrypt_ciphertext_threadpool(aes_key: [u8; 32], nonce: [u8; 12], ciphertext: Vec<u8>) -> Vec<u8>;
    fn key_from_x25519_shared_secret(shared_secret: [u8; 32]) -> Aes256KeyFromX25519SharedSecret;
    fn key_from_x25519_shared_secret_threadpool(shared_secret: [u8; 32]) -> Aes256KeyFromX25519SharedSecret;
    fn generate_nonce() -> [u8; 12];
    fn generate_nonce_threadpool() -> [u8; 12];
}

pub trait CASAES128Encryption {
    fn generate_key() -> [u8; 16];
    fn generate_key_threadpool() -> [u8; 16];
    fn encrypt_plaintext(aes_key: [u8; 16], nonce: [u8; 12], plaintext: Vec<u8>) -> Vec<u8>;
    fn encrypt_plaintext_threadpool(aes_key: [u8; 16], nonce: [u8; 12], plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt_ciphertext(aes_key: [u8; 16], nonce: [u8; 12], ciphertext: Vec<u8>) -> Vec<u8>;
    fn decrypt_ciphertext_threadpool(aes_key: [u8; 16], nonce: [u8; 12], ciphertext: Vec<u8>) -> Vec<u8>;
    fn key_from_x25519_shared_secret(shared_secret: [u8; 32]) -> Aes128KeyFromX25519SharedSecret;
    fn key_from_x25519_shared_secret_threadpool(shared_secret: [u8; 32]) -> Aes128KeyFromX25519SharedSecret;
    fn generate_nonce() -> [u8; 12];
    fn generate_nonce_threadpool() -> [u8; 12];
}