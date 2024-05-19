use super::x25519::x25519SecretPublicKeyResult;

pub trait CASKeyExchange {
    fn generate_secret_and_public_key() -> x25519SecretPublicKeyResult;
    fn diffie_hellman(my_secret_key: Vec<u8>, users_public_key: Vec<u8>) -> Vec<u8>;
}
