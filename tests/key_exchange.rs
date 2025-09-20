#[cfg(test)]
mod key_exchange {
    use cas_lib::key_exchange::{cas_key_exchange::CASKeyExchange, x25519::{X25519SecretPublicKeyResult, X25519}};

    #[test]
    pub fn x25519_diffie_hellman() {
        let alice: X25519SecretPublicKeyResult = X25519::generate_secret_and_public_key();
        let bob: X25519SecretPublicKeyResult = X25519::generate_secret_and_public_key();

        let alice_shared_secret = X25519::diffie_hellman(alice.secret_key.clone(), bob.public_key.clone());
        let bob_shared_secret = X25519::diffie_hellman(bob.secret_key.clone(), alice.public_key.clone());
        assert_eq!(alice_shared_secret, bob_shared_secret);
    }
}