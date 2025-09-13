#[cfg(test)]
mod ed25519 {
    use cas_lib::signatures::ed25519::{ed25519_sign_with_key_pair, ed25519_verify_with_key_pair, ed25519_verify_with_public_key, get_ed25519_key_pair};

    #[test]
    pub fn get_key_pair_test() {
        let key_pair = get_ed25519_key_pair();
        assert!(key_pair != [0; 32], "Array is all zeros");
    }

    #[test]
    pub fn sign_with_key_pair() {
        let key_pair = get_ed25519_key_pair();
        let message_to_sign = b"Hello World Message To Sign".to_vec();
        let signature = ed25519_sign_with_key_pair(key_pair, message_to_sign);
        assert!(signature.signature != [0; 64], "Array is all zeros");
        assert!(signature.public_key != [0; 32], "Array is all zeros");
    }

    #[test]
    pub fn verify_with_public_key_() {
        let key_pair = get_ed25519_key_pair();
        let message_to_sign = b"Hello World Message To Sign".to_vec();
        let signature = ed25519_sign_with_key_pair(key_pair, message_to_sign.clone());
        let verification = ed25519_verify_with_public_key(signature.public_key, signature.signature, message_to_sign);
        assert_eq!(verification, true);
    }

    #[test]
    pub fn verify_with_key_pair() {
        let key_pair = get_ed25519_key_pair();
        let message_to_sign = b"Hello World Message To Sign".to_vec();
        let signature = ed25519_sign_with_key_pair(key_pair.clone(), message_to_sign.clone());
        let verification = ed25519_verify_with_key_pair(key_pair, signature.signature, message_to_sign);
        assert_eq!(verification, true);
    }
}
