#[cfg(test)]
mod message {
    use cas_lib::message::{cas_hmac::CASHMAC, hmac::HMAC};

    #[test]
    pub fn hmac_sign() {
        let key = vec![1, 2, 3, 4, 5];
        let message = vec![6, 7, 8, 9, 10];
        // Replace `ConcreteHmacType` with the actual struct that implements CASHMAC
        let signature = HMAC::sign(key.clone(), message.clone());
        assert!(!signature.is_empty());
    }

    #[test]
    pub fn hmac_verify() {
        let key = vec![1, 2, 3, 4, 5];
        let message = vec![6, 7, 8, 9, 10];
        let signature = HMAC::sign(key.clone(), message.clone());
        let is_valid = HMAC::verify(key, message, signature);
        assert!(is_valid);
    }
}