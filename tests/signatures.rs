#[cfg(test)]
mod signatures {
    use cas_lib::signatures::ed25519::{ed25519_sign_with_key_pair, ed25519_verify_with_key_pair, ed25519_verify_with_public_key, get_ed25519_key_pair};

    #[test]
    pub fn get_key_pair_test() {
        let key_pair = get_ed25519_key_pair();
        assert!(key_pair.key_pair != [0; 32], "Array is all zeros");
        assert!(key_pair.public_key != [0; 32], "Array is all zeros");
    }

    #[test]
    pub fn sign_with_key_pair() {
        let key_pair = get_ed25519_key_pair();
        let message_to_sign = b"Hello World Message To Sign".to_vec();
        let signature = ed25519_sign_with_key_pair(key_pair.key_pair, message_to_sign).unwrap();
        assert!(signature.signature != [0; 64], "Array is all zeros");
        assert!(signature.public_key != [0; 32], "Array is all zeros");
    }

    #[test]
    pub fn verify_with_public_key_() {
        let key_pair = get_ed25519_key_pair();
        let message_to_sign = b"Hello World Message To Sign".to_vec();
        let signature = ed25519_sign_with_key_pair(key_pair.key_pair, message_to_sign.clone()).unwrap();
        let verification = ed25519_verify_with_public_key(signature.public_key, signature.signature, message_to_sign).unwrap();
        assert_eq!(verification, true);
    }

    #[test]
    pub fn verify_with_key_pair() {
        let key_pair = get_ed25519_key_pair();
        let message_to_sign = b"Hello World Message To Sign".to_vec();
        let signature = ed25519_sign_with_key_pair(key_pair.key_pair.clone(), message_to_sign.clone()).unwrap();
        let verification = ed25519_verify_with_key_pair(key_pair.key_pair, signature.signature, message_to_sign).unwrap();
        assert_eq!(verification, true);
    }

    /// Builds a signature whose R is the identity point (a small-order point)
    /// for a key pair whose secret scalar is known. It satisfies the
    /// cofactorless equation [S]B = R + [k]A, so permissive verification
    /// accepts it, while `verify_strict` rejects it because R has small order.
    fn small_order_r_signature(key_pair: &[u8], message: &[u8]) -> Vec<u8> {
        use curve25519_dalek::scalar::Scalar;
        use sha2::{Digest, Sha512};

        let seed: [u8; 32] = key_pair.try_into().unwrap();
        let expanded = Sha512::digest(seed);
        let mut a_bytes = [0u8; 32];
        a_bytes.copy_from_slice(&expanded[..32]);
        a_bytes[0] &= 248;
        a_bytes[31] &= 127;
        a_bytes[31] |= 64;
        let a = Scalar::from_bytes_mod_order(a_bytes);

        let public_key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let mut r = [0u8; 32];
        r[0] = 1; // canonical encoding of the identity point

        let mut h = Sha512::new();
        h.update(r);
        h.update(public_key);
        h.update(message);
        let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        let s = k * a;

        let mut signature = r.to_vec();
        signature.extend_from_slice(s.as_bytes());
        signature
    }

    fn verify_both(key_pair: &[u8], public_key: &[u8], signature: &[u8], message: &[u8]) -> (bool, bool) {
        let with_key_pair =
            ed25519_verify_with_key_pair(key_pair.to_vec(), signature.to_vec(), message.to_vec()).unwrap();
        let with_public_key =
            ed25519_verify_with_public_key(public_key.to_vec(), signature.to_vec(), message.to_vec()).unwrap();
        (with_key_pair, with_public_key)
    }

    #[test]
    pub fn key_pair_and_public_key_verification_agree() {
        let key_pair = get_ed25519_key_pair();
        let message = b"Hello World Message To Sign".to_vec();
        let signed = ed25519_sign_with_key_pair(key_pair.key_pair.clone(), message.clone()).unwrap();

        // Valid signature: both accept.
        assert_eq!(verify_both(&key_pair.key_pair, &signed.public_key, &signed.signature, &message), (true, true));

        // Tampered signature (S flipped): both reject.
        let mut tampered = signed.signature.clone();
        tampered[40] ^= 0x01;
        assert_eq!(verify_both(&key_pair.key_pair, &signed.public_key, &tampered, &message), (false, false));

        // Tampered message: both reject.
        let mut other_message = message.clone();
        other_message[0] ^= 0x01;
        assert_eq!(verify_both(&key_pair.key_pair, &signed.public_key, &signed.signature, &other_message), (false, false));

        // Small-order R: permissive verification accepts it, strict rejects it.
        let small_order = small_order_r_signature(&key_pair.key_pair, &message);
        let sig = ed25519_dalek::Signature::from_slice(&small_order).unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&signed.public_key.clone().try_into().unwrap()).unwrap();
        assert!(
            ed25519_dalek::Verifier::verify(&verifying_key, &message, &sig).is_ok(),
            "test vector should pass permissive verification"
        );
        assert!(verifying_key.verify_strict(&message, &sig).is_err());
        assert_eq!(verify_both(&key_pair.key_pair, &signed.public_key, &small_order, &message), (false, false));

        // Non-canonical encoding of the identity R (y = p + 1): both reject.
        let mut non_canonical = small_order.clone();
        non_canonical[..32].copy_from_slice(&{
            let mut r = [0xffu8; 32];
            r[0] = 0xee;
            r[31] = 0x7f;
            r
        });
        assert_eq!(verify_both(&key_pair.key_pair, &signed.public_key, &non_canonical, &message), (false, false));
    }
}
