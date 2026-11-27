#[cfg(test)]
mod key_exchange {
    use cas_lib::error::{CasError, CasResult};
    use cas_lib::key_exchange::{cas_key_exchange::CASKeyExchange, x25519::{X25519SecretPublicKeyResult, X25519}};
    use cas_lib::symmetric::aes::{CASAES128, CASAES256};
    use cas_lib::symmetric::aes_gcm_siv::{CASAES128SIV, CASAES256SIV};
    use cas_lib::symmetric::cas_symmetric_encryption::{
        CASAES128Encryption, CASAES128SIVEncryption, CASAES256Encryption, CASAES256SIVEncryption,
    };
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use hkdf::Hkdf;
    use sha2::Sha256;

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input must have an even length");
        hex.as_bytes()
            .chunks(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
            .collect()
    }

    /// libsodium's X25519 low-order blocklist (`has_small_order` in
    /// `crypto_scalarmult/curve25519/ref10/x25519_ref10.c`), as little-endian
    /// u-coordinates: 0, 1, the two points of order 8, and p - 1, p, p + 1.
    const LOW_ORDER_POINTS: [&str; 7] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    /// Every blocklist point, plus the same point with bit 255 set: RFC 7748
    /// masks that bit, so it must not be a way around the check.
    fn low_order_points() -> Vec<[u8; 32]> {
        LOW_ORDER_POINTS
            .iter()
            .flat_map(|hex| {
                let point: [u8; 32] = decode_hex(hex).try_into().unwrap();
                let mut high_bit = point;
                high_bit[31] |= 0x80;
                [point, high_bit]
            })
            .collect()
    }

    type Derive = fn(Vec<u8>, Vec<u8>, Vec<u8>) -> CasResult<Vec<u8>>;

    /// The four X25519-to-AES helpers: name, function, key length, and the HKDF
    /// `info` label each one must use.
    fn helpers() -> [(&'static str, Derive, usize, &'static [u8]); 4] {
        [
            (
                "AES-256-GCM",
                <CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret,
                32,
                b"cas-lib/v1/x25519-hkdf-sha256/aes-256-gcm",
            ),
            (
                "AES-128-GCM",
                <CASAES128 as CASAES128Encryption>::key_from_x25519_shared_secret,
                16,
                b"cas-lib/v1/x25519-hkdf-sha256/aes-128-gcm",
            ),
            (
                "AES-256-GCM-SIV",
                <CASAES256SIV as CASAES256SIVEncryption>::key_from_x25519_shared_secret,
                32,
                b"cas-lib/v1/x25519-hkdf-sha256/aes-256-gcm-siv",
            ),
            (
                "AES-128-GCM-SIV",
                <CASAES128SIV as CASAES128SIVEncryption>::key_from_x25519_shared_secret,
                16,
                b"cas-lib/v1/x25519-hkdf-sha256/aes-128-gcm-siv",
            ),
        ]
    }

    /// Two key pairs and the shared secret each side computes.
    struct Exchange {
        alice: X25519SecretPublicKeyResult,
        bob: X25519SecretPublicKeyResult,
        alice_shared: Vec<u8>,
        bob_shared: Vec<u8>,
    }

    fn exchange() -> Exchange {
        let alice = X25519::generate_secret_and_public_key();
        let bob = X25519::generate_secret_and_public_key();
        let alice_shared = X25519::diffie_hellman(alice.secret_key.clone(), bob.public_key.clone()).unwrap();
        let bob_shared = X25519::diffie_hellman(bob.secret_key.clone(), alice.public_key.clone()).unwrap();
        Exchange { alice, bob, alice_shared, bob_shared }
    }

    #[test]
    pub fn x25519_diffie_hellman() {
        let ex = exchange();
        assert_eq!(ex.alice_shared, ex.bob_shared);
    }

    #[test]
    fn diffie_hellman_rejects_low_order_public_keys() {
        for point in low_order_points() {
            for _ in 0..4 {
                let me = X25519::generate_secret_and_public_key();

                // Independently confirm the point really forces the all-zero secret.
                let scalar: [u8; 32] = me.secret_key.clone().try_into().unwrap();
                assert_eq!(
                    MontgomeryPoint(point).mul_clamped(scalar).to_bytes(),
                    [0u8; 32],
                    "{} is not a low-order point",
                    hex(&point),
                );

                assert_eq!(
                    X25519::diffie_hellman(me.secret_key, point.to_vec()),
                    Err(CasError::InvalidKey),
                    "low-order public key {} was accepted",
                    hex(&point),
                );
            }
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn helpers_agree_whatever_the_public_key_order() {
        let ex = exchange();
        for (name, derive, len, _) in helpers() {
            let alice_key = derive(ex.alice_shared.clone(), ex.alice.public_key.clone(), ex.bob.public_key.clone()).unwrap();
            let bob_key = derive(ex.bob_shared.clone(), ex.bob.public_key.clone(), ex.alice.public_key.clone()).unwrap();
            let alice_swapped = derive(ex.alice_shared.clone(), ex.bob.public_key.clone(), ex.alice.public_key.clone()).unwrap();
            assert_eq!(alice_key.len(), len, "{name}");
            assert_eq!(alice_key, bob_key, "{name}: peers derived different keys");
            assert_eq!(alice_key, alice_swapped, "{name}: key depends on public key order");
        }
    }

    /// Pins the derivation: HKDF-SHA256, no salt, IKM = shared secret,
    /// `info = label || 0x00 || min(pk_a, pk_b) || max(pk_a, pk_b)`.
    #[test]
    fn helpers_match_the_documented_hkdf_construction() {
        let ex = exchange();
        let (low, high) = if ex.alice.public_key <= ex.bob.public_key {
            (&ex.alice.public_key, &ex.bob.public_key)
        } else {
            (&ex.bob.public_key, &ex.alice.public_key)
        };
        for (name, derive, len, label) in helpers() {
            let mut info = label.to_vec();
            info.push(0);
            info.extend_from_slice(low);
            info.extend_from_slice(high);
            let mut expected = vec![0u8; len];
            Hkdf::<Sha256>::new(None, &ex.alice_shared).expand(&info, &mut expected).unwrap();

            let key = derive(ex.alice_shared.clone(), ex.alice.public_key.clone(), ex.bob.public_key.clone()).unwrap();
            assert_eq!(key, expected, "{name}");
        }
    }

    #[test]
    fn helpers_derive_unrelated_keys_per_cipher() {
        let ex = exchange();
        let keys: Vec<(&str, Vec<u8>)> = helpers()
            .into_iter()
            .map(|(name, derive, _, _)| {
                (name, derive(ex.alice_shared.clone(), ex.alice.public_key.clone(), ex.bob.public_key.clone()).unwrap())
            })
            .collect();
        let key = |name: &str| &keys.iter().find(|(n, _)| *n == name).unwrap().1;

        // HKDF-Expand output with the same `info` is a prefix of a longer one; distinct
        // labels must break that.
        assert_ne!(&key("AES-256-GCM")[..16], key("AES-128-GCM").as_slice());
        assert_ne!(&key("AES-256-GCM-SIV")[..16], key("AES-128-GCM-SIV").as_slice());
        // Same key size, different cipher.
        assert_ne!(key("AES-256-GCM"), key("AES-256-GCM-SIV"));
        assert_ne!(key("AES-128-GCM"), key("AES-128-GCM-SIV"));
        // And no 16-byte key is the prefix of any 32-byte key.
        for (_, long) in keys.iter().filter(|(_, k)| k.len() == 32) {
            for (_, short) in keys.iter().filter(|(_, k)| k.len() == 16) {
                assert_ne!(&long[..16], short.as_slice());
            }
        }
    }

    #[test]
    fn helpers_bind_both_public_keys() {
        let ex = exchange();
        let mallory = X25519::generate_secret_and_public_key();
        for (name, derive, _, _) in helpers() {
            let key = derive(ex.alice_shared.clone(), ex.alice.public_key.clone(), ex.bob.public_key.clone()).unwrap();
            let other_a = derive(ex.alice_shared.clone(), mallory.public_key.clone(), ex.bob.public_key.clone()).unwrap();
            let other_b = derive(ex.alice_shared.clone(), ex.alice.public_key.clone(), mallory.public_key.clone()).unwrap();
            assert_ne!(key, other_a, "{name}: first public key not bound");
            assert_ne!(key, other_b, "{name}: second public key not bound");
            assert_ne!(other_a, other_b, "{name}");

            // A single flipped bit in either key is enough.
            for which in 0..2 {
                let mut pk_a = ex.alice.public_key.clone();
                let mut pk_b = ex.bob.public_key.clone();
                if which == 0 { pk_a[0] ^= 1 } else { pk_b[31] ^= 0x40 }
                let flipped = derive(ex.alice_shared.clone(), pk_a, pk_b).unwrap();
                assert_ne!(key, flipped, "{name}: bit flip in public key {which} not bound");
            }
        }
    }

    #[test]
    fn helpers_reject_bad_lengths_and_the_zero_secret() {
        let ex = exchange();
        let ss = ex.alice_shared.clone();
        let pk_a = ex.alice.public_key.clone();
        let pk_b = ex.bob.public_key.clone();
        for (name, derive, _, _) in helpers() {
            for bad in [Vec::new(), vec![1u8; 31], vec![1u8; 33], vec![1u8; 64]] {
                assert_eq!(derive(bad.clone(), pk_a.clone(), pk_b.clone()), Err(CasError::InvalidKey), "{name}: secret len {}", bad.len());
                assert_eq!(derive(ss.clone(), bad.clone(), pk_b.clone()), Err(CasError::InvalidKey), "{name}: pk_a len {}", bad.len());
                assert_eq!(derive(ss.clone(), pk_a.clone(), bad.clone()), Err(CasError::InvalidKey), "{name}: pk_b len {}", bad.len());
            }
            assert_eq!(derive(vec![0u8; 32], pk_a.clone(), pk_b.clone()), Err(CasError::InvalidKey), "{name}: all-zero secret");
            // A secret that is zero except for one byte is fine.
            let mut almost_zero = vec![0u8; 32];
            almost_zero[31] = 1;
            assert!(derive(almost_zero, pk_a.clone(), pk_b.clone()).is_ok(), "{name}");
        }
    }
}
