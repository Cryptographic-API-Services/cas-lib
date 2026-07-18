use cas_lib::symmetric::{
    aes_kw::{CASAES128KW, CASAES256KW},
    cas_symmetric_encryption::{CASAES128KeyWrap, CASAES256KeyWrap},
};

#[cfg(test)]
mod aes_kw {
    use cas_lib::error::CasError;
    use serde_json::Value;

    use super::*;

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input must have an even length");

        hex.as_bytes()
            .chunks(2)
            .map(|chunk| {
                let byte = std::str::from_utf8(chunk).unwrap();
                u8::from_str_radix(byte, 16).unwrap()
            })
            .collect()
    }

    fn hex_field(obj: &Value, key: &str) -> Vec<u8> {
        let value = obj[key].as_str().unwrap_or_else(|| panic!("missing field {key}"));
        decode_hex(value)
    }

    fn load(path: &str) -> Value {
        let contents = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("could not read {path}: {err}"));
        serde_json::from_str(&contents).unwrap_or_else(|err| panic!("invalid JSON in {path}: {err}"))
    }

    /// Known-answer test vectors from RFC 3394 section 4. Only the 128-bit and
    /// 256-bit KEK examples are used (sections 4.2, 4.4 and 4.5 use a 192-bit
    /// KEK, which the library does not expose).
    struct KwKatCase {
        kek: &'static str,
        key_data: &'static str,
        wrapped: &'static str,
    }

    // RFC 3394 section 4.1 — wrap 128 bits of key data with a 128-bit KEK
    const RFC3394_AES128_KAT: &[KwKatCase] = &[KwKatCase {
        kek: "000102030405060708090A0B0C0D0E0F",
        key_data: "00112233445566778899AABBCCDDEEFF",
        wrapped: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
    }];

    // RFC 3394 sections 4.3 and 4.6 — wrap 128 / 256 bits of key data with a 256-bit KEK
    const RFC3394_AES256_KAT: &[KwKatCase] = &[
        KwKatCase {
            kek: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            key_data: "00112233445566778899AABBCCDDEEFF",
            wrapped: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
        },
        KwKatCase {
            kek: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            key_data: "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            wrapped: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        },
    ];

    #[test]
    fn aes_128_kw_rfc_3394_known_answer_vectors() {
        for case in RFC3394_AES128_KAT {
            let kek = decode_hex(case.kek);
            let key_data = decode_hex(case.key_data);
            let expected = decode_hex(case.wrapped);

            let wrapped =
                <CASAES128KW as CASAES128KeyWrap>::wrap_key(kek.clone(), key_data.clone()).unwrap();
            assert_eq!(wrapped, expected);

            let unwrapped =
                <CASAES128KW as CASAES128KeyWrap>::unwrap_key(kek, wrapped).unwrap();
            assert_eq!(unwrapped, key_data);
        }
    }

    #[test]
    fn aes_256_kw_rfc_3394_known_answer_vectors() {
        for case in RFC3394_AES256_KAT {
            let kek = decode_hex(case.kek);
            let key_data = decode_hex(case.key_data);
            let expected = decode_hex(case.wrapped);

            let wrapped =
                <CASAES256KW as CASAES256KeyWrap>::wrap_key(kek.clone(), key_data.clone()).unwrap();
            assert_eq!(wrapped, expected);

            let unwrapped =
                <CASAES256KW as CASAES256KeyWrap>::unwrap_key(kek, wrapped).unwrap();
            assert_eq!(unwrapped, key_data);
        }
    }

    /// Runs every 128-bit and 256-bit KEK case from a Wycheproof key-wrap vector
    /// file (192-bit KEK groups are skipped — the library does not expose them).
    ///
    /// - `valid` cases must wrap to exactly the expected ciphertext and unwrap
    ///   back to the original key data.
    /// - `invalid` cases must fail to unwrap.
    /// - `acceptable` cases (only present in the unpadded KW file, for 64-bit
    ///   key data) may be rejected: NIST SP 800-38F requires at least two
    ///   semiblocks, which this library enforces, so they must not unwrap to
    ///   the wrong key data.
    ///
    /// The RFC 5649 (AES-KWP) worked examples both use a 192-bit KEK, so padded
    /// mode is covered exclusively by these NIST-derived vectors.
    fn run_wycheproof_file(
        path: &str,
        wrap: &dyn Fn(usize, Vec<u8>, Vec<u8>) -> Result<Vec<u8>, CasError>,
        unwrap: &dyn Fn(usize, Vec<u8>, Vec<u8>) -> Result<Vec<u8>, CasError>,
    ) {
        let file = load(path);
        let mut cases_run = 0;

        for group in file["testGroups"].as_array().expect("testGroups array") {
            let key_size = group["keySize"].as_u64().expect("keySize") as usize;
            if key_size != 128 && key_size != 256 {
                continue;
            }

            for test in group["tests"].as_array().expect("tests array") {
                let tc_id = test["tcId"].as_u64().expect("tcId");
                let key = hex_field(test, "key");
                let msg = hex_field(test, "msg");
                let ct = hex_field(test, "ct");
                let result = test["result"].as_str().expect("result");
                cases_run += 1;

                match result {
                    "valid" => {
                        let wrapped = wrap(key_size, key.clone(), msg.clone())
                            .unwrap_or_else(|err| panic!("tcId {tc_id}: wrap failed: {err}"));
                        assert_eq!(wrapped, ct, "tcId {tc_id}: wrapped output mismatch");

                        let unwrapped = unwrap(key_size, key, ct)
                            .unwrap_or_else(|err| panic!("tcId {tc_id}: unwrap failed: {err}"));
                        assert_eq!(unwrapped, msg, "tcId {tc_id}: unwrapped output mismatch");
                    }
                    "invalid" => {
                        assert!(
                            unwrap(key_size, key, ct).is_err(),
                            "tcId {tc_id}: unwrap of invalid ciphertext succeeded"
                        );
                    }
                    "acceptable" => {
                        if let Ok(unwrapped) = unwrap(key_size, key, ct) {
                            assert_eq!(unwrapped, msg, "tcId {tc_id}: unwrapped output mismatch");
                        }
                    }
                    other => panic!("tcId {tc_id}: unknown result type {other}"),
                }
            }
        }

        assert!(cases_run > 0, "no test cases were executed from {path}");
    }

    fn kw_wrap(key_size: usize, kek: Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, CasError> {
        match key_size {
            128 => <CASAES128KW as CASAES128KeyWrap>::wrap_key(kek, msg),
            256 => <CASAES256KW as CASAES256KeyWrap>::wrap_key(kek, msg),
            _ => unreachable!(),
        }
    }

    fn kw_unwrap(key_size: usize, kek: Vec<u8>, ct: Vec<u8>) -> Result<Vec<u8>, CasError> {
        match key_size {
            128 => <CASAES128KW as CASAES128KeyWrap>::unwrap_key(kek, ct),
            256 => <CASAES256KW as CASAES256KeyWrap>::unwrap_key(kek, ct),
            _ => unreachable!(),
        }
    }

    fn kwp_wrap(key_size: usize, kek: Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, CasError> {
        match key_size {
            128 => <CASAES128KW as CASAES128KeyWrap>::wrap_key_with_padding(kek, msg),
            256 => <CASAES256KW as CASAES256KeyWrap>::wrap_key_with_padding(kek, msg),
            _ => unreachable!(),
        }
    }

    fn kwp_unwrap(key_size: usize, kek: Vec<u8>, ct: Vec<u8>) -> Result<Vec<u8>, CasError> {
        match key_size {
            128 => <CASAES128KW as CASAES128KeyWrap>::unwrap_key_with_padding(kek, ct),
            256 => <CASAES256KW as CASAES256KeyWrap>::unwrap_key_with_padding(kek, ct),
            _ => unreachable!(),
        }
    }

    #[test]
    fn aes_kw_wycheproof_vectors() {
        run_wycheproof_file("tests/data/aes/aes_wrap_test.json", &kw_wrap, &kw_unwrap);
    }

    #[test]
    fn aes_kwp_wycheproof_vectors() {
        run_wycheproof_file("tests/data/aes/aes_kwp_test.json", &kwp_wrap, &kwp_unwrap);
    }

    #[test]
    fn aes_256_kw_round_trip() {
        let kek = <CASAES256KW as CASAES256KeyWrap>::generate_kek();
        let data_key = <CASAES256KW as CASAES256KeyWrap>::generate_kek();

        let wrapped =
            <CASAES256KW as CASAES256KeyWrap>::wrap_key(kek.clone(), data_key.clone()).unwrap();
        assert_eq!(wrapped.len(), data_key.len() + 8);
        assert_ne!(wrapped[8..], data_key[..]);

        let unwrapped = <CASAES256KW as CASAES256KeyWrap>::unwrap_key(kek, wrapped).unwrap();
        assert_eq!(unwrapped, data_key);
    }

    #[test]
    fn aes_128_kw_round_trip() {
        let kek = <CASAES128KW as CASAES128KeyWrap>::generate_kek();
        let data_key = <CASAES128KW as CASAES128KeyWrap>::generate_kek();

        let wrapped =
            <CASAES128KW as CASAES128KeyWrap>::wrap_key(kek.clone(), data_key.clone()).unwrap();
        assert_eq!(wrapped.len(), data_key.len() + 8);

        let unwrapped = <CASAES128KW as CASAES128KeyWrap>::unwrap_key(kek, wrapped).unwrap();
        assert_eq!(unwrapped, data_key);
    }

    #[test]
    fn aes_256_kwp_round_trip_unaligned_length() {
        let kek = <CASAES256KW as CASAES256KeyWrap>::generate_kek();
        // 20 bytes: not a multiple of the 8-byte semiblock, so only KWP can wrap it.
        let key_data = vec![0xAB; 20];

        let wrapped =
            <CASAES256KW as CASAES256KeyWrap>::wrap_key_with_padding(kek.clone(), key_data.clone())
                .unwrap();
        assert_eq!(wrapped.len(), 32);

        let unwrapped =
            <CASAES256KW as CASAES256KeyWrap>::unwrap_key_with_padding(kek, wrapped).unwrap();
        assert_eq!(unwrapped, key_data);
    }

    #[test]
    fn aes_128_kwp_round_trip_single_byte() {
        let kek = <CASAES128KW as CASAES128KeyWrap>::generate_kek();
        let key_data = vec![0x42];

        let wrapped =
            <CASAES128KW as CASAES128KeyWrap>::wrap_key_with_padding(kek.clone(), key_data.clone())
                .unwrap();
        // 1-8 bytes of key data pad to one semiblock, wrapped as a single AES block.
        assert_eq!(wrapped.len(), 16);

        let unwrapped =
            <CASAES128KW as CASAES128KeyWrap>::unwrap_key_with_padding(kek, wrapped).unwrap();
        assert_eq!(unwrapped, key_data);
    }

    /// The use case from issue #95: rotate the KEK protecting a data key
    /// without ever re-encrypting the data itself.
    #[test]
    fn kek_rotation_preserves_data_key() {
        let old_kek = <CASAES256KW as CASAES256KeyWrap>::generate_kek();
        let new_kek = <CASAES256KW as CASAES256KeyWrap>::generate_kek();
        let data_key = <CASAES256KW as CASAES256KeyWrap>::generate_kek();

        let wrapped_old =
            <CASAES256KW as CASAES256KeyWrap>::wrap_key(old_kek.clone(), data_key.clone()).unwrap();

        // Rotation: unwrap with the old KEK, re-wrap with the new one.
        let recovered =
            <CASAES256KW as CASAES256KeyWrap>::unwrap_key(old_kek.clone(), wrapped_old.clone())
                .unwrap();
        let wrapped_new =
            <CASAES256KW as CASAES256KeyWrap>::wrap_key(new_kek.clone(), recovered).unwrap();

        assert_ne!(wrapped_new, wrapped_old);
        let unwrapped =
            <CASAES256KW as CASAES256KeyWrap>::unwrap_key(new_kek, wrapped_new).unwrap();
        assert_eq!(unwrapped, data_key);

        // The old KEK can no longer recover the new wrapping.
        assert!(<CASAES256KW as CASAES256KeyWrap>::unwrap_key(old_kek, wrapped_old).is_ok());
    }

    #[test]
    fn wrap_key_rejects_invalid_kek_length() {
        let key_data = vec![0u8; 16];
        assert_eq!(
            <CASAES256KW as CASAES256KeyWrap>::wrap_key(vec![0u8; 16], key_data.clone()),
            Err(CasError::InvalidKey)
        );
        assert_eq!(
            <CASAES128KW as CASAES128KeyWrap>::wrap_key(vec![0u8; 32], key_data.clone()),
            Err(CasError::InvalidKey)
        );
        assert_eq!(
            <CASAES256KW as CASAES256KeyWrap>::wrap_key_with_padding(vec![0u8; 24], key_data),
            Err(CasError::InvalidKey)
        );
    }

    #[test]
    fn wrap_key_rejects_invalid_key_data_length() {
        let kek = vec![0u8; 32];
        // NIST SP 800-38F: KW needs at least two semiblocks...
        assert_eq!(
            <CASAES256KW as CASAES256KeyWrap>::wrap_key(kek.clone(), vec![0u8; 8]),
            Err(CasError::InvalidInput)
        );
        // ...and a whole number of semiblocks.
        assert_eq!(
            <CASAES256KW as CASAES256KeyWrap>::wrap_key(kek.clone(), vec![0u8; 20]),
            Err(CasError::InvalidInput)
        );
        // KWP pads arbitrary lengths but the key data must not be empty.
        assert_eq!(
            <CASAES256KW as CASAES256KeyWrap>::wrap_key_with_padding(kek, Vec::new()),
            Err(CasError::InvalidInput)
        );
    }

    #[test]
    fn unwrap_key_rejects_invalid_wrapped_length() {
        let kek = vec![0u8; 32];
        // Below the three-semiblock minimum for unpadded KW.
        assert_eq!(
            <CASAES256KW as CASAES256KeyWrap>::unwrap_key(kek.clone(), vec![0u8; 16]),
            Err(CasError::InvalidInput)
        );
        // Below the two-semiblock minimum for KWP.
        assert_eq!(
            <CASAES256KW as CASAES256KeyWrap>::unwrap_key_with_padding(kek.clone(), vec![0u8; 8]),
            Err(CasError::InvalidInput)
        );
        // Not a whole number of semiblocks.
        assert_eq!(
            <CASAES256KW as CASAES256KeyWrap>::unwrap_key(kek, vec![0u8; 25]),
            Err(CasError::InvalidInput)
        );
    }

    #[test]
    fn unwrap_key_detects_tampering() {
        let kek = <CASAES256KW as CASAES256KeyWrap>::generate_kek();
        let data_key = <CASAES256KW as CASAES256KeyWrap>::generate_kek();

        let wrapped =
            <CASAES256KW as CASAES256KeyWrap>::wrap_key(kek.clone(), data_key.clone()).unwrap();

        let mut tampered = wrapped.clone();
        tampered[0] ^= 0x01;
        assert_eq!(
            <CASAES256KW as CASAES256KeyWrap>::unwrap_key(kek.clone(), tampered),
            Err(CasError::DecryptionFailed)
        );

        let wrong_kek = <CASAES256KW as CASAES256KeyWrap>::generate_kek();
        assert_eq!(
            <CASAES256KW as CASAES256KeyWrap>::unwrap_key(wrong_kek, wrapped),
            Err(CasError::DecryptionFailed)
        );
    }

    #[test]
    fn unwrap_key_with_padding_detects_tampering() {
        let kek = <CASAES128KW as CASAES128KeyWrap>::generate_kek();
        let key_data = vec![0x42; 20];

        let wrapped =
            <CASAES128KW as CASAES128KeyWrap>::wrap_key_with_padding(kek.clone(), key_data)
                .unwrap();

        let mut tampered = wrapped;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            <CASAES128KW as CASAES128KeyWrap>::unwrap_key_with_padding(kek, tampered),
            Err(CasError::DecryptionFailed)
        );
    }
}
