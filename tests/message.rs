#[cfg(test)]
mod message {
    use cas_lib::message::{cas_hmac::CASHMAC, hmac::HMAC};
    use std::fs;

    #[test]
    pub fn hmac_sign() {
        let key = vec![1, 2, 3, 4, 5];
        let message = vec![6, 7, 8, 9, 10];
        // Replace `ConcreteHmacType` with the actual struct that implements CASHMAC
        let signature = HMAC::sign(key.clone(), message.clone()).unwrap();
        assert!(!signature.is_empty());
    }

    #[test]
    pub fn hmac_verify() {
        let key = vec![1, 2, 3, 4, 5];
        let message = vec![6, 7, 8, 9, 10];
        let signature = HMAC::sign(key.clone(), message.clone()).unwrap();
        let is_valid = HMAC::verify(key, message, signature).unwrap();
        assert!(is_valid);
    }

    /// A single HMACVS known-answer record from the `[L=32]` (SHA-256) block.
    #[derive(Debug)]
    struct HmacCase {
        /// Tag length in bytes. `mac` is the full HMAC truncated to this length.
        tlen: usize,
        key: Vec<u8>,
        msg: Vec<u8>,
        mac: Vec<u8>,
    }

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

    /// Parses the NIST HMACVS file (`HMACVS.pdf` format), returning only the
    /// records under the `[L=32]` / SHA-256 section, which is all the current
    /// SHA-256-only `HMAC` implementation can validate.
    fn parse_hmac_vectors(path: &str) -> Vec<HmacCase> {
        let contents = fs::read_to_string(path).unwrap();
        let mut in_l32 = false;
        let mut klen: Option<usize> = None;
        let mut tlen: Option<usize> = None;
        let mut key: Option<Vec<u8>> = None;
        let mut msg: Option<Vec<u8>> = None;
        let mut cases = Vec::new();

        for line in contents.lines() {
            let line = line.trim();

            if line.starts_with('[') {
                in_l32 = line == "[L=32]";
                continue;
            }

            if !in_l32 || line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(value) = line.strip_prefix("Klen = ") {
                klen = Some(value.parse::<usize>().unwrap());
            } else if let Some(value) = line.strip_prefix("Tlen = ") {
                tlen = Some(value.parse::<usize>().unwrap());
            } else if let Some(value) = line.strip_prefix("Key = ") {
                key = Some(decode_hex(value));
            } else if let Some(value) = line.strip_prefix("Msg = ") {
                msg = Some(decode_hex(value));
            } else if let Some(value) = line.strip_prefix("Mac = ") {
                let klen = klen.take().unwrap();
                let tlen = tlen.take().unwrap();
                let key = key.take().unwrap();
                let msg = msg.take().unwrap();
                let mac = decode_hex(value);

                assert_eq!(key.len(), klen, "Key length must match Klen");
                assert_eq!(mac.len(), tlen, "Mac length must match Tlen");

                cases.push(HmacCase { tlen, key, msg, mac });
            }
            // `Count = ...` and anything else is ignored.
        }

        cases
    }

    /// Validates every SHA-256 HMACVS vector by signing and comparing against
    /// the (possibly truncated) expected tag, plus a full-length `verify`.
    #[test]
    fn test_hmac_sha256_nist_vectors() {
        let cases = parse_hmac_vectors("tests/data/hmac/HMAC.txt");
        assert!(!cases.is_empty(), "no [L=32] vectors were parsed");

        for case in &cases {
            let tag = HMAC::sign(case.key.clone(), case.msg.clone()).unwrap();
            assert_eq!(tag.len(), 32, "SHA-256 HMAC must produce a 32-byte tag");

            // `Mac` is the full tag truncated to `Tlen` bytes.
            assert_eq!(&tag[..case.tlen], &case.mac[..]);

            // `verify` requires a full-length tag, so it only applies when the
            // vector is not truncated.
            if case.tlen == 32 {
                assert!(HMAC::verify(case.key.clone(), case.msg.clone(), case.mac.clone()).unwrap());
            }
        }
    }

    /// A tampered tag must not verify.
    #[test]
    fn test_hmac_sha256_nist_vectors_negative() {
        let cases = parse_hmac_vectors("tests/data/hmac/HMAC.txt");
        let case = cases
            .iter()
            .find(|c| c.tlen == 32)
            .expect("expected at least one full-length (Tlen=32) vector");

        let mut tampered = case.mac.clone();
        tampered[0] ^= 0x01;

        assert!(!HMAC::verify(case.key.clone(), case.msg.clone(), tampered).unwrap());
    }
}
