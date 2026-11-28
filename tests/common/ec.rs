//! Builds PEM keys from raw test-vector values for the `ecc` tests.
//!
//! NIST and Wycheproof give EC keys as raw coordinates, raw scalars or SPKI
//! DER, while `cas_lib::ecc` takes PEM. Public keys are assembled byte by byte
//! (a fixed SPKI prefix plus the SEC1 point) rather than through the curve
//! crates, so that deliberately invalid points (off the curve, coordinates out
//! of range) reach the library under test instead of being rejected here.

use elliptic_curve::pkcs8::{EncodePrivateKey, LineEnding};

/// The curves the `ecc` module supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
    P521,
    Secp256k1,
}

impl Curve {
    /// Field (and scalar) size in bytes.
    pub fn field_len(self) -> usize {
        match self {
            Curve::P256 | Curve::Secp256k1 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }

    /// DER of `SubjectPublicKeyInfo` up to and including the BIT STRING's
    /// unused-bits byte, for an uncompressed point (`04 || x || y`):
    /// `SEQUENCE { SEQUENCE { id-ecPublicKey, namedCurve }, BIT STRING }`.
    fn spki_prefix(self) -> &'static str {
        match self {
            Curve::P256 => "3059301306072a8648ce3d020106082a8648ce3d030107034200",
            Curve::P384 => "3076301006072a8648ce3d020106052b81040022036200",
            Curve::P521 => "30819b301006072a8648ce3d020106052b8104002303818600",
            Curve::Secp256k1 => "3056301006072a8648ce3d020106052b8104000a034200",
        }
    }

    /// SPKI PEM for the uncompressed point `(x, y)`. Returns `None` if a
    /// coordinate does not fit in the field size (it cannot be encoded at all).
    /// Coordinates shorter than the field size are left-padded with zeros.
    pub fn public_key_pem(self, x: &[u8], y: &[u8]) -> Option<String> {
        let x = left_pad(x, self.field_len())?;
        let y = left_pad(y, self.field_len())?;
        let mut der = decode_hex(self.spki_prefix());
        der.push(0x04);
        der.extend_from_slice(&x);
        der.extend_from_slice(&y);
        Some(pem("PUBLIC KEY", &der))
    }

    /// PKCS#8 PEM private key for the big-endian scalar `d`. Leading zero
    /// bytes beyond the field size are stripped and shorter values padded.
    /// Returns `None` if the scalar is not a valid private key (0 or >= n).
    pub fn private_key_pem(self, d: &[u8]) -> Option<String> {
        let d = left_pad(strip_leading_zeros(d), self.field_len())?;
        fn encode<C>(d: &[u8]) -> Option<String>
        where
            elliptic_curve::SecretKey<C>: EncodePrivateKey,
            C: elliptic_curve::Curve,
        {
            let key = elliptic_curve::SecretKey::<C>::from_slice(d).ok()?;
            Some(key.to_pkcs8_pem(LineEnding::LF).ok()?.to_string())
        }
        match self {
            Curve::P256 => encode::<p256::NistP256>(&d),
            Curve::P384 => encode::<p384::NistP384>(&d),
            Curve::P521 => encode::<p521::NistP521>(&d),
            Curve::Secp256k1 => encode::<k256::Secp256k1>(&d),
        }
    }
}

impl Curve {
    /// Re-encodes a P1363 (`r || s`) signature as ASN.1 DER with the `ecdsa`
    /// crate. `None` if `r` or `s` is out of range (no DER form exists then
    /// that the library would accept either).
    pub fn p1363_to_der(self, signature: &[u8]) -> Option<Vec<u8>> {
        Some(match self {
            Curve::P256 => p256::ecdsa::Signature::from_slice(signature).ok()?.to_der().as_bytes().to_vec(),
            Curve::P384 => p384::ecdsa::Signature::from_slice(signature).ok()?.to_der().as_bytes().to_vec(),
            Curve::P521 => p521::ecdsa::Signature::from_slice(signature).ok()?.to_der().as_bytes().to_vec(),
            Curve::Secp256k1 => k256::ecdsa::Signature::from_slice(signature).ok()?.to_der().as_bytes().to_vec(),
        })
    }

    /// The group order `n`, big-endian, padded to the field size.
    pub fn order(self) -> Vec<u8> {
        let n = match self {
            Curve::P256 => "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            Curve::P384 => "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            Curve::P521 => "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
            Curve::Secp256k1 => "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        };
        left_pad(&decode_hex(n), self.field_len()).unwrap()
    }

    /// Turns a P1363 signature `(r, s)` into `(r, n - s)`, the other valid
    /// signature for the same key and message.
    pub fn negate_s(self, signature: &[u8]) -> Vec<u8> {
        let len = self.field_len();
        assert_eq!(signature.len(), 2 * len);
        let (r, s) = signature.split_at(len);
        let n = self.order();
        let mut out = r.to_vec();
        let mut neg = vec![0u8; len];
        let mut borrow = 0i16;
        for i in (0..len).rev() {
            let mut d = n[i] as i16 - s[i] as i16 - borrow;
            borrow = if d < 0 { d += 256; 1 } else { 0 };
            neg[i] = d as u8;
        }
        assert_eq!(borrow, 0, "s must be below n");
        out.extend_from_slice(&neg);
        out
    }
}

pub fn decode_hex(hex: &str) -> Vec<u8> {
    let hex = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex.to_string() };
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

/// Left-pads `bytes` with zeros to `len`, after dropping redundant leading
/// zeros. `None` if the value needs more than `len` bytes.
pub fn left_pad(bytes: &[u8], len: usize) -> Option<Vec<u8>> {
    let bytes = strip_leading_zeros(bytes);
    if bytes.len() > len {
        return None;
    }
    let mut out = vec![0u8; len - bytes.len()];
    out.extend_from_slice(bytes);
    Some(out)
}

/// PEM-armors DER bytes (RFC 7468): base64 in 64-character lines.
pub fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                b64.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
