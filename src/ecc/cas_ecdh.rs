use crate::error::CasResult;

use super::types::EcKeyPair;

/// Elliptic-curve Diffie-Hellman (SEC 1 / NIST SP 800-56A ECC CDH).
///
/// | Struct | Curve | Shared secret |
/// |---|---|---|
/// | [`CASEcdhP256`] | NIST P-256 (secp256r1) | 32 bytes |
/// | [`CASEcdhP384`] | NIST P-384 (secp384r1) | 48 bytes |
/// | [`CASEcdhP521`] | NIST P-521 (secp521r1) | 66 bytes |
/// | [`CASEcdhSecp256k1`] | secp256k1 | 32 bytes |
///
/// Keys are PEM, as for [`CASEcdsa`](super::cas_ecdsa::CASEcdsa): private keys
/// PKCS#8 (SEC1 `EC PRIVATE KEY` also accepted), public keys SPKI.
///
/// The shared secret is the x-coordinate of the shared point, big-endian and
/// padded to the field size: the raw "Z" value that WebCrypto `deriveBits`,
/// OpenSSL `EVP_PKEY_derive` and the NIST CDH test vectors use.
///
/// The shared secret is **not** a key. Pass it through a KDF first, e.g.
/// [`CASHkdfSha256::derive`](crate::kdf::cas_hkdf::CASHkdfSha256) with an `info`
/// naming the protocol and both public keys. ECDH on its own is also
/// unauthenticated: the peer's public key must reach you over a channel you
/// trust, or be signed (for example with [`CASEcdsa`](super::cas_ecdsa::CASEcdsa)).
pub trait CASEcdh {
    /// Generates a key pair from the OS random number generator.
    ///
    /// Returns [`CasError::KeyGenerationFailed`](crate::error::CasError::KeyGenerationFailed)
    /// if the random number generator fails. `private_key` is secret and owned by
    /// the caller, who must zeroize it when done (FFI layers: before freeing it).
    fn generate_key_pair() -> CasResult<EcKeyPair>;

    /// Computes the shared secret between `my_private_key` and
    /// `peer_public_key`.
    ///
    /// The peer's key is validated before use: it must be an SPKI key for this
    /// curve whose point is on the curve and is not the point at infinity.
    /// Compressed points are accepted. All four curves have cofactor 1, so a
    /// valid peer key always gives a non-trivial shared secret.
    ///
    /// Returns [`CasError::InvalidPemKey`](crate::error::CasError::InvalidPemKey)
    /// if either key cannot be parsed, is for another curve, or (for the peer
    /// key) is not a valid point. The returned shared secret is owned by the
    /// caller, who must zeroize it when done (FFI layers: before freeing it).
    fn diffie_hellman(my_private_key: String, peer_public_key: String) -> CasResult<Vec<u8>>;
}

/// ECDH over NIST P-256. 32-byte shared secret.
pub struct CASEcdhP256;

/// ECDH over NIST P-384. 48-byte shared secret.
pub struct CASEcdhP384;

/// ECDH over NIST P-521. 66-byte shared secret.
pub struct CASEcdhP521;

/// ECDH over secp256k1. 32-byte shared secret.
pub struct CASEcdhSecp256k1;
