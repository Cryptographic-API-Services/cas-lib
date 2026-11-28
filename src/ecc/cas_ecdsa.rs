use crate::error::CasResult;

use super::types::EcKeyPair;

/// ECDSA (FIPS 186-5 / SEC 1) key generation, signing and verification.
///
/// Implemented for four curves, each with its standard hash:
///
/// | Struct | Curve | Hash | JOSE `alg` | P1363 signature |
/// |---|---|---|---|---|
/// | [`CASEcdsaP256`] | NIST P-256 (secp256r1) | SHA-256 | `ES256` | 64 bytes |
/// | [`CASEcdsaP384`] | NIST P-384 (secp384r1) | SHA-384 | `ES384` | 96 bytes |
/// | [`CASEcdsaP521`] | NIST P-521 (secp521r1) | SHA-512 | `ES512` | 132 bytes |
/// | [`CASEcdsaSecp256k1`] | secp256k1 | SHA-256 | `ES256K` | 64 bytes |
///
/// Every function hashes the message itself: pass the message, not a digest
/// of it.
///
/// Keys are PEM: private keys PKCS#8 (`PRIVATE KEY`; SEC1 `EC PRIVATE KEY` is
/// also accepted), public keys SPKI (`PUBLIC KEY`). A key for another curve is
/// rejected with [`CasError::InvalidPemKey`](crate::error::CasError::InvalidPemKey).
///
/// Signatures come in two encodings:
///
/// - **IEEE P1363** (`sign` / `verify`): the fixed-size `r || s`, each
///   big-endian and padded to the field size. This is what JOSE (JWS/JWT),
///   COSE and WebCrypto use.
/// - **ASN.1 DER** (`sign_der` / `verify_der`): the `ECDSA-Sig-Value` SEQUENCE
///   that X.509, TLS, OpenSSL and most HSMs use. Verification accepts only
///   strict DER, not BER.
///
/// Signing is deterministic (RFC 6979): the same key and message always give
/// the same signature, and no random number generator is involved.
pub trait CASEcdsa {
    /// Generates a key pair from the OS random number generator.
    ///
    /// Returns [`CasError::KeyGenerationFailed`](crate::error::CasError::KeyGenerationFailed)
    /// if the random number generator fails. `private_key` is secret and owned by
    /// the caller, who must zeroize it when done (FFI layers: before freeing it).
    fn generate_key_pair() -> CasResult<EcKeyPair>;

    /// Signs `message` and returns the fixed-size IEEE P1363 (`r || s`) signature.
    ///
    /// Returns [`CasError::InvalidPemKey`](crate::error::CasError::InvalidPemKey)
    /// if the private key cannot be parsed or is for another curve.
    fn sign(private_key: String, message: Vec<u8>) -> CasResult<Vec<u8>>;

    /// Signs `message` and returns the ASN.1 DER signature.
    ///
    /// Returns [`CasError::InvalidPemKey`](crate::error::CasError::InvalidPemKey)
    /// if the private key cannot be parsed or is for another curve.
    fn sign_der(private_key: String, message: Vec<u8>) -> CasResult<Vec<u8>>;

    /// Verifies an IEEE P1363 (`r || s`) signature over `message`.
    ///
    /// Returns `Ok(true)` if it is valid and `Ok(false)` if it is not, including
    /// a signature of the wrong length or with `r` or `s` out of range. Returns
    /// [`CasError::InvalidPemKey`](crate::error::CasError::InvalidPemKey) if the
    /// public key cannot be parsed or is for another curve.
    fn verify(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool>;

    /// Verifies an ASN.1 DER signature over `message`.
    ///
    /// Returns `Ok(true)` if it is valid and `Ok(false)` if it is not, including
    /// a signature that is not strict DER or has `r` or `s` out of range. Returns
    /// [`CasError::InvalidPemKey`](crate::error::CasError::InvalidPemKey) if the
    /// public key cannot be parsed or is for another curve.
    fn verify_der(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool>;
}

/// ECDSA over NIST P-256 with SHA-256 (`ES256`).
pub struct CASEcdsaP256;

/// ECDSA over NIST P-384 with SHA-384 (`ES384`).
pub struct CASEcdsaP384;

/// ECDSA over NIST P-521 with SHA-512 (`ES512`).
pub struct CASEcdsaP521;

/// ECDSA over secp256k1 with SHA-256 (`ES256K`).
///
/// # High-S signatures
///
/// For any valid signature `(r, s)`, `(r, n - s)` is valid too. Bitcoin
/// (BIP-62 / BIP-146) and Ethereum remove that malleability by accepting only
/// the "low-S" form, `s <= n / 2`.
///
/// - [`sign`](CASEcdsa::sign) and [`sign_der`](CASEcdsa::sign_der) always
///   produce low-S signatures, which every verifier accepts.
/// - [`verify`](CASEcdsa::verify) and [`verify_der`](CASEcdsa::verify_der)
///   follow standard ECDSA (SEC 1, RFC 8812 `ES256K`) and accept both forms, so
///   signatures from signers that don't normalize still verify.
/// - [`verify_low_s`](CASEcdsaSecp256k1::verify_low_s) and
///   [`verify_der_low_s`](CASEcdsaSecp256k1::verify_der_low_s) reject high-S
///   signatures. Use them where malleability matters, e.g. when a signature or
///   a hash of it identifies a transaction.
pub struct CASEcdsaSecp256k1;
