use ecdsa::signature::{Signer, Verifier};
use ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::error::{CasError, CasResult};

use super::cas_ecdsa::{CASEcdsa, CASEcdsaP256, CASEcdsaP384, CASEcdsaP521, CASEcdsaSecp256k1};
use super::keys::{generate, parse_private, parse_public};
use super::types::EcKeyPair;

/// Implements [`CASEcdsa`] for `$ty` on curve `$curve`.
///
/// The curve crates fix the hash (`DigestAlgorithm`) and RFC 6979 signing.
/// `$normalize_s` makes `verify` / `verify_der` normalize a high-S signature to
/// its low-S form before verifying. That only matters for secp256k1, whose
/// `ecdsa` implementation rejects high-S signatures itself (`NORMALIZE_S`); the
/// NIST curves accept both forms anyway.
///
/// A macro rather than a generic function: the bounds `ecdsa` needs for DER
/// signatures (`der::MaxSize<C>: ArraySize` and friends) would have to be
/// repeated on every function.
macro_rules! impl_cas_ecdsa {
    ($ty:ty, $curve:ty, $normalize_s:expr) => {
        impl $ty {
            fn signing_key(private_key: String) -> CasResult<SigningKey<$curve>> {
                // The `SecretKey` and the `SigningKey` both zeroize on drop.
                let secret_key = parse_private::<$curve>(private_key)?;
                Ok(SigningKey::<$curve>::from(&secret_key))
            }

            fn sign_signature(private_key: String, message: &[u8]) -> CasResult<Signature<$curve>> {
                Self::signing_key(private_key)?
                    .try_sign(message)
                    .map_err(|_| CasError::SigningFailed)
            }

            fn verifying_key(public_key: &str) -> CasResult<VerifyingKey<$curve>> {
                Ok(VerifyingKey::<$curve>::from(parse_public::<$curve>(public_key)?))
            }

            fn verify_signature(
                public_key: &str,
                message: &[u8],
                signature: Option<Signature<$curve>>,
                normalize_s: bool,
            ) -> CasResult<bool> {
                // Parse the key first, so a bad key is reported whatever the signature.
                let verifying_key = Self::verifying_key(public_key)?;
                let Some(signature) = signature else {
                    return Ok(false);
                };
                let signature = if normalize_s { signature.normalize_s() } else { signature };
                Ok(verifying_key.verify(message, &signature).is_ok())
            }

            /// Parses a P1363 signature; `None` if malformed (wrong length, `r` or `s` out of range).
            fn parse_p1363(signature: &[u8]) -> Option<Signature<$curve>> {
                Signature::<$curve>::from_slice(signature).ok()
            }

            /// Parses a strict-DER signature; `None` if malformed.
            fn parse_der(signature: &[u8]) -> Option<Signature<$curve>> {
                Signature::<$curve>::from_der(signature).ok()
            }
        }

        impl CASEcdsa for $ty {
            fn generate_key_pair() -> CasResult<EcKeyPair> {
                generate::<$curve>()
            }

            fn sign(private_key: String, message: Vec<u8>) -> CasResult<Vec<u8>> {
                Ok(Self::sign_signature(private_key, &message)?.to_vec())
            }

            fn sign_der(private_key: String, message: Vec<u8>) -> CasResult<Vec<u8>> {
                Ok(Self::sign_signature(private_key, &message)?.to_der().as_bytes().to_vec())
            }

            fn verify(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
                Self::verify_signature(&public_key, &message, Self::parse_p1363(&signature), $normalize_s)
            }

            fn verify_der(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
                Self::verify_signature(&public_key, &message, Self::parse_der(&signature), $normalize_s)
            }
        }
    };
}

impl_cas_ecdsa!(CASEcdsaP256, p256::NistP256, false);
impl_cas_ecdsa!(CASEcdsaP384, p384::NistP384, false);
impl_cas_ecdsa!(CASEcdsaP521, p521::NistP521, false);
impl_cas_ecdsa!(CASEcdsaSecp256k1, k256::Secp256k1, true);

impl CASEcdsaSecp256k1 {
    /// Like [`verify`](CASEcdsa::verify), but also rejects high-S signatures
    /// (`s > n / 2`), as Bitcoin (BIP-62 / BIP-146) and Ethereum require.
    /// Signatures from [`sign`](CASEcdsa::sign) are always low-S.
    ///
    /// Returns `Ok(true)` only for a valid low-S P1363 signature. Returns
    /// [`CasError::InvalidPemKey`] if the public key cannot be parsed or is for
    /// another curve.
    pub fn verify_low_s(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        Self::verify_signature(&public_key, &message, Self::parse_p1363(&signature), false)
    }

    /// Like [`verify_der`](CASEcdsa::verify_der), but also rejects high-S
    /// signatures (`s > n / 2`), as Bitcoin (BIP-62 / BIP-146) and Ethereum
    /// require. Signatures from [`sign_der`](CASEcdsa::sign_der) are always low-S.
    ///
    /// Returns `Ok(true)` only for a valid low-S strict-DER signature. Returns
    /// [`CasError::InvalidPemKey`] if the public key cannot be parsed or is for
    /// another curve.
    pub fn verify_der_low_s(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool> {
        Self::verify_signature(&public_key, &message, Self::parse_der(&signature), false)
    }
}
