//! PEM key handling and key generation shared by every curve in the `ecc`
//! module.

use elliptic_curve::pkcs8::{AssociatedOid, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point, ValidatePublicKey};
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, Generate, PublicKey, SecretKey};
use getrandom::SysRng;
use zeroize::Zeroizing;

use crate::error::{CasError, CasResult};

use super::types::EcKeyPair;

/// Generates a key pair on curve `C` from the OS random number generator and
/// PEM-encodes it (PKCS#8 private key, SPKI public key).
///
/// The secret scalar is drawn by rejection sampling, so it is uniform in
/// `[1, n)`. Returns [`CasError::KeyGenerationFailed`] if the OS random number
/// generator fails, and [`CasError::InvalidPemKey`] if encoding fails.
pub(crate) fn generate<C>() -> CasResult<EcKeyPair>
where
    C: AssociatedOid + CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    // `SecretKey` zeroizes itself on drop.
    let secret_key =
        SecretKey::<C>::try_generate_from_rng(&mut SysRng).map_err(|_| CasError::KeyGenerationFailed)?;
    let public_key = secret_key
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| CasError::InvalidPemKey)?;
    // `to_pkcs8_pem` returns a `Zeroizing<String>`; move the string out rather
    // than copying it, so no unzeroized copy is left behind.
    let mut private_pem = secret_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| CasError::InvalidPemKey)?;
    Ok(EcKeyPair {
        private_key: std::mem::take(&mut *private_pem),
        public_key,
    })
}

/// Parses a PEM private key on curve `C`: PKCS#8 (`PRIVATE KEY`) or SEC1
/// (`EC PRIVATE KEY`). The PEM string is zeroized once parsed; the parsed key
/// zeroizes itself on drop.
///
/// Returns [`CasError::InvalidPemKey`] if the PEM cannot be decoded, names a
/// different curve, holds a scalar outside `[1, n)`, or embeds a public key
/// that does not match the private scalar.
pub(crate) fn parse_private<C>(private_key: String) -> CasResult<SecretKey<C>>
where
    C: AssociatedOid + CurveArithmetic + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
{
    let pem = Zeroizing::new(private_key);
    SecretKey::<C>::from_pem(&pem).map_err(|_| CasError::InvalidPemKey)
}

/// Parses an SPKI PEM public key on curve `C`.
///
/// The result is always a valid public key: on the curve and not the point at
/// infinity. Compressed and uncompressed points are accepted. Returns
/// [`CasError::InvalidPemKey`] if the PEM cannot be decoded, names a different
/// curve or algorithm, or holds a point that is not a valid public key.
pub(crate) fn parse_public<C>(public_key: &str) -> CasResult<PublicKey<C>>
where
    C: AssociatedOid + CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    PublicKey::<C>::from_public_key_pem(public_key).map_err(|_| CasError::InvalidPemKey)
}
