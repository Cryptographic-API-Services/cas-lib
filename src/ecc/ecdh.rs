use elliptic_curve::pkcs8::AssociatedOid;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point, ValidatePublicKey};
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize};

use crate::error::CasResult;

use super::cas_ecdh::{CASEcdh, CASEcdhP256, CASEcdhP384, CASEcdhP521, CASEcdhSecp256k1};
use super::keys::{generate, parse_private, parse_public};
use super::types::EcKeyPair;

/// ECDH on curve `C`. `parse_public` guarantees the peer's point is on the curve
/// and not the identity; the secret scalar is non-zero; with cofactor 1 the
/// shared point therefore can't be the identity either.
fn diffie_hellman<C>(my_private_key: String, peer_public_key: String) -> CasResult<Vec<u8>>
where
    C: AssociatedOid + CurveArithmetic + ValidatePublicKey,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let peer_public_key = parse_public::<C>(&peer_public_key)?;
    // `SecretKey` and `SharedSecret` zeroize themselves on drop.
    let secret_key = parse_private::<C>(my_private_key)?;
    let shared_secret = secret_key.diffie_hellman(&peer_public_key);
    Ok(shared_secret.raw_secret_bytes().to_vec())
}

macro_rules! impl_cas_ecdh {
    ($ty:ty, $curve:ty) => {
        impl CASEcdh for $ty {
            fn generate_key_pair() -> CasResult<EcKeyPair> {
                generate::<$curve>()
            }

            fn diffie_hellman(my_private_key: String, peer_public_key: String) -> CasResult<Vec<u8>> {
                diffie_hellman::<$curve>(my_private_key, peer_public_key)
            }
        }
    };
}

impl_cas_ecdh!(CASEcdhP256, p256::NistP256);
impl_cas_ecdh!(CASEcdhP384, p384::NistP384);
impl_cas_ecdh!(CASEcdhP521, p521::NistP521);
impl_cas_ecdh!(CASEcdhSecp256k1, k256::Secp256k1);
