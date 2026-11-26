use ::hkdf::Hkdf;
use sha2_hkdf::{Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use super::cas_hkdf::{CASHKDF, CASHkdfSha256, CASHkdfSha512};
use crate::error::{CasError, CasResult};

/// RFC 5869 treats a missing salt as `HashLen` zero bytes, and HMAC pads a short
/// key with zeros, so an empty salt and no salt are the same. `None` says so.
fn salt_option(salt: &[u8]) -> Option<&[u8]> {
    if salt.is_empty() {
        None
    } else {
        Some(salt)
    }
}

/// Fills a zeroizing buffer of `length` bytes with `fill` and hands it to the
/// caller without leaving an unzeroed copy behind.
fn output<E>(
    length: usize,
    max: usize,
    fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
) -> CasResult<Vec<u8>> {
    if length == 0 || length > max {
        return Err(CasError::InvalidParameters);
    }
    let mut okm = Zeroizing::new(vec![0u8; length]);
    fill(&mut okm).map_err(|_| CasError::InvalidParameters)?;
    Ok(std::mem::take(&mut *okm))
}

// The `Hkdf` state (an HMAC keyed with the PRK) lives inside the `hkdf` crate,
// which does not zeroize it on drop. The buffers this crate allocates are zeroized.
macro_rules! impl_hkdf {
    ($ty:ty, $hash:ty, $hash_len:expr) => {
        impl CASHKDF for $ty {
            const HASH_LEN: usize = $hash_len;

            fn extract(salt: Vec<u8>, ikm: Vec<u8>) -> Vec<u8> {
                let ikm = Zeroizing::new(ikm);
                let (mut prk, _) = Hkdf::<$hash>::extract(salt_option(&salt), &ikm);
                let result = prk.to_vec();
                prk.as_mut_slice().zeroize();
                result
            }

            fn expand(prk: Vec<u8>, info: Vec<u8>, length: usize) -> CasResult<Vec<u8>> {
                let prk = Zeroizing::new(prk);
                let hk = Hkdf::<$hash>::from_prk(&prk).map_err(|_| CasError::InvalidKey)?;
                output(length, Self::MAX_OUTPUT_LEN, |okm| hk.expand(&info, okm))
            }

            fn derive(
                salt: Vec<u8>,
                ikm: Vec<u8>,
                info: Vec<u8>,
                length: usize,
            ) -> CasResult<Vec<u8>> {
                let ikm = Zeroizing::new(ikm);
                let hk = Hkdf::<$hash>::new(salt_option(&salt), &ikm);
                output(length, Self::MAX_OUTPUT_LEN, |okm| hk.expand(&info, okm))
            }
        }
    };
}

impl_hkdf!(CASHkdfSha256, Sha256, 32);
impl_hkdf!(CASHkdfSha512, Sha512, 64);
