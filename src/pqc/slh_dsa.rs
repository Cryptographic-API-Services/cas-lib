use std::mem::MaybeUninit;

// `slh-dsa` does not re-export typenum; this is the same `typenum` crate (there
// is only one version in the build), so `Unsigned` is the trait `SkLen` implements.
use aes_gcm::aead::array::typenum::Unsigned;
use signature::*;
use slh_dsa::*;
use zeroize::Zeroizing;

use crate::error::{CasError, CasResult};
use crate::pqc::cas_pqc::SlhDsaKeyPair;

/// The SLH-DSA parameter set used by this module.
type Params = Shake128f;

/// The security parameter n of [`Params`], in bytes: the length of each of the
/// three key-generation seeds (`SK.seed`, `SK.prf`, `PK.seed`).
///
/// slh-dsa 0.0.3 keeps n in a crate-private trait, so it is read from the
/// public serialized key lengths instead: FIPS 205 section 9.1 encodes a
/// private key as `SK.seed || SK.prf || PK.seed || PK.root` (4n bytes) and a
/// public key as `PK.seed || PK.root` (2n bytes).
const N: usize = <<Params as SigningKeyLen>::SkLen as Unsigned>::USIZE / 4;

/// The three seeds, `SK.seed || SK.prf || PK.seed`.
const SEEDS_LEN: usize = 3 * N;

// The key lengths must agree on n, so a wrong reading of the encoding fails to
// compile instead of handing `slh_keygen_internal` seeds of the wrong length
// (it panics on those).
const _: () = assert!(<<Params as SigningKeyLen>::SkLen as Unsigned>::USIZE == 4 * N);
const _: () = assert!(<<Params as VerifyingKeyLen>::VkLen as Unsigned>::USIZE == 2 * N);

/// Builds the key pair from `SK.seed || SK.prf || PK.seed`, n bytes each
/// (FIPS 205 `slh_keygen_internal`).
fn key_pair_from_seeds(seeds: &[u8; SEEDS_LEN]) -> SlhDsaKeyPair {
    let (sk_seed, rest) = seeds.split_at(N);
    let (sk_prf, pk_seed) = rest.split_at(N);
    let sk = SigningKey::<Params>::slh_keygen_internal(sk_seed, sk_prf, pk_seed);
    let verifying_key = sk.verifying_key();
    let vk_bytes = verifying_key.to_bytes();
    SlhDsaKeyPair {
        signing_key: sk.to_bytes().to_vec(),
        verification_key: vk_bytes.to_vec(),
    }
}

/// Generates a new SLH-DSA-SHAKE-128f key pair.
///
/// `signing_key` is the secret key, owned by the caller, who must zeroize it
/// when done (FFI layers: before freeing it). See the crate-level docs.
///
/// # Panics
///
/// Panics if the operating system's random number generator fails, like
/// x25519-dalek's `StaticSecret::random` (and `rand`'s `OsRng`).
pub fn generate_signing_and_verification_key() -> SlhDsaKeyPair {
    // FIPS 205 slh_keygen (Algorithm 21): draw SK.seed, SK.prf and PK.seed, n
    // bytes each, and run slh_keygen_internal. slh-dsa's `SigningKey::new`
    // does exactly this, in this order, but needs a rand_core 0.6 RNG; these
    // seeds come straight from the OS RNG into a buffer zeroized on drop.
    let mut buf = Zeroizing::new([MaybeUninit::<u8>::uninit(); SEEDS_LEN]);
    let seeds = getrandom::fill_uninit(&mut *buf).expect("getrandom failure");
    let seeds: &[u8; SEEDS_LEN] = (&*seeds)
        .try_into()
        .expect("getrandom::fill_uninit fills the whole buffer");
    key_pair_from_seeds(seeds)
}

/// Signs a message with an SLH-DSA signing key.
/// Returns an error if the signing key could not be parsed.
pub fn sign_message(message: Vec<u8>, signing_key: Vec<u8>) -> CasResult<Vec<u8>> {
    let key = SigningKey::<Shake128f>::try_from(signing_key.as_slice())
        .map_err(|_| CasError::InvalidKey)?;
    let signature: Signature<Shake128f> = key.sign(&message);
    Ok(signature.to_bytes().to_vec())
}

/// Verifies an SLH-DSA signature.
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is not, and
/// an error if the verification key or signature could not be parsed.
pub fn verify_signature(message: Vec<u8>, signature: Vec<u8>, verification_key: Vec<u8>) -> CasResult<bool> {
    let vk = VerifyingKey::<Shake128f>::try_from(verification_key.as_slice())
        .map_err(|_| CasError::InvalidKey)?;
    let sig = Signature::<Shake128f>::try_from(signature.as_slice())
        .map_err(|_| CasError::InvalidSignature)?;
    Ok(vk.verify(&message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use slh_dsa::signature::rand_core::{self, CryptoRng, RngCore};

    /// A rand_core 0.6 "RNG" that hands out fixed bytes in order, so
    /// `SigningKey::new` can be fed known seeds.
    struct Replay<'a>(&'a [u8]);

    impl RngCore for Replay<'_> {
        fn next_u32(&mut self) -> u32 {
            unimplemented!("SigningKey::new only calls fill_bytes")
        }
        fn next_u64(&mut self) -> u64 {
            unimplemented!("SigningKey::new only calls fill_bytes")
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let (head, tail) = self.0.split_at(dest.len());
            dest.copy_from_slice(head);
            self.0 = tail;
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for Replay<'_> {}

    #[test]
    fn seed_length_is_n_for_shake_128f() {
        assert_eq!(N, 16);
        assert_eq!(SEEDS_LEN, 48);
    }

    /// `key_pair_from_seeds` must build the same key as `SigningKey::new` when
    /// that is given the same bytes from its RNG, i.e. our seed order and
    /// lengths match what `new` draws.
    #[test]
    fn key_pair_from_seeds_matches_signing_key_new() {
        for fill in [0x00u8, 0x5a, 0xff] {
            let mut seeds = [fill; SEEDS_LEN];
            for (i, byte) in seeds.iter_mut().enumerate() {
                *byte ^= i as u8;
            }
            let mut rng = Replay(&seeds);
            let expected = SigningKey::<Params>::new(&mut rng);
            assert!(rng.0.is_empty(), "SigningKey::new must draw exactly 3n bytes");

            let key_pair = key_pair_from_seeds(&seeds);
            assert_eq!(key_pair.signing_key, expected.to_bytes().to_vec());
            assert_eq!(key_pair.verification_key, expected.verifying_key().to_bytes().to_vec());
        }
    }

    /// NIST ACVP SLH-DSA-keyGen-FIPS205, SLH-DSA-SHAKE-128f, tcId 31
    /// (more cases in `tests/pqc.rs`).
    #[test]
    fn key_pair_from_seeds_matches_acvp_vector() {
        let seeds: [u8; SEEDS_LEN] = [
            0x39, 0x56, 0xab, 0x39, 0x1b, 0x4d, 0x22, 0xfc, 0x90, 0x7a, 0xf0, 0x74, 0x03, 0x26, 0xd0, 0x61,
            0xab, 0x0e, 0xb2, 0x06, 0x43, 0x6f, 0x2b, 0x86, 0xeb, 0xe0, 0x86, 0xd7, 0x77, 0x39, 0xb3, 0xe4,
            0x56, 0x50, 0x5c, 0x22, 0x9f, 0x4e, 0x7f, 0xa6, 0xb2, 0x01, 0x71, 0x4c, 0x7d, 0xcc, 0x9d, 0xa3,
        ];
        let pk_root = [
            0x66, 0x57, 0x8f, 0x1f, 0x24, 0xc3, 0xfe, 0x37, 0x1c, 0x97, 0xc1, 0x4c, 0xe0, 0xe7, 0x9c, 0xdc,
        ];
        let key_pair = key_pair_from_seeds(&seeds);
        assert_eq!(key_pair.verification_key, [&seeds[2 * N..], &pk_root[..]].concat());
        assert_eq!(key_pair.signing_key, [&seeds[..], &pk_root[..]].concat());
    }
}
