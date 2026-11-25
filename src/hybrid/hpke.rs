use hpke::{
    aead::{AeadTag, AesGcm256},
    kdf::HkdfSha512,
    kem::X25519HkdfSha256,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};

use uuid::Uuid;

use crate::error::{CasError, CasResult};
use super::cas_hybrid::CASHybrid;

type Kem = X25519HkdfSha256;
type Aead = AesGcm256;
type Kdf = HkdfSha512;

pub struct CASHPKE;

/// Longest `info` HPKE accepts in base mode: `hpke` panics when
/// `info.len() + psk_id.len() + 5` reaches 2^16, and a panic must not unwind
/// across the FFI boundary.
const MAX_INFO_LEN: usize = u16::MAX as usize - 5;

fn check_info_len(info: &[u8]) -> CasResult<()> {
    if info.len() > MAX_INFO_LEN {
        return Err(CasError::InvalidInput);
    }
    Ok(())
}

impl CASHybrid for CASHPKE {
    /// Generates a key pair for HPKE using X25519 as the KEM algorithm.
    /// Returns the private key, public key, and a random info string (see
    /// [`generate_info_str`](Self::generate_info_str) for why you should usually
    /// pass your own `info` instead).
    fn generate_key_pair() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (private_key, public_key) = Kem::gen_keypair();
        (
            private_key.to_bytes().to_vec(),
            public_key.to_bytes().to_vec(),
            Self::generate_info_str(),
        )
    }

    /// Returns 16 random bytes (a UUID v4) to use as an HPKE `info` string.
    ///
    /// A random value is **not** domain separation. `info` binds the derived keys to
    /// a context, so the recipient must pass exactly the same bytes, which means this
    /// value has to be sent or stored alongside the message. Prefer a fixed,
    /// application-specific string that both sides already know, such as
    /// `b"my-app/v1/file-encryption"`.
    fn generate_info_str() -> Vec<u8> {
        let uuid = Uuid::new_v4();
        let uuid_bytes: Vec<u8> = uuid.as_bytes().to_vec();
        uuid_bytes
    }

    /// Encrypts data using HPKE with the provided public key, info string and
    /// additional authenticated data (`aad`, which may be empty).
    /// Returns the encapsulated key, ciphertext, and tag, or an error if the
    /// public key could not be parsed or encryption failed.
    fn encrypt(
        plaintext: Vec<u8>,
        public_key: Vec<u8>,
        info_str: Vec<u8>,
        aad: Vec<u8>,
    ) -> CasResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let public_key = <Kem as KemTrait>::PublicKey::from_bytes(public_key.as_slice())
            .map_err(|_| CasError::InvalidKey)?;
        check_info_len(&info_str)?;
        let (encapped_key, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem>(
            &OpModeS::Base,
            &public_key,
            &info_str,
        )
        .map_err(|_| CasError::EncryptionFailed)?;
        let mut msg_copy = plaintext;
        let tag = sender_ctx
            .seal_inout_detached(msg_copy.as_mut_slice().into(), &aad)
            .map_err(|_| CasError::EncryptionFailed)?;
        let ciphertext = msg_copy;
        Ok((
            encapped_key.to_bytes().to_vec(),
            ciphertext,
            tag.to_bytes().to_vec(),
        ))
    }

    /// Decrypts data using HPKE with the provided private key, encapsulated key,
    /// tag, info string and additional authenticated data. `info_str` and `aad`
    /// must match the values used to encrypt.
    /// Returns the decrypted plaintext, or an error if any input could not be
    /// parsed or decryption failed.
    fn decrypt(
        ciphertext: Vec<u8>,
        private_key: Vec<u8>,
        encapped_key: Vec<u8>,
        tag: Vec<u8>,
        info_str: Vec<u8>,
        aad: Vec<u8>,
    ) -> CasResult<Vec<u8>> {
        check_info_len(&info_str)?;
        let server_sk = <Kem as KemTrait>::PrivateKey::from_bytes(&private_key)
            .map_err(|_| CasError::InvalidKey)?;
        let tag = AeadTag::<Aead>::from_bytes(&tag).map_err(|_| CasError::InvalidInput)?;
        let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&encapped_key)
            .map_err(|_| CasError::InvalidKey)?;
        let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &server_sk,
            &encapped_key,
            &info_str,
        )
        .map_err(|_| CasError::DecryptionFailed)?;
        let mut ciphertext_copy = ciphertext;
        receiver_ctx
            .open_inout_detached(ciphertext_copy.as_mut_slice().into(), &aad, &tag)
            .map_err(|_| CasError::DecryptionFailed)?;
        let plaintext = ciphertext_copy;
        Ok(plaintext)
    }
}
