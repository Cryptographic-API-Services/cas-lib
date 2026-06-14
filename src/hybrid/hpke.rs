use hpke::{
    aead::{AeadTag, AesGcm256},
    kdf::HkdfSha512,
    kem::X25519HkdfSha256,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};

use rand::{rngs::StdRng, SeedableRng};
use uuid::Uuid;

use crate::error::{CasError, CasResult};
use super::cas_hybrid::CASHybrid;

type Kem = X25519HkdfSha256;
type Aead = AesGcm256;
type Kdf = HkdfSha512;

pub struct CASHPKE;

impl CASHybrid for CASHPKE {
    /// Generates a key pair for HPKE using X25519 as the KEM algorithm.
    /// Returns the private key, public key, and an info string.
    fn generate_key_pair() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut csprng = StdRng::from_entropy();
        let (private_key, public_key) = Kem::gen_keypair(&mut csprng);
        (
            private_key.to_bytes().to_vec(),
            public_key.to_bytes().to_vec(),
            Self::generate_info_str(),
        )
    }

    /// Generates an info string for HPKE.
    /// Returns a vector of bytes representing the info string.
    fn generate_info_str() -> Vec<u8> {
        let uuid = Uuid::new_v4();
        let uuid_bytes: Vec<u8> = uuid.as_bytes().to_vec();
        uuid_bytes
    }

    /// Encrypts data using HPKE with the provided public key and info string.
    /// Returns the encapsulated key, ciphertext, and tag, or an error if the
    /// public key could not be parsed or encryption failed.
    fn encrypt(
        plaintext: Vec<u8>,
        public_key: Vec<u8>,
        info_str: Vec<u8>,
    ) -> CasResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let mut csprng = StdRng::from_entropy();
        let public_key = <Kem as KemTrait>::PublicKey::from_bytes(public_key.as_slice())
            .map_err(|_| CasError::InvalidKey)?;
        let (encapped_key, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
            &OpModeS::Base,
            &public_key,
            &info_str.as_slice(),
            &mut csprng,
        )
        .map_err(|_| CasError::EncryptionFailed)?;
        let mut msg_copy = plaintext;
        let tag = sender_ctx
            .seal_in_place_detached(&mut msg_copy, b"")
            .map_err(|_| CasError::EncryptionFailed)?;
        let ciphertext = msg_copy;
        Ok((
            encapped_key.to_bytes().to_vec(),
            ciphertext,
            tag.to_bytes().to_vec(),
        ))
    }

    /// Decrypts data using HPKE with the provided private key, encapsulated key, tag, and info string.
    /// Returns the decrypted plaintext, or an error if any input could not be
    /// parsed or decryption failed.
    fn decrypt(
        ciphertext: Vec<u8>,
        private_key: Vec<u8>,
        encapped_key: Vec<u8>,
        tag: Vec<u8>,
        info_str: Vec<u8>,
    ) -> CasResult<Vec<u8>> {
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
            .open_in_place_detached(&mut ciphertext_copy, b"", &tag)
            .map_err(|_| CasError::DecryptionFailed)?;
        let plaintext = ciphertext_copy;
        Ok(plaintext)
    }
}
