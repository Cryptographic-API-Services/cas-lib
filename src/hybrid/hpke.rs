use hpke::{
    aead::{AeadTag, AesGcm256},
    kdf::HkdfSha512,
    kem::X25519HkdfSha256,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};

use rand::{rngs::StdRng, SeedableRng};
use uuid::Uuid;

use super::cas_hybrid::CASHybrid;

type Kem = X25519HkdfSha256;
type Aead = AesGcm256;
type Kdf = HkdfSha512;

pub struct CASHPKE;

impl CASHybrid for CASHPKE {
    fn generate_key_pair() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut csprng = StdRng::from_entropy();
        let (private_key, public_key) = Kem::gen_keypair(&mut csprng);
        (
            private_key.to_bytes().to_vec(),
            public_key.to_bytes().to_vec(),
            Self::generate_info_str(),
        )
    }

    fn generate_info_str() -> Vec<u8> {
        let uuid = Uuid::new_v4();
        let uuid_bytes: Vec<u8> = uuid.as_bytes().to_vec();
        uuid_bytes
    }

    fn encrypt(
        plaintext: Vec<u8>,
        public_key: Vec<u8>,
        info_str: Vec<u8>,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut csprng = StdRng::from_entropy();
        let public_key = <Kem as KemTrait>::PublicKey::from_bytes(public_key.as_slice())
            .expect("could not deserialize server privkey!");
        let (encapped_key, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
            &OpModeS::Base,
            &public_key,
            &info_str.as_slice(),
            &mut csprng,
        )
        .expect("invalid server pubkey!");
        let mut msg_copy = plaintext;
        let tag = sender_ctx
            .seal_in_place_detached(&mut msg_copy, b"")
            .expect("encryption failed!");
        let ciphertext = msg_copy;
        (
            encapped_key.to_bytes().to_vec(),
            ciphertext,
            tag.to_bytes().to_vec(),
        )
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        private_key: Vec<u8>,
        encapped_key: Vec<u8>,
        tag: Vec<u8>,
        info_str: Vec<u8>,
    ) -> Vec<u8> {
        let server_sk = <Kem as KemTrait>::PrivateKey::from_bytes(&private_key)
            .expect("could not deserialize server privkey!");
        let tag = AeadTag::<Aead>::from_bytes(&tag).expect("could not deserialize AEAD tag!");
        let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&encapped_key)
            .expect("could not deserialize the encapsulated pubkey!");
        let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &server_sk,
            &encapped_key,
            &info_str,
        )
        .expect("failed to set up receiver!");
        let mut ciphertext_copy = ciphertext;
        receiver_ctx
            .open_in_place_detached(&mut ciphertext_copy, b"", &tag)
            .expect("invalid ciphertext!");
        let plaintext = ciphertext_copy;
        plaintext
    }
}
