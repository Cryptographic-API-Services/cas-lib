use rand::rngs::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    RsaPublicKey,
};
use rsa::{Pkcs1v15Sign, RsaPrivateKey};

use super::types::{CASRSAEncryption, RSAKeyPairResult};

pub struct CASRSA;

impl CASRSAEncryption for CASRSA {
    /// Generates an RSA key pair of the specified size.
    /// The key size must be at of a supported kind like 1024, 2048, 4096 bits.
    fn generate_rsa_keys(key_size: usize) -> RSAKeyPairResult {
        // TODO: do a check for key_size, if it is too small, return an error
        let mut rng: OsRng = OsRng;
        let private_key: RsaPrivateKey =
            RsaPrivateKey::new(&mut rng, key_size).expect("failed to generate a key");
        let public_key: RsaPublicKey = private_key.to_public_key();
        let result = RSAKeyPairResult {
            public_key: public_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .unwrap()
                .to_string(),
            private_key: private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
        };
        result
    }

    /// Sign the given hash with the provided private key of the RSA key pair.
    /// The parameter `hash` doesn't necessarily have to be a hash, it can be any data that you want to sign.
    fn sign(private_key: String, hash: Vec<u8>) -> Vec<u8> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key).unwrap();
        let signed_data = private_key
            .sign(Pkcs1v15Sign::new_unprefixed(), &hash)
            .unwrap();
        signed_data
    }


    /// Verify the signature of the given hash with the provided public key of the RSA key pair.
    /// The parameter `hash` doesn't necessarily have to be a hash, it can be any data that you want to verify.
    /// Returns true if the signature is valid, false otherwise.
    fn verify(public_key: String, hash: Vec<u8>, signature: Vec<u8>) -> bool {
        let public_key = RsaPublicKey::from_pkcs1_pem(&public_key).unwrap();
        let verified = public_key.verify(Pkcs1v15Sign::new_unprefixed(), &hash, &signature);
        if verified.is_err() == false {
            return true;
        } else {
            return false;
        }
    }
}