use rand::rngs::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::EncodePrivateKey,
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use sha3::{Digest, Sha3_256};


use super::cas_digital_signature_rsa::{RSADigitalSignatureResult, RSADigitalSignature};

pub struct SHA256RSADigitalSignature;

impl RSADigitalSignature for SHA256RSADigitalSignature {
    fn digital_signature_rsa(
        rsa_key_size: u32,
        data_to_sign: Vec<u8>,
    ) -> RSADigitalSignatureResult {
        let mut hasher = Sha3_256::new();
        hasher.update(data_to_sign);
        let sha_hasher_result = hasher.finalize();
        let mut rng: OsRng = OsRng;
        let private_key: RsaPrivateKey =
            RsaPrivateKey::new(&mut rng, rsa_key_size as usize).expect("failed to generate a key");
        let public_key = private_key.to_public_key();
        let signed_data = private_key
            .sign(Pkcs1v15Sign::new_unprefixed(), &sha_hasher_result)
            .unwrap();
        let result = RSADigitalSignatureResult {
            private_key: private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
            public_key: public_key
                .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
            signature: signed_data,
        };
        result
    }

    fn verify_rsa(public_key: String, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(data_to_verify);
        let sha_hasher_result = hasher.finalize();
        let public_key = RsaPublicKey::from_pkcs1_pem(&public_key).unwrap();
        let verified = public_key.verify(
            Pkcs1v15Sign::new_unprefixed(),
            &sha_hasher_result,
            &signature,
        );
        if verified.is_err() == false {
            return true;
        } else {
            return false;
        }
    }
}