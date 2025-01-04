#[cfg(test)]
mod digital_signatures {
    use cas_lib::digital_signature::{cas_digital_signature_rsa::{ED25519DigitalSignature, SHAED25519DalekDigitalSignatureResult}, sha_256_ed25519::SHA256ED25519DigitalSignature, sha_256_rsa::SHA256RSADigitalSignature, sha_512_ed25519::SHA512ED25519DigitalSignature};
 
    #[test]
    pub fn ed25519_sha_512_digital_signature_verify() {
        let data_to_sign = b"This is a test of a digital signature";
        let result: SHAED25519DalekDigitalSignatureResult = <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(data_to_sign);
        let verification = <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519_verify(result.public_key, data_to_sign, result.signature);
        assert_eq!(true, verification);
    }

    #[test]
    pub fn ed25519_sha_256_digital_signature_verify() {
        let data_to_sign = b"This is a test of a digital signature";
        let result: SHAED25519DalekDigitalSignatureResult = <SHA256ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(data_to_sign);
        let verification = <SHA256ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519_verify(result.public_key, data_to_sign, result.signature);
        assert_eq!(true, verification);
    }
}