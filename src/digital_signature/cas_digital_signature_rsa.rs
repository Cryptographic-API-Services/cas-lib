pub struct RSADigitalSignatureResult {
    pub public_key: String,
    pub private_key: String,
    pub signature: Vec<u8>,
}
pub struct SHAED25519DalekDigitalSignatureResult {
    pub public_key: [u8; 32],
    pub signature: [u8; 64]
}

pub trait RSADigitalSignature {
    fn digital_signature_rsa(rsa_key_size: u32, data_to_sign: Vec<u8>) -> RSADigitalSignatureResult;
    fn digital_signature_rsa_threadpool(rsa_key_size: u32, data_to_sign: Vec<u8>) -> RSADigitalSignatureResult;
    fn verify_rsa(public_key: String, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool;
    fn verify_rsa_threadpool(public_key: String, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool;
}

pub trait ED25519DigitalSignature {
    fn digital_signature_ed25519(data_to_sign: &[u8]) -> SHAED25519DalekDigitalSignatureResult;
    fn digital_signature_ed25519_verify(public_key: [u8; 32], data_to_verify: &[u8], signature: [u8; 64]) -> bool;
}