pub struct RSADigitalSignatureResult {
    pub public_key: String,
    pub private_key: String,
    pub signature: Vec<u8>,
}
pub struct SHAED25519DalekDigitalSignatureResult {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>
}

pub trait RSADigitalSignature {
    fn digital_signature_rsa(rsa_key_size: u32, data_to_sign: Vec<u8>) -> RSADigitalSignatureResult; 
    fn verify_rsa(public_key: String, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool;
}