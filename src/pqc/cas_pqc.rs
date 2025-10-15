#[repr(C)]
#[derive(Debug, Clone)]
pub struct MlKemKeyPair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MlKemEncapResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MlKemSharedSecret {
    pub shared_secret: Vec<u8>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SlhDsaKeyPair {
    pub signing_key: Vec<u8>,
    pub verification_key: Vec<u8>,
}