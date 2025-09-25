#[derive(Debug, Clone)]
pub struct MlKemKeyPair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MlKemEncapResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MlKemSharedSecret {
    pub shared_secret: Vec<u8>,
}