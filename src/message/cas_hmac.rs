use crate::error::CasResult;

pub trait CASHMAC {
    fn sign(key: Vec<u8>, message: Vec<u8>) -> CasResult<Vec<u8>>;
    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> CasResult<bool>;
}
