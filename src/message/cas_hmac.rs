pub trait CASHMAC {
    fn sign(key: Vec<u8>, message: Vec<u8>) -> Vec<u8>;
    fn sign_threadpool(key: Vec<u8>, message: Vec<u8>) -> Vec<u8>;
    fn verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool;
    fn verify_threadpool(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool;
}