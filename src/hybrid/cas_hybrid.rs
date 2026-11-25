use crate::error::CasResult;

pub trait CASHybrid {
    fn generate_key_pair() -> (Vec<u8>, Vec<u8>, Vec<u8>);
    fn generate_info_str() -> Vec<u8>;
    /// Encrypts `plaintext` to `public_key`, returning `(encapped_key, ciphertext, tag)`.
    ///
    /// `aad` is additional authenticated data: it is not encrypted or returned,
    /// but the recipient must pass the same bytes to [`decrypt`](Self::decrypt).
    /// Pass an empty vector for no AAD.
    fn encrypt(plaintext: Vec<u8>, public_key: Vec<u8>, info_str: Vec<u8>, aad: Vec<u8>) -> CasResult<(Vec<u8>, Vec<u8>, Vec<u8>)>;
    /// Decrypts a message from [`encrypt`](Self::encrypt). Fails unless `info_str`
    /// and `aad` match the values the sender used.
    fn decrypt(ciphertext: Vec<u8>, private_key: Vec<u8>, encapped_key: Vec<u8>, tag: Vec<u8>, info_str: Vec<u8>, aad: Vec<u8>) -> CasResult<Vec<u8>>;
}
