pub trait CASHasher {
    fn hash_512(data_to_hash: Vec<u8>) -> Vec<u8>;
    fn verify_512(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool;
    fn hash_256(data_to_hash: Vec<u8>) -> Vec<u8>;
    fn verify_256(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool;
}

/// Compares a caller-supplied digest with a freshly computed one in constant time.
///
/// A digest of the wrong length is rejected immediately: the expected length is
/// public (it is fixed by the algorithm), so returning early on it leaks nothing.
/// Equal-length digests are compared with `subtle::ConstantTimeEq`, which takes the
/// same time wherever the first differing byte is.
pub(crate) fn digests_match(hash_to_verify: &[u8], computed: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    if hash_to_verify.len() != computed.len() {
        return false;
    }
    hash_to_verify.ct_eq(computed).into()
}
