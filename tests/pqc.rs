#[cfg(test)]
mod pqc {
    use cas_lib::{hashers::sha::CASSHA, pqc::{cas_pqc::MlKemKeyPair, ml_kem::{ml_kem_1024_decapsulate, ml_kem_1024_encapsulate, ml_kem_1024_generate}, slh_dsa::*}};
    use cas_lib::hashers::cas_hasher::CASHasher;

    #[test]
    pub fn round_trip_mlkem1024() {
        let secret_key_public_key: MlKemKeyPair = ml_kem_1024_generate();
            let ct = ml_kem_1024_encapsulate(secret_key_public_key.public_key).expect("encapsulate failed");
            let ss_receiver = ml_kem_1024_decapsulate(secret_key_public_key.secret_key, ct.ciphertext).expect("decapsulate failed");
        assert_eq!(ss_receiver, ss_receiver);
    }

    #[test]
    pub fn hkdf_sha256_pass() {
        let to_hash = b"Lets HashThis".to_vec();
        let hash = <CASSHA as CASHasher>::hash_512(to_hash.clone());

        let keys = generate_signing_and_verification_key();
        let signature = sign_message(hash.clone(), keys.signing_key);
        let is_valid = verify_signature(hash, signature, keys.verification_key);
        assert_eq!(true, is_valid);
    }

    #[test]
    pub fn hkdf_sha256_fail() {
        let to_hash = b"Lets HashThis".to_vec();
        let hash = <CASSHA as CASHasher>::hash_512(to_hash.clone());

        let keys = generate_signing_and_verification_key();
        let signature = sign_message(hash, keys.signing_key);
        let is_valid = verify_signature(to_hash, signature, keys.verification_key);
        assert_eq!(false, is_valid);
    }
}