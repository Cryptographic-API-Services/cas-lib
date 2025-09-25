#[cfg(test)]
mod pqc {
    use cas_lib::pqc::{cas_pqc::MlKemKeyPair, ml_kem::{ml_kem_1024_decapsulate, ml_kem_1024_encapsulate, ml_kem_1024_generate}};

    #[test]
    pub fn round_trip_mlkem1024() {
        let secret_key_public_key: MlKemKeyPair = ml_kem_1024_generate();
        let ct = ml_kem_1024_encapsulate(secret_key_public_key.public_key).expect("encapsulate failed");
        let ss_receiver = ml_kem_1024_decapsulate(secret_key_public_key.secret_key, ct.ciphertext).expect("decapsulate failed");
        assert_eq!(ss_receiver, ss_receiver);
    }
}