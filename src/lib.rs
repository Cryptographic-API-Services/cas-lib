pub mod password_hashers {
    pub mod argon2;
    pub mod bcrypt;
    pub mod cas_password_hasher;
    pub mod scrypt;
    pub mod pbkdf2;
}

pub mod hashers {
    pub mod blake2;
    pub mod cas_hasher;
    pub mod sha;
}

pub mod key_exchange {
    pub mod cas_key_exchange;
    pub mod x25519;
}

pub mod symmetric {
    pub mod aes;
    pub mod cas_symmetric_encryption;
}

pub mod asymmetric {
    pub mod cas_rsa;
    pub mod types;
}

pub mod digital_signature {
    pub mod cas_digital_signature_rsa;
    pub mod sha_512_rsa;
    pub mod sha_256_rsa;
    pub mod sha_512_ed25519;
    pub mod sha_256_ed25519;
}

pub mod sponges {
    pub mod cas_ascon_aead;
    pub mod ascon_aead;
}

pub mod message {
    pub mod hmac;
    pub mod cas_hmac;
}

pub mod signatures {
    pub mod ed25519;
    pub mod cas_ed25519;
}

pub mod compression {
    pub mod zstd;
}

pub mod hybrid {
    pub mod hpke;
    pub mod cas_hybrid;
}