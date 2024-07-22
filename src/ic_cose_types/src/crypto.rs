use aes_gcm::{aead::KeyInit, AeadInPlace, Aes256Gcm, Key, Nonce};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::format_error;

pub fn ecdh_x25519(secret: [u8; 32], their_public: [u8; 32]) -> (SharedSecret, PublicKey) {
    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(&secret);
    (
        secret.diffie_hellman(&PublicKey::from(their_public)),
        public,
    )
}

pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plain_data: &[u8],
) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    let mut buf: Vec<u8> = Vec::with_capacity(plain_data.len() + 16);
    buf.extend_from_slice(plain_data);
    cipher
        .encrypt_in_place(nonce, aad, &mut buf)
        .map_err(format_error)?;
    Ok(buf)
}

pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    cipher_data: &[u8],
) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    let mut buf: Vec<u8> = Vec::with_capacity(cipher_data.len() + 16);
    buf.extend_from_slice(cipher_data);
    cipher
        .decrypt_in_place(nonce, aad, &mut buf)
        .map_err(format_error)?;
    Ok(buf)
}
