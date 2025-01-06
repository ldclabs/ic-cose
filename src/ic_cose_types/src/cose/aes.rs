use aes_gcm::{aead::KeyInit, AeadInPlace, Aes256Gcm, Key, Nonce};

use super::format_error;

pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plain_data: &[u8],
) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let mut buf: Vec<u8> = Vec::with_capacity(plain_data.len() + 16);
    buf.extend_from_slice(plain_data);
    aes256_gcm_encrypt_in_place(&cipher, nonce, aad, &mut buf)?;
    Ok(buf)
}

pub fn aes256_gcm_encrypt_in_place(
    cipher: &Aes256Gcm,
    nonce: &[u8; 12],
    aad: &[u8],
    plain_data: &mut Vec<u8>,
) -> Result<(), String> {
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt_in_place(nonce, aad, plain_data)
        .map_err(format_error)
}

pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    cipher_data: &[u8],
) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let mut buf: Vec<u8> = Vec::with_capacity(cipher_data.len());
    buf.extend_from_slice(cipher_data);
    aes256_gcm_decrypt_in_place(&cipher, nonce, aad, &mut buf)?;
    Ok(buf)
}

pub fn aes256_gcm_decrypt_in_place(
    cipher: &Aes256Gcm,
    nonce: &[u8; 12],
    aad: &[u8],
    cipher_data: &mut Vec<u8>,
) -> Result<(), String> {
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt_in_place(nonce, aad, cipher_data)
        .map_err(format_error)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn aes256_gcm_works() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plain_data = [3u8; 8];
        let cipher_data = aes256_gcm_encrypt(&key, &nonce, &[], &plain_data).unwrap();
        assert_eq!(cipher_data.len(), plain_data.len() + 16);

        let data = aes256_gcm_decrypt(&key, &nonce, &[], &cipher_data).unwrap();
        assert_eq!(&data, &plain_data);
    }
}
