use aes_gcm::{aead::KeyInit, AeadInPlace, Aes256Gcm, Key, Nonce, Tag};

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
    let tag = aes256_gcm_encrypt_in(&cipher, nonce, aad, &mut buf)?;
    buf.extend_from_slice(&tag);
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
    let tag_pos = cipher_data.len().saturating_sub(16);
    let (msg, tag) = cipher_data.split_at(tag_pos);
    let mut buf: Vec<u8> = Vec::with_capacity(msg.len());
    buf.extend_from_slice(msg);
    aes256_gcm_decrypt_in(&cipher, nonce, aad, &mut buf, tag)?;
    Ok(buf)
}

fn aes256_gcm_encrypt_in(
    cipher: &Aes256Gcm,
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> Result<[u8; 16], String> {
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, data)
        .map_err(format_error)?;
    Ok(tag.into())
}

fn aes256_gcm_decrypt_in(
    cipher: &Aes256Gcm,
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8],
) -> Result<(), String> {
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, data, Tag::from_slice(tag))
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
