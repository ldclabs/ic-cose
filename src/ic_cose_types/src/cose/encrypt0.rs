use coset::{
    iana, CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, HeaderBuilder,
    TaggedCborSerializable,
};

use super::{
    aes::{aes256_gcm_decrypt, aes256_gcm_encrypt},
    format_error, skip_prefix, ENCRYPT0_TAG,
};

/// Attempts to decode a COSE_Encrypt0 structure from raw bytes.
///
/// # Arguments
/// * `payload` - Raw byte array containing the COSE_Encrypt0 structure
///
/// # Returns
/// Result containing the decoded CoseEncrypt0 or error message
pub fn try_decode_encrypt0(payload: &[u8]) -> Result<CoseEncrypt0, String> {
    CoseEncrypt0::from_slice(skip_prefix(&ENCRYPT0_TAG, payload)).map_err(format_error)
}

/// Encrypts payload using COSE_Encrypt0 structure with AES-256-GCM.
///
/// # Arguments
/// * `payload` - Plaintext data to encrypt
/// * `secret` - 32-byte AES-256-GCM key
/// * `aad` - Additional authenticated data
/// * `nonce` - 12-byte initialization vector
/// * `key_id` - Optional key identifier
///
/// # Returns
/// Result containing the serialized COSE_Encrypt0 structure or error message
pub fn cose_encrypt0(
    payload: &[u8], // plain payload
    secret: &[u8; 32],
    aad: &[u8],
    nonce: &[u8; 12],
    key_id: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::A256GCM)
        .build();
    let mut unprotected = HeaderBuilder::new().iv(nonce.to_vec());
    if let Some(key_id) = key_id {
        unprotected = unprotected.key_id(key_id);
    }

    let e0 = CoseEncrypt0Builder::new()
        .protected(protected)
        .unprotected(unprotected.build())
        .create_ciphertext(payload, aad, |plain_data, enc| {
            aes256_gcm_encrypt(secret, nonce, enc, plain_data).unwrap()
        })
        .build();
    e0.to_tagged_vec().map_err(format_error)
}

/// Decrypts a COSE_Encrypt0 structure using AES-256-GCM.
///
/// # Arguments
/// * `payload` - Serialized COSE_Encrypt0 structure
/// * `secret` - 32-byte AES-256-GCM key
/// * `aad` - Additional authenticated data
///
/// # Returns
/// Result containing the decrypted plaintext or error message
pub fn cose_decrypt0(
    payload: &[u8], // COSE_Encrypt0 item
    secret: &[u8; 32],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let e0 = CoseEncrypt0::from_slice(skip_prefix(&ENCRYPT0_TAG, payload)).map_err(format_error)?;
    let nonce = e0.unprotected.iv.first_chunk::<12>().ok_or_else(|| {
        format!(
            "invalid nonce length, expected 12, got {}",
            e0.unprotected.iv.len()
        )
    })?;
    e0.decrypt(aad, |cipher_data, enc| {
        aes256_gcm_decrypt(secret, nonce, enc, cipher_data)
    })
}

/// Decrypts a COSE_Encrypt0 structure using AES-256-GCM.
///
/// # Arguments
/// * `item` - COSE_Encrypt0 structure to decrypt
/// * `secret` - 32-byte AES-256-GCM key
/// * `aad` - Additional authenticated data
///
/// # Returns
/// Result containing the decrypted plaintext or error message
pub fn decrypt(item: &CoseEncrypt0, secret: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, String> {
    let nonce = item.unprotected.iv.first_chunk::<12>().ok_or_else(|| {
        format!(
            "invalid nonce length, expected 12, got {}",
            item.unprotected.iv.len()
        )
    })?;
    item.decrypt(aad, |cipher_data, enc| {
        aes256_gcm_decrypt(secret, nonce, enc, cipher_data)
    })
}
