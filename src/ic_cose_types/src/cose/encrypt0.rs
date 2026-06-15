use cose2::{iana, Encrypt0Message as CoseEncrypt0, Encryptor, Error, Label};

use super::{
    aes::{aes256_gcm_decrypt, aes256_gcm_encrypt},
    skip_prefix, ENCRYPT0_TAG,
};

struct Aes256GcmCose<'a> {
    secret: &'a [u8; 32],
}

impl Encryptor for Aes256GcmCose<'_> {
    fn alg(&self) -> Option<Label> {
        Some(Label::Int(iana::AlgorithmA256GCM))
    }

    fn nonce_size(&self) -> usize {
        12
    }

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce: &[u8; 12] = nonce.try_into().map_err(|_| {
            Error::custom(format!(
                "invalid nonce length, expected 12, got {}",
                nonce.len()
            ))
        })?;
        aes256_gcm_encrypt(self.secret, nonce, aad, plaintext).map_err(Error::custom)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce: &[u8; 12] = nonce.try_into().map_err(|_| {
            Error::custom(format!(
                "invalid nonce length, expected 12, got {}",
                nonce.len()
            ))
        })?;
        aes256_gcm_decrypt(self.secret, nonce, aad, ciphertext).map_err(Error::custom)
    }
}

fn cose_error(err: Error) -> String {
    match err {
        Error::Custom(msg) => match msg.strip_prefix("IV size mismatch, ") {
            Some(detail) => format!("invalid nonce length, {detail}"),
            None => msg,
        },
        Error::Verify(msg) | Error::UnexpectedType(msg) | Error::Cbor(msg) => msg,
        err => err.to_string(),
    }
}

/// Attempts to decode a COSE_Encrypt0 structure from raw bytes.
///
/// # Arguments
/// * `payload` - Raw byte array containing the COSE_Encrypt0 structure
///
/// # Returns
/// Result containing the decoded CoseEncrypt0 or error message
pub fn try_decode_encrypt0(payload: &[u8]) -> Result<CoseEncrypt0, String> {
    CoseEncrypt0::from_slice(skip_prefix(&ENCRYPT0_TAG, payload)).map_err(cose_error)
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
    let mut e0 = CoseEncrypt0::new(Some(payload.to_vec()));
    e0.protected.set_alg(iana::AlgorithmA256GCM);
    e0.unprotected.set_iv(nonce.to_vec());
    if let Some(key_id) = key_id {
        e0.unprotected.set_kid(key_id);
    }

    e0.encrypt_and_encode(&Aes256GcmCose { secret }, Some(aad))
        .map_err(cose_error)
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
    let e0 = try_decode_encrypt0(payload)?;
    decrypt(&e0, secret, aad)
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
    if item.is_ciphertext_detached() {
        return Err("missing ciphertext".to_string());
    }
    let mut item = item.clone();
    item.decrypt(&Aes256GcmCose { secret }, Some(aad))
        .map(|payload| payload.to_vec())
        .map_err(cose_error)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cose_encrypt0_roundtrips() {
        let secret = [1u8; 32];
        let nonce = [2u8; 12];
        let aad = b"aad";
        let payload = b"payload";

        let encrypted =
            cose_encrypt0(payload, &secret, aad, &nonce, Some(b"kid".to_vec())).unwrap();
        assert_eq!(cose_decrypt0(&encrypted, &secret, aad).unwrap(), payload);
        assert!(cose_decrypt0(&encrypted, &secret, b"wrong aad").is_err());
    }

    #[test]
    fn cose_decrypt0_rejects_invalid_tag_length() {
        let secret = [1u8; 32];
        let mut item = CoseEncrypt0::new(None);
        item.protected.set_alg(iana::AlgorithmA256GCM);
        item.unprotected.set_iv(vec![2u8; 12]);
        item.set_ciphertext(vec![1, 2, 3], false).unwrap();
        let payload = item.to_vec().unwrap();

        let err = cose_decrypt0(&payload, &secret, &[]).unwrap_err();
        assert_eq!(err, "invalid tag length, expected 16, got 3");
    }

    #[test]
    fn encrypt0_decode_and_decrypt_error_paths_work() {
        let secret = [1u8; 32];
        assert!(try_decode_encrypt0(b"not cbor").is_err());
        assert!(cose_decrypt0(b"not cbor", &secret, &[]).is_err());

        let encrypted = cose_encrypt0(b"payload", &secret, b"aad", &[2u8; 12], None).unwrap();
        let decoded = try_decode_encrypt0(&encrypted).unwrap();
        assert_eq!(decrypt(&decoded, &secret, b"aad").unwrap(), b"payload");

        let mut invalid_nonce = CoseEncrypt0::new(None);
        invalid_nonce.protected.set_alg(iana::AlgorithmA256GCM);
        invalid_nonce.unprotected.set_iv(vec![1, 2, 3]);
        invalid_nonce.set_ciphertext(vec![1; 16], false).unwrap();
        assert_eq!(
            decrypt(&invalid_nonce, &secret, &[]).unwrap_err(),
            "invalid nonce length, expected 12, got 3"
        );
        assert_eq!(
            cose_decrypt0(&invalid_nonce.to_vec().unwrap(), &secret, &[]).unwrap_err(),
            "invalid nonce length, expected 12, got 3"
        );

        let mut missing_ciphertext = CoseEncrypt0::new(None);
        missing_ciphertext.protected.set_alg(iana::AlgorithmA256GCM);
        missing_ciphertext.unprotected.set_iv(vec![1u8; 12]);
        missing_ciphertext.set_ciphertext(Vec::new(), true).unwrap();
        assert_eq!(
            decrypt(&missing_ciphertext, &secret, &[]).unwrap_err(),
            "missing ciphertext"
        );
        assert_eq!(
            cose_decrypt0(&missing_ciphertext.to_vec().unwrap(), &secret, &[]).unwrap_err(),
            "missing ciphertext"
        );
    }
}
