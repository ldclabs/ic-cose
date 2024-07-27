use super::{format_error, sha256};

use k256::ecdsa::signature::hazmat::PrehashVerifier;
// use k256::schnorr::signature::Verifier;

pub use k256::{ecdsa, schnorr};

pub fn secp256k1_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    let key = ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(format_error)?;
    let sig = ecdsa::Signature::try_from(signature).map_err(format_error)?;
    let digest = sha256(message);
    match key.verify_prehash(&digest, &sig).is_ok() {
        true => Ok(()),
        false => Err("secp256k1 signature verification failed".to_string()),
    }
}

pub fn secp256k1_verify_any(
    public_keys: &[ecdsa::VerifyingKey],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let sig = ecdsa::Signature::try_from(signature).map_err(format_error)?;
    let digest = sha256(message);
    match public_keys
        .iter()
        .any(|key| key.verify_prehash(&digest, &sig).is_ok())
    {
        true => Ok(()),
        false => Err("secp256k1 signature verification failed".to_string()),
    }
}

// wait for k256@0.14.0
// pub fn schnorr_secp256k1_verify_any(
//     public_keys: &[schnorr::VerifyingKey],
//     message: &[u8],
//     signature: &[u8],
// ) -> Result<(), String> {
//     let sig = schnorr::Signature::try_from(signature).map_err(format_error)?;
//     let digest = sha256(message);
//     match public_keys
//         .iter()
//         .any(|key| key.verify_raw(&digest, &sig).is_ok())
//     {
//         true => Ok(()),
//         false => Err("schnorr secp256k1 signature verification failed".to_string()),
//     }
// }
