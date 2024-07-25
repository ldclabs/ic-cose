use serde_bytes::ByteBuf;

use super::sha256;
use crate::format_error;

pub use k256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};

pub fn secp256k1_verify_any(
    public_keys: &[ByteBuf],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let keys: Vec<VerifyingKey> = public_keys
        .iter()
        .map(|key| VerifyingKey::from_sec1_bytes(key).map_err(format_error))
        .collect::<Result<_, _>>()?;
    let sig = Signature::try_from(signature).map_err(format_error)?;
    let digest = sha256(message);
    match keys
        .iter()
        .any(|key| key.verify_prehash(&digest, &sig).is_ok())
    {
        true => Ok(()),
        false => Err("secp256k1 signature verification failed".to_string()),
    }
}
