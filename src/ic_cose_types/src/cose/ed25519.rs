use crate::{format_error, ByteN};

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

pub fn ed25519_verify_any(
    public_keys: &[ByteN<32>],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let keys: Vec<VerifyingKey> = public_keys
        .iter()
        .map(|key| VerifyingKey::from_bytes(key).map_err(format_error))
        .collect::<Result<_, _>>()?;
    let sig = Signature::from_slice(signature).map_err(format_error)?;

    match keys
        .iter()
        .any(|key| key.verify_strict(message, &sig).is_ok())
    {
        true => Ok(()),
        false => Err("ed25519 signature verification failed".to_string()),
    }
}
