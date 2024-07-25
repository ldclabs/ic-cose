use super::format_error;

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

pub fn ed25519_verify_any(
    public_keys: &[VerifyingKey],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let sig = Signature::from_slice(signature).map_err(format_error)?;

    match public_keys
        .iter()
        .any(|key| key.verify_strict(message, &sig).is_ok())
    {
        true => Ok(()),
        false => Err("ed25519 signature verification failed".to_string()),
    }
}
