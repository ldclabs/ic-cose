use super::{format_error, sha256};

pub use k256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};

pub fn secp256k1_verify_any(
    public_keys: &[VerifyingKey],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let sig = Signature::try_from(signature).map_err(format_error)?;
    let digest = sha256(message);
    match public_keys
        .iter()
        .any(|key| key.verify_prehash(&digest, &sig).is_ok())
    {
        true => Ok(()),
        false => Err("secp256k1 signature verification failed".to_string()),
    }
}
