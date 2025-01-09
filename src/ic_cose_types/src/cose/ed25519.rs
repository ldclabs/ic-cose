use super::format_error;

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

/// Verifies an Ed25519 signature using the provided public key.
///
/// # Arguments
/// * `public_key` - 32-byte Ed25519 public key
/// * `message` - The message that was signed
/// * `signature` - 64-byte Ed25519 signature to verify
///
/// # Returns
/// * `Ok(())` if the signature is valid
/// * `Err(String)` with error message if verification fails
pub fn ed25519_verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(public_key).map_err(format_error)?;
    let sig = Signature::from_slice(signature).map_err(format_error)?;

    match key.verify_strict(message, &sig).is_ok() {
        true => Ok(()),
        false => Err("ed25519 signature verification failed".to_string()),
    }
}

/// Verifies an Ed25519 signature against multiple public keys.
///
/// # Arguments
/// * `public_keys` - List of Ed25519 public keys to try
/// * `message` - The message that was signed
/// * `signature` - 64-byte Ed25519 signature to verify
///
/// # Returns
/// * `Ok(())` if any key verifies the signature
/// * `Err(String)` if no key verifies the signature
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

#[cfg(test)]
mod test {
    use const_hex::decode;

    use super::*;

    #[test]
    fn ed25519_verify_works() {
        // generated with:
        // dfx canister call ic_cose_canister schnorr_public_key '(variant { ed25519 }, opt record {
        //     ns = "_";
        //     derivation_path = vec {};
        //   })' --ic
        let pk =
            decode("dded78d6f1087ebe259f8dadd83f5bce72cbd5d95aa93fe237bb6f53b05fe809").unwrap();
        let pk: [u8; 32] = pk.try_into().unwrap();

        // generated with:
        // dfx canister call ic_cose_canister schnorr_sign '(variant { ed25519 }, record {
        //     ns = "_";
        //     derivation_path = vec {};
        //     message = blob "\62\33\97\68\50\d2\fc\6a\b6\53\30\6b\33\2d\de\43\89\a4\e8\7b\79\d5\21\a3\31\68\3c\f9\01\02\c4\78";
        //   })' --ic
        let message =
            decode("6233976850d2fc6ab653306b332dde4389a4e87b79d521a331683cf90102c478").unwrap();
        let signature = decode("aba0f24e4c025e136adc6928b2ea736d1621c3b307f9283756240180a0b9dd0a504cc70b79f3c44c5c894c3105281e73035fe551f3c9ef964beb8548b3e63b03").unwrap();
        assert!(ed25519_verify(&pk, &message, &signature).is_ok());

        let signature = decode("96ea613d0a26f3812bdee85b262c898393b063b56379d6e9d75e0ab28be820cd4f42fdfb60f8a6fc081393b9407be9387d7f68fe6dec4699dc69b7ace6990303").unwrap();
        assert!(ed25519_verify(&pk, &message, &signature).is_ok());
    }
}
