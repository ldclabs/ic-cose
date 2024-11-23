use super::format_error;

use k256::ecdsa::signature::hazmat::PrehashVerifier;
// use k256::schnorr::signature::Verifier;

pub use k256::{ecdsa, schnorr};

pub fn secp256k1_verify(
    public_key: &[u8],
    message_hash: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    if message_hash.len() != 32 {
        return Err("message_hash must be 32 bytes".to_string());
    }
    let key = ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(format_error)?;
    let sig = ecdsa::Signature::try_from(signature).map_err(format_error)?;
    match key.verify_prehash(message_hash, &sig).is_ok() {
        true => Ok(()),
        false => Err("secp256k1 signature verification failed".to_string()),
    }
}

pub fn secp256k1_verify_any(
    public_keys: &[ecdsa::VerifyingKey],
    message_hash: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    if message_hash.len() != 32 {
        return Err("message_hash must be 32 bytes".to_string());
    }

    let sig = ecdsa::Signature::try_from(signature).map_err(format_error)?;
    match public_keys
        .iter()
        .any(|key| key.verify_prehash(message_hash, &sig).is_ok())
    {
        true => Ok(()),
        false => Err("secp256k1 signature verification failed".to_string()),
    }
}

pub fn schnorr_secp256k1_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let key = schnorr::VerifyingKey::from_bytes(if public_key.len() == 33 {
        &public_key[1..]
    } else {
        public_key
    })
    .map_err(format_error)?;
    let sig = schnorr::Signature::try_from(signature).map_err(format_error)?;
    match key.verify_raw(message, &sig).is_ok() {
        true => Ok(()),
        false => Err("schnorr secp256k1 signature verification failed".to_string()),
    }
}

pub fn schnorr_secp256k1_verify_any(
    public_keys: &[schnorr::VerifyingKey],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let sig = schnorr::Signature::try_from(signature).map_err(format_error)?;
    match public_keys
        .iter()
        .any(|key| key.verify_raw(message, &sig).is_ok())
    {
        true => Ok(()),
        false => Err("schnorr secp256k1 signature verification failed".to_string()),
    }
}

#[cfg(test)]
mod test {
    use const_hex::decode;

    use super::*;

    #[test]
    fn secp256k1_verify_works() {
        // generated with:
        // dfx canister call ic_cose_canister ecdsa_public_key '(opt record {
        //     ns = "_";
        //     derivation_path = vec {};
        //   })' --ic
        let pk =
            decode("025ddf616f61959973238149361b788ec6bb8e01d896c80a6b82538cf27f61b934").unwrap();

        // generated with:
        // dfx canister call ic_cose_canister ecdsa_sign '(record {
        //     ns = "_";
        //     derivation_path = vec {};
        //     message = blob "\62\33\97\68\50\d2\fc\6a\b6\53\30\6b\33\2d\de\43\89\a4\e8\7b\79\d5\21\a3\31\68\3c\f9\01\02\c4\78";
        //   })' --ic
        let message =
            decode("6233976850d2fc6ab653306b332dde4389a4e87b79d521a331683cf90102c478").unwrap();
        let signature = decode("f17f8cb96a9e8845a3fd9a33fee76d9c54c1949b16ca23537d4f6f75a07ecdd355dd7ac662b9ae7a2d779ea6cb1ad399240f450024eef46d6e6ab1493fe1eb95").unwrap();
        assert!(secp256k1_verify(&pk, &message, &signature).is_ok());

        let signature = decode("6d8983dbeaf2977d2a41d69e0a6fb46b51fb7c1616a8ddd8bb948e1b08bb10e31eee92ef0f8b44ff62f231e6afd7f443a132414d431b57a6ce6dd23ffac8f878").unwrap();
        assert!(secp256k1_verify(&pk, &message, &signature).is_ok());
    }
}
