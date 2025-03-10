use ic_cdk::api::management_canister::schnorr;
use ic_cose_types::{format_error, types::PublicKeyOutput};
use serde_bytes::ByteBuf;

pub fn derive_schnorr_public_key(
    alg: schnorr::SchnorrAlgorithm,
    public_key: &PublicKeyOutput,
    derivation_path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    match alg {
        schnorr::SchnorrAlgorithm::Bip340secp256k1 => {
            let path = ic_secp256k1::DerivationPath::new(
                derivation_path
                    .into_iter()
                    .map(ic_secp256k1::DerivationIndex)
                    .collect(),
            );

            let chain_code: [u8; 32] = public_key
                .chain_code
                .to_vec()
                .try_into()
                .map_err(format_error)?;
            let pk = ic_secp256k1::PublicKey::deserialize_sec1(&public_key.public_key)
                .map_err(format_error)?;
            let (derived_public_key, derived_chain_code) =
                pk.derive_subkey_with_chain_code(&path, &chain_code);

            Ok(PublicKeyOutput {
                public_key: ByteBuf::from(derived_public_key.serialize_sec1(true)),
                chain_code: ByteBuf::from(derived_chain_code),
            })
        }

        schnorr::SchnorrAlgorithm::Ed25519 => {
            let path = ic_ed25519::DerivationPath::new(
                derivation_path
                    .into_iter()
                    .map(ic_ed25519::DerivationIndex)
                    .collect(),
            );

            let chain_code: [u8; 32] = public_key
                .chain_code
                .to_vec()
                .try_into()
                .map_err(format_error)?;
            let pk = ic_ed25519::PublicKey::deserialize_raw(&public_key.public_key)
                .map_err(format_error)?;
            let (derived_public_key, derived_chain_code) =
                pk.derive_subkey_with_chain_code(&path, &chain_code);

            Ok(PublicKeyOutput {
                public_key: ByteBuf::from(derived_public_key.serialize_raw()),
                chain_code: ByteBuf::from(derived_chain_code),
            })
        }
    }
}

pub async fn sign_with_schnorr(
    key_name: String,
    alg: schnorr::SchnorrAlgorithm,
    derivation_path: Vec<Vec<u8>>,
    message: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let args = schnorr::SignWithSchnorrArgument {
        message,
        derivation_path,
        key_id: schnorr::SchnorrKeyId {
            algorithm: alg,
            name: key_name,
        },
    };

    let (res,): (schnorr::SignWithSchnorrResponse,) = schnorr::sign_with_schnorr(args)
        .await
        .map_err(|err| format!("sign_with_ecdsa failed: {:?}", err))?;

    Ok(res.signature)
}

pub async fn schnorr_public_key(
    key_name: String,
    alg: schnorr::SchnorrAlgorithm,
    derivation_path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    let args = schnorr::SchnorrPublicKeyArgument {
        canister_id: None,
        derivation_path,
        key_id: schnorr::SchnorrKeyId {
            algorithm: alg,
            name: key_name,
        },
    };

    let (res,): (schnorr::SchnorrPublicKeyResponse,) = schnorr::schnorr_public_key(args)
        .await
        .map_err(|err| format!("schnorr_public_key failed {:?}", err))?;
    Ok(PublicKeyOutput {
        public_key: ByteBuf::from(res.public_key),
        chain_code: ByteBuf::from(res.chain_code),
    })
}
