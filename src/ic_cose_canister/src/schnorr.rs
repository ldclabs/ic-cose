use ic_cdk::management_canister as mgt;
use ic_cose_types::{format_error, types::PublicKeyOutput};
use serde_bytes::ByteBuf;

pub fn derive_schnorr_public_key(
    alg: mgt::SchnorrAlgorithm,
    public_key: &PublicKeyOutput,
    derivation_path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    match alg {
        mgt::SchnorrAlgorithm::Bip340secp256k1 => {
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

        mgt::SchnorrAlgorithm::Ed25519 => {
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
    alg: mgt::SchnorrAlgorithm,
    derivation_path: Vec<Vec<u8>>,
    message: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let args = mgt::SignWithSchnorrArgs {
        message,
        derivation_path,
        key_id: mgt::SchnorrKeyId {
            algorithm: alg,
            name: key_name,
        },
        aux: None,
    };

    let rt = mgt::sign_with_schnorr(&args)
        .await
        .map_err(|err| format!("sign_with_ecdsa failed: {:?}", err))?;

    Ok(rt.signature)
}

pub async fn schnorr_public_key(
    key_name: String,
    alg: mgt::SchnorrAlgorithm,
    derivation_path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    let args = mgt::SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path,
        key_id: mgt::SchnorrKeyId {
            algorithm: alg,
            name: key_name,
        },
    };

    let rt = mgt::schnorr_public_key(&args)
        .await
        .map_err(|err| format!("schnorr_public_key failed {:?}", err))?;
    Ok(PublicKeyOutput {
        public_key: ByteBuf::from(rt.public_key),
        chain_code: ByteBuf::from(rt.chain_code),
    })
}
