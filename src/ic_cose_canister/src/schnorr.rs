use candid::{CandidType, Principal};
use ic_cose_types::{
    format_error,
    types::{PublicKeyOutput, SchnorrAlgorithm},
};
use ic_crypto_extended_bip32::{DerivationIndex, DerivationPath, ExtendedBip32DerivationOutput};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

const MAX_SIGN_WITH_SCHNORR_FEE: u128 = 26_153_846_153;

pub fn derive_schnorr_public_key(
    alg: SchnorrAlgorithm,
    public_key: &PublicKeyOutput,
    derivation_path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    match alg {
        SchnorrAlgorithm::Bip340Secp256k1 => {
            let ExtendedBip32DerivationOutput {
                derived_public_key,
                derived_chain_code,
            } = DerivationPath::new(derivation_path.into_iter().map(DerivationIndex).collect())
                .public_key_derivation(&public_key.public_key, &public_key.chain_code)
                .map_err(format_error)?;
            Ok(PublicKeyOutput {
                public_key: ByteBuf::from(derived_public_key),
                chain_code: ByteBuf::from(derived_chain_code),
            })
        }

        SchnorrAlgorithm::Ed25519 => {
            let path = ic_crypto_ed25519::DerivationPath::new(
                derivation_path
                    .into_iter()
                    .map(ic_crypto_ed25519::DerivationIndex)
                    .collect(),
            );

            let chain_code: [u8; 32] = public_key
                .chain_code
                .to_vec()
                .try_into()
                .map_err(format_error)?;
            let pk = ic_crypto_ed25519::PublicKey::deserialize_raw(&public_key.public_key)
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

#[derive(CandidType, Deserialize, Serialize, Debug)]
pub struct SignWithSchnorrArgs {
    pub message: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: SchnorrKeyId,
}

#[derive(CandidType, Deserialize, Serialize, Debug)]
pub struct SignWithSchnorrResult {
    pub signature: Vec<u8>,
}

pub async fn sign_with_schnorr(
    key_name: String,
    alg: SchnorrAlgorithm,
    derivation_path: Vec<Vec<u8>>,
    message: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let args = SignWithSchnorrArgs {
        message,
        derivation_path,
        key_id: SchnorrKeyId {
            algorithm: alg,
            name: key_name,
        },
    };

    let (res,): (SignWithSchnorrResult,) = ic_cdk::api::call::call_with_payment128(
        Principal::management_canister(),
        "sign_with_schnorr",
        (args,),
        MAX_SIGN_WITH_SCHNORR_FEE,
    )
    .await
    .map_err(|err| format!("sign_with_ecdsa failed {:?}", err))?;

    Ok(res.signature)
}

#[derive(CandidType, Deserialize, Serialize, Debug)]
pub struct SchnorrPublicKeyArgs {
    pub canister_id: Option<Principal>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: SchnorrKeyId,
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SchnorrKeyId {
    algorithm: SchnorrAlgorithm,
    name: String,
}

pub async fn schnorr_public_key(
    key_name: String,
    alg: SchnorrAlgorithm,
    derivation_path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    let args = SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path,
        key_id: SchnorrKeyId {
            algorithm: alg,
            name: key_name,
        },
    };

    let (res,): (PublicKeyOutput,) = ic_cdk::call(
        Principal::management_canister(),
        "schnorr_public_key",
        (args,),
    )
    .await
    .map_err(|err| format!("schnorr_public_key failed {:?}", err))?;
    Ok(res)
}
