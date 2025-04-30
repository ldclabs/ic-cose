use candid::{CandidType, Principal};
use ic_cose_types::format_error;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::call;

pub async fn vetkd_public_key(
    key_name: String,
    derivation_path: Vec<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let request = VetKDPublicKeyRequest {
        canister_id: None,
        derivation_path,
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381_G2,
            name: key_name,
        },
    };

    let res: VetKDPublicKeyReply = call(
        vetkd_system_api_canister_id(),
        "vetkd_public_key",
        (request,),
        0,
    )
    .await
    .map_err(format_error)?;

    Ok(res.public_key)
}

pub async fn vetkd_encrypted_key(
    key_name: String,
    derivation_id: Vec<u8>,
    derivation_path: Vec<Vec<u8>>,
    encryption_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let request = VetKDEncryptedKeyRequest {
        derivation_id,
        derivation_path,
        encryption_public_key,
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381_G2,
            name: key_name,
        },
    };

    let response: VetKDEncryptedKeyReply = call(
        vetkd_system_api_canister_id(),
        "vetkd_derive_encrypted_key",
        (request,),
        0,
    )
    .await
    .map_err(format_error)?;

    Ok(response.encrypted_key)
}

// https://github.com/dfinity/examples/blob/master/rust/vetkd/README.md
const VETKD_SYSTEM_API_CANISTER_ID: &str = "s55qq-oqaaa-aaaaa-aaakq-cai";

fn vetkd_system_api_canister_id() -> Principal {
    Principal::from_text(VETKD_SYSTEM_API_CANISTER_ID).expect("failed to create canister ID")
}

#[derive(CandidType, Deserialize, Serialize)]
pub enum VetKDCurve {
    #[serde(rename = "bls12_381_g2")]
    #[allow(non_camel_case_types)]
    Bls12_381_G2,
}

#[derive(CandidType, Deserialize, Serialize)]
pub struct VetKDKeyId {
    pub curve: VetKDCurve,
    pub name: String,
}

#[serde_as]
#[derive(CandidType, Deserialize, Serialize)]
pub struct VetKDPublicKeyRequest {
    pub canister_id: Option<Principal>,
    #[serde_as(as = "Vec<serde_with::Bytes>")]
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: VetKDKeyId,
}

#[derive(CandidType, Deserialize, Serialize)]
pub struct VetKDPublicKeyReply {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

#[serde_as]
#[derive(CandidType, Deserialize, Serialize)]
pub struct VetKDEncryptedKeyRequest {
    #[serde_as(as = "Vec<serde_with::Bytes>")]
    pub derivation_path: Vec<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub derivation_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub encryption_public_key: Vec<u8>,
    pub key_id: VetKDKeyId,
}

#[derive(CandidType, Deserialize, Serialize)]
pub struct VetKDEncryptedKeyReply {
    #[serde(with = "serde_bytes")]
    pub encrypted_key: Vec<u8>,
}
