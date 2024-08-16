use candid::{CandidType, Principal};
use ic_cose_types::format_error;
use serde::{Deserialize, Serialize};

pub async fn vetkd_public_key(
    key_name: String,
    derivation_path: Vec<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let request = VetKDPublicKeyRequest {
        canister_id: None,
        derivation_path,
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381,
            name: key_name,
        },
    };

    let (res,): (VetKDPublicKeyReply,) = ic_cdk::call(
        vetkd_system_api_canister_id(),
        "vetkd_public_key",
        (request,),
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
        public_key_derivation_path: derivation_path,
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381,
            name: key_name,
        },
        encryption_public_key,
    };

    let (response,): (VetKDEncryptedKeyReply,) = ic_cdk::call(
        vetkd_system_api_canister_id(),
        "vetkd_encrypted_key",
        (request,),
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
    #[serde(rename = "bls12_381")]
    Bls12_381,
}

#[derive(CandidType, Deserialize, Serialize)]
pub struct VetKDKeyId {
    pub curve: VetKDCurve,
    pub name: String,
}

#[derive(CandidType, Deserialize, Serialize)]
pub struct VetKDPublicKeyRequest {
    pub canister_id: Option<Principal>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: VetKDKeyId,
}

#[derive(CandidType, Deserialize, Serialize)]
pub struct VetKDPublicKeyReply {
    pub public_key: Vec<u8>,
}

#[derive(CandidType, Deserialize, Serialize)]
pub struct VetKDEncryptedKeyRequest {
    pub public_key_derivation_path: Vec<Vec<u8>>,
    pub derivation_id: Vec<u8>,
    pub key_id: VetKDKeyId,
    pub encryption_public_key: Vec<u8>,
}

#[derive(CandidType, Deserialize, Serialize)]
pub struct VetKDEncryptedKeyReply {
    pub encrypted_key: Vec<u8>,
}
