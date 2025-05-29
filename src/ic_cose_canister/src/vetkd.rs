use ic_cdk::management_canister as mgt;
use ic_cose_types::format_error;
use sha3::Digest;

pub async fn vetkd_public_key(
    key_name: String,
    derivation_path: &[&[u8]],
) -> Result<Vec<u8>, String> {
    let args = mgt::VetKDPublicKeyArgs {
        canister_id: None,
        context: derivation_path_to_context(derivation_path),
        key_id: mgt::VetKDKeyId {
            curve: mgt::VetKDCurve::Bls12_381_G2,
            name: key_name,
        },
    };
    let res = mgt::vetkd_public_key(&args).await.map_err(format_error)?;
    Ok(res.public_key)
}

pub async fn vetkd_encrypted_key(
    key_name: String,
    derivation_path: &[&[u8]],
    input: Vec<u8>,
    transport_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let args = mgt::VetKDDeriveKeyArgs {
        input,
        context: derivation_path_to_context(derivation_path),
        transport_public_key,
        key_id: mgt::VetKDKeyId {
            curve: mgt::VetKDCurve::Bls12_381_G2,
            name: key_name,
        },
    };

    let res = mgt::vetkd_derive_key(&args).await.map_err(format_error)?;

    Ok(res.encrypted_key)
}

fn derivation_path_to_context(derivation_path: &[&[u8]]) -> Vec<u8> {
    let mut hasher = sha3::Sha3_256::new();
    for path in derivation_path {
        hasher.update(path);
    }
    let rt: [u8; 32] = hasher.finalize().into();
    rt.into()
}

// // https://github.com/dfinity/examples/blob/master/rust/vetkd/README.md
// const VETKD_SYSTEM_API_CANISTER_ID: &str = "s55qq-oqaaa-aaaaa-aaakq-cai";

// fn vetkd_system_api_canister_id() -> Principal {
//     Principal::from_text(VETKD_SYSTEM_API_CANISTER_ID).expect("failed to create canister ID")
// }

// #[derive(CandidType, Deserialize, Serialize)]
// pub enum VetKDCurve {
//     #[serde(rename = "bls12_381_g2")]
//     #[allow(non_camel_case_types)]
//     Bls12_381_G2,
// }

// #[derive(CandidType, Deserialize, Serialize)]
// pub struct VetKDKeyId {
//     pub curve: VetKDCurve,
//     pub name: String,
// }

// #[serde_as]
// #[derive(CandidType, Deserialize, Serialize)]
// pub struct VetKDPublicKeyRequest {
//     pub canister_id: Option<Principal>,
//     #[serde_as(as = "Vec<serde_with::Bytes>")]
//     pub derivation_path: Vec<Vec<u8>>,
//     pub key_id: VetKDKeyId,
// }

// #[derive(CandidType, Deserialize, Serialize)]
// pub struct VetKDPublicKeyReply {
//     #[serde(with = "serde_bytes")]
//     pub public_key: Vec<u8>,
// }

// #[serde_as]
// #[derive(CandidType, Deserialize, Serialize)]
// pub struct VetKDEncryptedKeyRequest {
//     #[serde_as(as = "Vec<serde_with::Bytes>")]
//     pub derivation_path: Vec<Vec<u8>>,
//     #[serde(with = "serde_bytes")]
//     pub derivation_id: Vec<u8>,
//     #[serde(with = "serde_bytes")]
//     pub encryption_public_key: Vec<u8>,
//     pub key_id: VetKDKeyId,
// }

// #[derive(CandidType, Deserialize, Serialize)]
// pub struct VetKDEncryptedKeyReply {
//     #[serde(with = "serde_bytes")]
//     pub encrypted_key: Vec<u8>,
// }
