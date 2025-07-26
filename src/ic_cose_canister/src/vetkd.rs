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
