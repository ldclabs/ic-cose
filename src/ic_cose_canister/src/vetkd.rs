use ic_cdk_management_canister as mgt;
use ic_cose_types::format_error;
use sha3::Digest;

pub fn vetkd_derive_key_cost(
    key_name: &str,
    context_version: u8,
    derivation_path: &[&[u8]],
    input: &[u8],
    transport_public_key: &[u8],
) -> Result<u128, String> {
    let args = mgt::VetKDDeriveKeyArgs {
        input: input.to_vec(),
        context: derivation_path_to_context(context_version, derivation_path)?,
        transport_public_key: transport_public_key.to_vec(),
        key_id: mgt::VetKDKeyId {
            curve: mgt::VetKDCurve::Bls12_381_G2,
            name: key_name.to_string(),
        },
    };
    let payload_bytes = candid::encode_one(&args).map_err(format_error)?.len() as u64;
    mgt::cost_vetkd_derive_key(&args)
        .map_err(format_error)?
        .checked_add(ic_cdk::api::cost_call(
            "vetkd_derive_key".len() as u64,
            payload_bytes,
        ))
        .ok_or_else(|| "vetKD call cost overflowed".to_string())
}

pub fn vetkd_public_key_cost(
    key_name: &str,
    context_version: u8,
    derivation_path: &[&[u8]],
) -> Result<u128, String> {
    let args = mgt::VetKDPublicKeyArgs {
        canister_id: None,
        context: derivation_path_to_context(context_version, derivation_path)?,
        key_id: mgt::VetKDKeyId {
            curve: mgt::VetKDCurve::Bls12_381_G2,
            name: key_name.to_string(),
        },
    };
    let payload_bytes = candid::encode_one(&args).map_err(format_error)?.len() as u64;
    Ok(ic_cdk::api::cost_call(
        "vetkd_public_key".len() as u64,
        payload_bytes,
    ))
}

pub async fn vetkd_public_key(
    key_name: String,
    context_version: u8,
    derivation_path: &[&[u8]],
) -> Result<Vec<u8>, String> {
    let args = mgt::VetKDPublicKeyArgs {
        canister_id: None,
        context: derivation_path_to_context(context_version, derivation_path)?,
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
    context_version: u8,
    derivation_path: &[&[u8]],
    input: Vec<u8>,
    transport_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let args = mgt::VetKDDeriveKeyArgs {
        input,
        context: derivation_path_to_context(context_version, derivation_path)?,
        transport_public_key,
        key_id: mgt::VetKDKeyId {
            curve: mgt::VetKDCurve::Bls12_381_G2,
            name: key_name,
        },
    };

    let res = mgt::vetkd_derive_key(&args).await.map_err(format_error)?;

    Ok(res.encrypted_key)
}

fn derivation_path_to_context(version: u8, derivation_path: &[&[u8]]) -> Result<Vec<u8>, String> {
    let mut hasher = sha3::Sha3_256::new();
    match version {
        1 => {
            for path in derivation_path {
                hasher.update(path);
            }
        }
        2 => {
            hasher.update(b"ic-cose:vetkd-context:v2");
            for path in derivation_path {
                hasher.update((path.len() as u64).to_be_bytes());
                hasher.update(path);
            }
        }
        _ => return Err("unsupported vetKD context version".to_string()),
    }
    let rt: [u8; 32] = hasher.finalize().into();
    Ok(rt.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_context_preserves_component_boundaries() {
        assert_eq!(
            derivation_path_to_context(1, &[b"ab", b"c"]).unwrap(),
            derivation_path_to_context(1, &[b"a", b"bc"]).unwrap()
        );
        assert_ne!(
            derivation_path_to_context(2, &[b"ab", b"c"]).unwrap(),
            derivation_path_to_context(2, &[b"a", b"bc"]).unwrap()
        );
        assert!(derivation_path_to_context(3, &[]).is_err());
    }
}
