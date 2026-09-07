use candid::{Nat, Principal};
use ic_cdk_management_canister as mgt;
use ic_cose_types::{
    format_error,
    types::wasm::{
        DeploymentInfo, PoolCanisterInfo, ProvisionTemplateInfo, StateInfo, WasmInfo, WasmMetadata,
    },
};
use num_traits::ToPrimitive;
use serde_bytes::ByteArray;

use crate::{is_controller_or_manager, store};

#[ic_cdk::query]
fn get_state() -> Result<StateInfo, String> {
    Ok(store::state::get_state_info())
}

#[ic_cdk::query]
fn list_latest_wasm_versions(
    prev: Option<String>,
    take: Option<u32>,
) -> Result<Vec<(String, ByteArray<32>)>, String> {
    if let Some(cursor) = prev.as_ref() {
        ic_cose_types::validate_str(cursor)?;
    }
    Ok(store::state::latest_versions_page(
        prev,
        take.unwrap_or(100).clamp(1, 1_000) as usize,
    ))
}

#[ic_cdk::query]
fn get_next_wasm_version(
    name: String,
    previous_module_hash: ByteArray<32>,
) -> Result<WasmMetadata, String> {
    ic_cose_types::validate_str(&name)?;
    store::wasm::next_version_metadata(&name, previous_module_hash).map(|(_, metadata)| metadata)
}

#[ic_cdk::query]
fn get_wasm(hash: ByteArray<32>) -> Result<WasmInfo, String> {
    let metadata = store::wasm::get_metadata(&hash)?;
    if metadata.wasm_size > 1_500_000 {
        return Err(
            "artifact is too large for one query response; use get_wasm_metadata and get_wasm_chunk"
                .to_string(),
        );
    }
    let w = store::wasm::get_wasm(&hash).ok_or_else(|| "NotFound: wasm not found".to_string())?;
    Ok(WasmInfo {
        name: w.name,
        created_at: w.created_at,
        created_by: w.created_by,
        description: w.description,
        wasm: w.wasm,
        hash,
        module_hash: metadata.module_hash,
        wasm_size: metadata.wasm_size,
        encoding: metadata.encoding,
    })
}

#[ic_cdk::query]
fn get_wasm_metadata(hash: ByteArray<32>) -> Result<WasmMetadata, String> {
    store::wasm::get_metadata(&hash)
}

#[ic_cdk::query]
fn get_wasm_chunk(
    hash: ByteArray<32>,
    offset: u64,
    take: u32,
) -> Result<serde_bytes::ByteBuf, String> {
    let take = take.clamp(1, 1024 * 1024) as usize;
    let offset = usize::try_from(offset).map_err(|_| "offset exceeds usize".to_string())?;
    store::wasm::get_chunk(&hash, offset, take).map(serde_bytes::ByteBuf::from)
}

#[ic_cdk::query(guard = "is_controller_or_manager")]
fn list_legacy_wasm_artifacts(
    prev: Option<ByteArray<32>>,
    take: Option<u32>,
) -> Result<Vec<ByteArray<32>>, String> {
    Ok(store::wasm::list_legacy_artifacts(
        prev,
        take.unwrap_or(20).clamp(1, 100) as usize,
    ))
}

#[ic_cdk::query]
fn get_deployed_canisters_info() -> Result<Vec<DeploymentInfo>, String> {
    let values = store::wasm::get_deployed_page(None, 1_001);
    if values.len() > 1_000 {
        return Err(
            "more than 1000 deployed canisters; use get_deployed_canisters_info_v2".to_string(),
        );
    }
    Ok(values)
}

#[ic_cdk::query]
fn get_deployed_canisters_info_v2(
    prev: Option<Principal>,
    take: Option<u32>,
) -> Result<Vec<DeploymentInfo>, String> {
    Ok(store::wasm::get_deployed_page(
        prev,
        take.unwrap_or(100).clamp(1, 1_000) as usize,
    ))
}

#[ic_cdk::query]
fn get_deployed_canisters() -> Result<Vec<Principal>, String> {
    let values = store::state::deployed_canisters_page(None, 1_001);
    if values.len() > 1_000 {
        return Err("more than 1000 canisters; use get_deployed_canisters_v2".to_string());
    }
    Ok(values)
}

#[ic_cdk::query]
fn get_deployed_canisters_v2(
    prev: Option<Principal>,
    take: Option<u32>,
) -> Result<Vec<Principal>, String> {
    Ok(store::state::deployed_canisters_page(
        prev,
        take.unwrap_or(100).clamp(1, 1_000) as usize,
    ))
}

#[ic_cdk::update(guard = "is_controller_or_manager")]
async fn get_canister_status(
    canister: Option<Principal>,
) -> Result<mgt::CanisterStatusResult, String> {
    let self_id = ic_cdk::api::canister_self();
    let canister = canister.unwrap_or(self_id);
    if canister != self_id && store::state::deployed(&canister).is_none() {
        return Err("NotFound: canister not found".to_string());
    }

    let res = mgt::canister_status(&mgt::CanisterStatusArgs {
        canister_id: canister,
    })
    .await
    .map_err(format_error)?;
    Ok(res)
}

#[ic_cdk::query(guard = "is_controller_or_manager")]
fn deployment_logs(
    name: String,
    prev: Option<Nat>,
    take: Option<Nat>,
) -> Result<Vec<DeploymentInfo>, String> {
    ic_cose_types::validate_str(&name)?;
    let prev = prev.as_ref().map(nat_to_u64).transpose()?;
    let take = take
        .as_ref()
        .map(nat_to_u64)
        .transpose()?
        .unwrap_or(10)
        .min(100) as usize;
    Ok(store::wasm::deployment_logs(&name, prev, take))
}

fn nat_to_u64(nat: &Nat) -> Result<u64, String> {
    nat.0
        .to_u64()
        .ok_or_else(|| "value exceeds nat64".to_string())
}

/// The approved template a provisioner must name by id and hash.
#[ic_cdk::query]
fn get_provision_template(id: String) -> Result<ProvisionTemplateInfo, String> {
    ic_cose_types::validate_str(&id)?;
    store::provision::get_template(&id)
        .ok_or_else(|| format!("NotFound: provision template {} not found", id))
}

#[ic_cdk::query]
fn list_provision_templates() -> Result<Vec<ProvisionTemplateInfo>, String> {
    let values = store::provision::list_templates_page(None, 1_001);
    if values.len() > 1_000 {
        return Err("more than 1000 templates; use list_provision_templates_v2".to_string());
    }
    Ok(values)
}

#[ic_cdk::query]
fn list_provision_templates_v2(
    prev: Option<String>,
    take: Option<u32>,
) -> Result<Vec<ProvisionTemplateInfo>, String> {
    if let Some(cursor) = prev.as_ref() {
        ic_cose_types::validate_str(cursor)?;
    }
    Ok(store::provision::list_templates_page(
        prev,
        take.unwrap_or(100).clamp(1, 1_000) as usize,
    ))
}

/// Recorded pool inventory of a template.
///
/// Governance watches this against the reservation churn: a pool that keeps
/// draining is the signal to rate-limit callers, not to raise the pool size.
#[ic_cdk::query(guard = "is_controller_or_manager")]
fn list_provision_pool(template_id: String) -> Result<Vec<PoolCanisterInfo>, String> {
    ic_cose_types::validate_str(&template_id)?;
    let values = store::provision::list_pool_page(&template_id, None, 1_001);
    if values.len() > 1_000 {
        return Err("more than 1000 pool records; use list_provision_pool_v2".to_string());
    }
    Ok(values)
}

#[ic_cdk::query(guard = "is_controller_or_manager")]
fn list_provision_pool_v2(
    template_id: String,
    prev: Option<Principal>,
    take: Option<u32>,
) -> Result<Vec<PoolCanisterInfo>, String> {
    ic_cose_types::validate_str(&template_id)?;
    Ok(store::provision::list_pool_page(
        &template_id,
        prev,
        take.unwrap_or(100).clamp(1, 1_000) as usize,
    ))
}
