use candid::{Nat, Principal};
use ic_cdk::api::management_canister::main::*;
use ic_cose_types::{
    format_error,
    types::wasm::{DeploymentInfo, StateInfo, WasmInfo},
};
use num_traits::ToPrimitive;
use serde_bytes::ByteArray;

use crate::{is_controller_or_manager, store};

#[ic_cdk::query]
fn get_state() -> Result<StateInfo, String> {
    Ok(store::state::get_state_info())
}

#[ic_cdk::query]
fn get_wasm(hash: ByteArray<32>) -> Result<WasmInfo, String> {
    store::wasm::get_wasm(&hash)
        .map(|w| WasmInfo {
            name: w.name,
            created_at: w.created_at,
            created_by: w.created_by,
            description: w.description,
            wasm: w.wasm,
            hash,
        })
        .ok_or_else(|| "wasm not found".to_string())
}

#[ic_cdk::query]
fn get_deployed_canisters_info() -> Result<Vec<DeploymentInfo>, String> {
    Ok(store::wasm::get_deployed())
}

#[ic_cdk::query]
fn get_deployed_canisters() -> Result<Vec<Principal>, String> {
    store::state::with(|s| Ok(s.deployed_list.keys().cloned().collect()))
}

#[ic_cdk::update(guard = "is_controller_or_manager")]
async fn get_canister_status(
    canister: Option<Principal>,
) -> Result<CanisterStatusResponse, String> {
    let self_id = ic_cdk::id();
    let canister = canister.unwrap_or(self_id);
    if canister != self_id {
        store::state::with(|s| {
            if !s.deployed_list.contains_key(&canister) {
                return Err("canister not found".to_string());
            }
            Ok(())
        })?;
    }

    let res = canister_status(CanisterIdRecord {
        canister_id: canister,
    })
    .await
    .map_err(format_error)?;
    Ok(res.0)
}

#[ic_cdk::query(guard = "is_controller_or_manager")]
fn deployment_logs(
    name: String,
    prev: Option<Nat>,
    take: Option<Nat>,
) -> Result<Vec<DeploymentInfo>, String> {
    let prev = prev.as_ref().map(nat_to_u64);
    let take = take.as_ref().map(nat_to_u64).unwrap_or(10).min(1000) as usize;
    Ok(store::wasm::deployment_logs(&name, prev, take))
}

fn nat_to_u64(nat: &Nat) -> u64 {
    nat.0.to_u64().unwrap_or(0)
}
