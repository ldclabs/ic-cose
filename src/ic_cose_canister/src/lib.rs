use candid::Principal;
use ic_auth_types::*;
use ic_cose_types::{
    format_error, types::namespace::*, types::setting::*, types::state::StateInfo, types::*,
    ANONYMOUS,
};
use serde_bytes::{ByteArray, ByteBuf};
use std::collections::BTreeSet;

mod api_admin;
mod api_cose;
mod api_identity;
mod api_init;
mod api_namespace;
mod api_setting;
#[path = "../../canister_memory.rs"]
mod canister_memory;
mod ecdsa;
mod schnorr;
mod store;
mod vetkd;

use api_init::InstallArgs;

// The upstream dummy backend only registers getrandom 0.2 on wasm32.
// Canisters obtain entropy asynchronously from raw_rand, never the host OS.
#[cfg(target_arch = "wasm64")]
getrandom_02::register_custom_getrandom!(unsupported_getrandom);
#[cfg(target_arch = "wasm64")]
fn unsupported_getrandom(_: &mut [u8]) -> Result<(), getrandom_02::Error> {
    Err(getrandom_02::Error::UNSUPPORTED)
}

#[inline]
fn remove_set_items<T: Ord>(target: &mut BTreeSet<T>, items: BTreeSet<T>) {
    for item in items {
        target.remove(&item);
    }
}

fn extend_set_bounded<T: Ord>(
    target: &mut BTreeSet<T>,
    items: BTreeSet<T>,
    limit: usize,
    label: &str,
) -> Result<(), String> {
    let additions = items.iter().filter(|item| !target.contains(*item)).count();
    if target.len().saturating_add(additions) > limit {
        return Err(format!("{label} count exceeds the limit {limit}"));
    }
    target.extend(items);
    Ok(())
}

fn is_controller() -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    if ic_cdk::api::is_controller(&caller) || store::state::is_controller(&caller) {
        Ok(())
    } else {
        Err("user is not a controller".to_string())
    }
}

fn is_controller_or_manager() -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    if ic_cdk::api::is_controller(&caller)
        || store::state::is_controller(&caller)
        || store::state::is_manager(&caller)
    {
        Ok(())
    } else {
        Err("user is not a controller or manager".to_string())
    }
}

fn is_authenticated() -> Result<(), String> {
    if ic_cdk::api::msg_caller() == ANONYMOUS {
        Err("anonymous user is not allowed".to_string())
    } else {
        Ok(())
    }
}

async fn rand_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut data = ic_cdk_management_canister::raw_rand()
        .await
        .map_err(format_error)?;
    data.truncate(N);
    data.try_into().map_err(format_error)
}

#[ic_cdk::on_low_wasm_memory]
fn on_low_wasm_memory() {
    store::state::set_low_wasm_memory(true);
    ic_cdk::api::debug_print("ic_cose_canister entered low Wasm memory mode");
}

ic_cdk::export_candid!();
