use candid::Principal;
use ic_cose_types::types::object_store::*;
use serde_bytes::ByteBuf;
use std::collections::BTreeSet;

mod api;
mod api_admin;
mod api_init;
mod store;

use api_init::InstallArgs;

fn is_controller() -> Result<(), String> {
    let caller = ic_cdk::caller();
    if ic_cdk::api::is_controller(&caller) || store::state::is_controller(&caller) {
        Ok(())
    } else {
        Err("user is not a controller".to_string())
    }
}

/// A getrandom implementation that always fails
#[no_mangle]
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
unsafe extern "Rust" fn __getrandom_v03_custom(
    _dest: *mut u8,
    _len: usize,
) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

ic_cdk::export_candid!();
