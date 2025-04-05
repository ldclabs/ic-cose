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
mod ecdsa;
mod schnorr;
mod store;
mod vetkd;

use api_init::InstallArgs;

fn is_controller() -> Result<(), String> {
    let caller = ic_cdk::caller();
    if ic_cdk::api::is_controller(&caller) || store::state::is_controller(&caller) {
        Ok(())
    } else {
        Err("user is not a controller".to_string())
    }
}

fn is_controller_or_manager() -> Result<(), String> {
    let caller = ic_cdk::caller();
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
    if ic_cdk::caller() == ANONYMOUS {
        Err("anonymous user is not allowed".to_string())
    } else {
        Ok(())
    }
}

async fn rand_bytes<const N: usize>() -> Result<[u8; N], String> {
    let (mut data,) = ic_cdk::api::management_canister::main::raw_rand()
        .await
        .map_err(format_error)?;
    data.truncate(N);
    data.try_into().map_err(format_error)
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
