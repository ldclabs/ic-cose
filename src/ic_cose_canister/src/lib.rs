use candid::Principal;
use ic_cose_types::{
    types::namespace::*, types::setting::*, types::state::StateInfo, types::*, ANONYMOUS,
};
use serde_bytes::ByteBuf;
use std::collections::BTreeSet;

mod api_admin;
mod api_cose;
mod api_init;
mod api_namespace;
mod api_setting;
mod ecdsa;
mod schnorr;
mod store;

use api_init::ChainArgs;

fn is_controller() -> Result<(), String> {
    let caller = ic_cdk::caller();
    if ic_cdk::api::is_controller(&caller) {
        Ok(())
    } else {
        Err("user is not a controller".to_string())
    }
}

fn is_authenticated() -> Result<(), String> {
    if ic_cdk::caller() == ANONYMOUS {
        Err("anonymous user is not allowed".to_string())
    } else {
        Ok(())
    }
}

async fn rand_bytes() -> Vec<u8> {
    let (rr,) = ic_cdk::api::management_canister::main::raw_rand()
        .await
        .expect("failed to get random bytes");
    rr
}

#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
/// A getrandom implementation that always fails
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
getrandom::register_custom_getrandom!(always_fail);

ic_cdk::export_candid!();
