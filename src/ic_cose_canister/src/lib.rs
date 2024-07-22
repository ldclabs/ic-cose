use candid::Principal;
use ic_cose_types::{cose::*, namespace::*, setting::*, state::StateInfo};
use serde_bytes::ByteBuf;
use std::collections::BTreeSet;

mod api_admin;
mod api_init;
mod api_query;
mod api_update;
mod ecdsa;
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
