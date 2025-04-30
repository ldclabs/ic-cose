use candid::{utils::ArgumentEncoder, Principal};
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

async fn call<In, Out>(id: Principal, method: &str, args: In, cycles: u128) -> Result<Out, String>
where
    In: ArgumentEncoder + Send,
    Out: candid::CandidType + for<'a> candid::Deserialize<'a>,
{
    let res = ic_cdk::call::Call::bounded_wait(id, method)
        .with_args(&args)
        .with_cycles(cycles)
        .await
        .map_err(|err| format!("failed to call {} on {:?}, error: {:?}", method, &id, err))?;
    res.candid().map_err(|err| {
        format!(
            "failed to decode response from {} on {:?}, error: {:?}",
            method, &id, err
        )
    })
}

async fn rand_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut data = ic_cdk::management_canister::raw_rand()
        .await
        .map_err(format_error)?;
    data.truncate(N);
    data.try_into().map_err(format_error)
}

ic_cdk::export_candid!();
