use candid::{utils::ArgumentEncoder, CandidType, Nat, Principal};
use ic_cdk_management_canister as mgt;
use ic_cose_types::format_error;
use ic_cose_types::types::wasm::{
    AddWasmInput, CommitWasmChunksInput, DeployWasmInput, DeploymentInfo, DeploymentRequest,
    InstallRequest, PoolCanisterInfo, ProvisionReceipt, ProvisionTemplate, ProvisionTemplateInfo,
    ReleaseReceipt, ReservationReceipt, ReserveRequest, StateInfo, WasmInfo,
};
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use std::collections::BTreeSet;

mod api;
mod api_admin;
mod api_provision;
mod init;
mod store;

use crate::init::ChainArgs;

static ANONYMOUS: Principal = Principal::anonymous();
// NNS Cycles Minting Canister: "rkp4c-7iaaa-aaaaa-aaaca-cai"
static CMC_PRINCIPAL: Principal = Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 4, 1, 1]);
const MILLISECONDS: u64 = 1_000_000;

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

fn is_controller_or_manager_or_committer() -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    if ic_cdk::api::is_controller(&caller)
        || store::state::is_controller(&caller)
        || store::state::is_manager(&caller)
        || store::state::is_committer(&caller)
    {
        Ok(())
    } else {
        Err("user is not a controller or manager or committer".to_string())
    }
}

/// Least-privilege role for the provisioning API.
///
/// A provisioner may only name a governance-approved template and supply init
/// args; it can neither manage roles nor deploy an arbitrary module, so granting
/// it to another canister does not hand over this canister's wasm repository.
fn is_provisioner() -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    if store::state::is_provisioner(&caller)
        || ic_cdk::api::is_controller(&caller)
        || store::state::is_controller(&caller)
    {
        Ok(())
    } else {
        Err("user is not a provisioner".to_string())
    }
}

pub fn validate_principals(principals: &BTreeSet<Principal>) -> Result<(), String> {
    if principals.is_empty() {
        return Err("principals cannot be empty".to_string());
    }
    if principals.contains(&ANONYMOUS) {
        return Err("anonymous user is not allowed".to_string());
    }
    Ok(())
}

/// Like [`call`], but preserves the typed call error so the caller can tell a
/// pre-dispatch failure from an unknown outcome.
async fn raw_call<In, Out>(
    id: Principal,
    method: &str,
    args: In,
    cycles: u128,
) -> Result<Out, ic_cdk::call::Error>
where
    In: ArgumentEncoder + Send,
    Out: candid::CandidType + for<'a> candid::Deserialize<'a>,
{
    ic_cdk::call::Call::bounded_wait(id, method)
        .with_args(&args)
        .with_cycles(cycles)
        .await?
        .candid()
        .map_err(ic_cdk::call::Error::from)
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
        .map_err(|err| format!("failed to call {} on {:?}, error: {:?}", method, id, err))?;
    res.candid().map_err(|err| {
        format!(
            "failed to decode response from {} on {:?}, error: {:?}",
            method, id, err
        )
    })
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct SubnetId {
    pub principal_id: String,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum SubnetSelection {
    /// Choose a specific subnet
    Subnet { subnet: SubnetId },
    // Skip the SubnetFilter on the CMC SubnetSelection for simplification.
    // https://github.com/dfinity/ic/blob/master/rs/nns/cmc/cmc.did#L35
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
struct CreateCanisterInput {
    pub settings: Option<mgt::CanisterSettings>,
    pub subnet_selection: Option<SubnetSelection>,
    pub subnet_type: Option<String>,
}

/// Error for create_canister.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum CreateCanisterOutput {
    Refunded {
        refund_amount: u128,
        create_error: String,
    },
}

/// Outcome of a canister creation, keeping "provably nothing was created" apart
/// from "the result is unknown".
///
/// The management canister cannot be asked which canister it created for a lost
/// response, so an unknown outcome must circuit-break refill rather than be
/// retried into a leak of one canister per attempt.
pub enum CreateOutcome {
    Created(Principal),
    /// The request provably did not create a canister.
    Refunded(String),
    /// A canister may exist without this canister knowing its principal.
    Unknown(String),
}

/// Only these two errors are raised before the call is dispatched, so they are
/// the only ones that prove no canister was created.
fn is_predispatch_error(err: &ic_cdk::call::Error) -> bool {
    matches!(
        err,
        ic_cdk::call::Error::InsufficientLiquidCycleBalance(_)
            | ic_cdk::call::Error::CallPerformFailed(_)
    )
}

/// Creates one pool canister, on `subnet` when the template pins one.
pub async fn create_pool_canister(
    subnet: Option<Principal>,
    settings: mgt::CanisterSettings,
    cycles: u128,
) -> CreateOutcome {
    match subnet {
        Some(subnet) => create_canister_on_outcome(subnet, Some(settings), cycles).await,
        None => match mgt::create_canister_with_extra_cycles(
            &mgt::CreateCanisterArgs {
                settings: Some(settings),
            },
            cycles,
        )
        .await
        {
            Ok(res) => CreateOutcome::Created(res.canister_id),
            Err(err) if is_predispatch_error(&err) => CreateOutcome::Refunded(format_error(err)),
            Err(err) => CreateOutcome::Unknown(format_error(err)),
        },
    }
}

/// CMC variant. A `Refunded` reply is the CMC explicitly stating it created
/// nothing, so it is deterministic; anything else may have created a canister.
async fn create_canister_on_outcome(
    subnet: Principal,
    settings: Option<mgt::CanisterSettings>,
    cycles: u128,
) -> CreateOutcome {
    let arg = CreateCanisterInput {
        settings,
        subnet_type: None,
        subnet_selection: Some(SubnetSelection::Subnet {
            subnet: SubnetId {
                principal_id: subnet.to_text(),
            },
        }),
    };
    let res: Result<Result<Principal, CreateCanisterOutput>, ic_cdk::call::Error> =
        raw_call(CMC_PRINCIPAL, "create_canister", (arg,), cycles).await;
    match res {
        Ok(Ok(canister)) => CreateOutcome::Created(canister),
        Ok(Err(err)) => CreateOutcome::Refunded(format!("{:?}", err)),
        Err(err) if is_predispatch_error(&err) => CreateOutcome::Refunded(format_error(err)),
        Err(err) => CreateOutcome::Unknown(format_error(err)),
    }
}

async fn create_canister_on(
    subnet: Principal,
    settings: Option<mgt::CanisterSettings>,
    cycles: u128,
) -> Result<Principal, String> {
    let arg = CreateCanisterInput {
        settings,
        subnet_type: None,
        subnet_selection: Some(SubnetSelection::Subnet {
            subnet: SubnetId {
                principal_id: subnet.to_text(),
            },
        }),
    };
    let res: Result<Principal, CreateCanisterOutput> =
        call(CMC_PRINCIPAL, "create_canister", (arg,), cycles).await?;
    res.map_err(|err| format!("failed to create canister, error: {:?}", err))
}

ic_cdk::export_candid!();
