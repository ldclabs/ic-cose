use candid::{utils::ArgumentEncoder, CandidType, Nat, Principal};
use ic_cdk_management_canister as mgt;
use ic_cose_types::format_error;
use ic_cose_types::types::wasm::{
    AddWasmInput, BatchCallResult, CommitWasmChunksInput, DeployWasmInput, DeploymentInfo,
    DeploymentRequest, InstallRequest, PoolCanisterInfo, ProvisionReceipt, ProvisionTemplate,
    ProvisionTemplateInfo, ReleaseReceipt, ReservationReceipt, ReserveRequest, StateInfo,
    TopupResult, WasmInfo, WasmMetadata,
};
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use std::collections::BTreeSet;

mod api;
mod api_admin;
mod api_provision;
#[path = "../../canister_memory.rs"]
mod canister_memory;
mod init;
mod management;
mod store;

use crate::init::ChainArgs;

#[cfg(target_arch = "wasm64")]
getrandom_02::register_custom_getrandom!(unsupported_getrandom);
#[cfg(target_arch = "wasm64")]
fn unsupported_getrandom(_: &mut [u8]) -> Result<(), getrandom_02::Error> {
    Err(getrandom_02::Error::UNSUPPORTED)
}

// NNS Cycles Minting Canister: "rkp4c-7iaaa-aaaaa-aaaca-cai"
static CMC_PRINCIPAL: Principal = Principal::from_slice(&[0, 0, 0, 0, 0, 0, 0, 4, 1, 1]);
const MILLISECONDS: u64 = 1_000_000;
/// Keeps a payload this canister builds comfortably below the 2 MiB message
/// limit, including Candid framing: install arguments, direct installs, query
/// replies and batch replies.
const MAX_MESSAGE_PAYLOAD_BYTES: usize = 1_500_000;

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

pub use ic_cose_types::validate_principals;

fn extend_role_set(
    target: &mut BTreeSet<Principal>,
    values: BTreeSet<Principal>,
    label: &str,
) -> Result<(), String> {
    let additions = values
        .iter()
        .filter(|principal| !target.contains(*principal))
        .count();
    if target.len().saturating_add(additions) > ic_cose_types::MAX_PRINCIPALS_PER_SET {
        return Err(format!(
            "{label} count exceeds the limit {}",
            ic_cose_types::MAX_PRINCIPALS_PER_SET
        ));
    }
    target.extend(values);
    Ok(())
}

/// Calls a trusted system canister while preserving the typed call error so the
/// caller can tell a pre-dispatch failure from an unknown outcome.
///
/// This deliberately uses unbounded wait: the call transfers enough cycles to
/// create and fund a canister, and a best-effort timeout could lose the response
/// while those cycles have already been accepted.
async fn call_with_cycles<In, Out>(
    id: Principal,
    method: &str,
    args: In,
    cycles: u128,
) -> Result<Out, ic_cdk::call::Error>
where
    In: ArgumentEncoder + Send,
    Out: candid::CandidType + for<'a> candid::Deserialize<'a>,
{
    ic_cdk::call::Call::unbounded_wait(id, method)
        .with_args(&args)
        .with_cycles(cycles)
        .await?
        .candid()
        .map_err(ic_cdk::call::Error::from)
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum SubnetSelection {
    /// Choose a specific subnet
    Subnet { subnet: Principal },
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
/// `creation_budget` is the total amount attached to creation; the subnet's
/// creation fee is deducted from it on both paths.
pub async fn create_pool_canister(
    subnet: Option<Principal>,
    settings: mgt::CanisterSettings,
    creation_budget: u128,
) -> CreateOutcome {
    match subnet {
        Some(subnet) => create_canister_on_outcome(subnet, Some(settings), creation_budget).await,
        None => {
            // The management canister deducts the creation fee from the attached
            // budget, so a budget below the fee is a guaranteed rejection. That
            // rejection is not a pre-dispatch error, so dispatching it anyway
            // would circuit-break refill on a create that provably never
            // happened. Refuse it here, where nothing was created for certain.
            let fee = ic_cdk::api::cost_create_canister();
            if creation_budget < fee {
                return CreateOutcome::Refunded(format!(
                    "creation budget {} is below the subnet creation fee {}",
                    creation_budget, fee
                ));
            }
            match management::create_canister(settings, creation_budget).await {
                Ok(canister) => CreateOutcome::Created(canister),
                Err(err) if is_predispatch_error(&err) => {
                    CreateOutcome::Refunded(format_error(err))
                }
                Err(err) => CreateOutcome::Unknown(format_error(err)),
            }
        }
    }
}

/// CMC variant. A `Refunded` reply is the CMC explicitly stating it created
/// nothing, so it is deterministic; anything else may have created a canister.
async fn create_canister_on_outcome(
    subnet: Principal,
    settings: Option<mgt::CanisterSettings>,
    creation_budget: u128,
) -> CreateOutcome {
    let arg = create_canister_input(subnet, settings);
    let res: Result<Result<Principal, CreateCanisterOutput>, ic_cdk::call::Error> =
        call_with_cycles(CMC_PRINCIPAL, "create_canister", (arg,), creation_budget).await;
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
    creation_budget: u128,
) -> Result<Principal, String> {
    let arg = create_canister_input(subnet, settings);
    let res: Result<Principal, CreateCanisterOutput> =
        call_with_cycles(CMC_PRINCIPAL, "create_canister", (arg,), creation_budget)
            .await
            .map_err(|err| {
                format!(
                    "failed to call create_canister on {:?}, error: {:?}",
                    CMC_PRINCIPAL, err
                )
            })?;
    res.map_err(|err| format!("failed to create canister, error: {:?}", err))
}

fn create_canister_input(
    subnet: Principal,
    settings: Option<mgt::CanisterSettings>,
) -> CreateCanisterInput {
    CreateCanisterInput {
        settings,
        subnet_type: None,
        subnet_selection: Some(SubnetSelection::Subnet { subnet }),
    }
}

#[ic_cdk::on_low_wasm_memory]
fn on_low_wasm_memory() {
    store::state::set_low_wasm_memory(true);
    ic_cdk::api::debug_print("ic_wasm_canister entered low Wasm memory mode");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keeps the local CMC binding aligned with the canonical `cmc.did`, where
    /// `Subnet.subnet` is a principal (not the legacy protobuf-shaped text).
    #[test]
    fn cmc_subnet_selection_encodes_a_principal() {
        #[derive(CandidType, Deserialize)]
        enum CanonicalSubnetSelection {
            Subnet { subnet: Principal },
        }

        #[derive(CandidType, Deserialize)]
        struct CanonicalCreateCanisterInput {
            settings: Option<mgt::CanisterSettings>,
            subnet_selection: Option<CanonicalSubnetSelection>,
            subnet_type: Option<String>,
        }

        let subnet = Principal::from_slice(&[1, 2, 3, 4]);
        let bytes = candid::encode_one(create_canister_input(subnet, None)).unwrap();
        let decoded: CanonicalCreateCanisterInput = candid::decode_one(&bytes).unwrap();
        assert!(decoded.settings.is_none());
        assert!(decoded.subnet_type.is_none());
        match decoded.subnet_selection {
            Some(CanonicalSubnetSelection::Subnet { subnet: actual }) => {
                assert_eq!(actual, subnet)
            }
            None => panic!("subnet selection is missing"),
        }
    }
}

ic_cdk::export_candid!();
