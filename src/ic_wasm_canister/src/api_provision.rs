use candid::Principal;
use ic_cdk_management_canister as mgt;
use ic_cose_types::{
    cose::sha256,
    types::wasm::{
        DeploymentRequest, InstallRequest, ProvisionReceipt, ReleaseReceipt, ReservationReceipt,
        ReserveRequest, MAX_PROVISION_ARGS_BYTES,
    },
};
use serde_bytes::ByteArray;

use crate::{
    is_controller, is_controller_or_manager, is_provisioner, management,
    store::{self, state::OperationGuard},
    MILLISECONDS,
};

/// Claims one pre-created canister for `request_id`.
///
/// Idempotent and fully synchronous: the `request_id -> canister` binding is
/// committed together with the reply, so a caller that never sees the response
/// recovers the same canister by replaying the call or reading the receipt. It
/// never creates a canister, which is why a lost management-canister create can
/// only ever waste an unpaid pool canister.
#[ic_cdk::update(guard = "is_provisioner")]
fn reserve_canister(req: ReserveRequest) -> Result<ReservationReceipt, String> {
    if store::provision::get_receipt(&req.request_id).is_none() {
        store::state::ensure_memory_available()?;
    }
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::provision::validate_epoch(req.expires_at, now_ms)?;
    store::provision::reserve(ic_cdk::api::msg_caller(), now_ms, &req)
}

/// Installs the template's approved module onto the reserved canister.
///
/// Idempotent by `request_id`: a retry after a lost response converges on the
/// already-installed module instead of failing, and the module hash reported by
/// the management canister is verified against the hash the template pins.
#[ic_cdk::update(guard = "is_provisioner")]
async fn ensure_install(req: InstallRequest) -> Result<ProvisionReceipt, String> {
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::provision::validate_epoch(req.expires_at, now_ms)?;

    let owner = ic_cdk::api::msg_caller();
    let (attempt, canister, artifact_hash, expected, controllers) =
        match store::provision::begin_install(owner, now_ms, &req)? {
            store::provision::InstallPlan::AlreadyInstalled(receipt) => {
                return confirm_installed(*receipt, req.request_id, &req.init_args).await;
            }
            store::provision::InstallPlan::Install {
                attempt,
                canister,
                artifact_hash,
                expected_module_hash,
                controllers,
            } => (
                attempt,
                canister,
                artifact_hash,
                expected_module_hash,
                controllers,
            ),
        };

    let _lock = OperationGuard::adopt(canister, req.request_id, attempt);
    let outcome = install_exact(
        canister,
        mgt::CanisterInstallMode::Install,
        artifact_hash,
        &req.init_args,
        expected,
        &controllers,
    )
    .await;
    finish_attempt(&req.request_id, attempt, outcome, &req.init_args)
}

/// Upgrades an already deployed canister to an exact module.
///
/// Restricted to canisters this canister deployed, and to the wasm name they
/// already run: a provisioner must not be able to push an arbitrary module onto
/// an arbitrary canister. Compare-and-swaps on `expected_prev_module_hash`, so a
/// stale request can never overwrite a module the caller did not expect to be
/// running, and the result is verified against `expected_module_hash`.
#[ic_cdk::update(guard = "is_provisioner")]
async fn ensure_deployment(req: DeploymentRequest) -> Result<ProvisionReceipt, String> {
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::provision::validate_epoch(req.expires_at, now_ms)?;
    ic_cose_types::validate_str(&req.wasm_name)?;
    if store::provision::get_receipt(&req.request_id).is_none() {
        store::state::ensure_memory_available()?;
    }
    if req.args.len() > MAX_PROVISION_ARGS_BYTES as usize {
        return Err(format!(
            "args of {} bytes exceeds the limit {}",
            req.args.len(),
            MAX_PROVISION_ARGS_BYTES
        ));
    }
    if sha256(&req.args) != *req.args_hash {
        return Err("args_hash does not match args".to_string());
    }

    let metadata = store::wasm::get_metadata(&req.artifact_hash).map_err(|_| {
        format!(
            "NotFound: artifact {} not found",
            hex::encode(req.artifact_hash.as_ref())
        )
    })?;
    if metadata.name != req.wasm_name {
        return Err(format!(
            "artifact belongs to wasm {}, not {}",
            metadata.name, req.wasm_name
        ));
    }
    if metadata.module_hash != req.expected_module_hash {
        return Err("expected_module_hash does not match the stored artifact".to_string());
    }
    let owner = ic_cdk::api::msg_caller();

    let attempt = match store::provision::begin_deployment(
        owner,
        now_ms,
        &req.request_id,
        req.canister,
        &req.wasm_name,
        req.artifact_hash,
        req.expected_module_hash,
        req.expected_prev_module_hash,
        req.args_hash,
        req.args.len() as u64,
        req.expires_at,
    )? {
        store::provision::DeploymentPlan::AlreadyInstalled(receipt) => {
            return confirm_installed(*receipt, req.request_id, &req.args).await;
        }
        store::provision::DeploymentPlan::Deploy { attempt } => attempt,
    };
    let _lock = OperationGuard::adopt(req.canister, req.request_id, attempt);
    let outcome = upgrade_exact(&req).await;
    finish_attempt(&req.request_id, attempt, outcome, &req.args)
}

/// Returns a reserved canister to the pool.
///
/// Only valid while the reservation never installed anything; the canister must
/// still be empty and still carry the template's controllers, so a released
/// canister cannot come back polluted.
#[ic_cdk::update(guard = "is_provisioner")]
async fn release_reservation(
    request_id: ByteArray<32>,
    canister: Principal,
) -> Result<ReleaseReceipt, String> {
    let owner = ic_cdk::api::msg_caller();
    let receipt = store::provision::get_receipt(&request_id)
        .ok_or_else(|| "NotFound: provision request not found".to_string())?;
    if receipt.canister != canister {
        return Err(format!(
            "request is bound to canister {}, not {}",
            receipt.canister.to_text(),
            canister.to_text()
        ));
    }
    if receipt.stage == ic_cose_types::types::wasm::ProvisionStage::Released {
        return store::provision::release(
            owner,
            ic_cdk::api::time() / MILLISECONDS,
            &request_id,
            canister,
        );
    }
    probe_and_release(owner, request_id, canister).await
}

/// The durable outcome of a `request_id`, readable after any lost response.
#[ic_cdk::query(guard = "is_provisioner")]
fn get_provision_receipt(request_id: ByteArray<32>) -> Result<ProvisionReceipt, String> {
    let caller = ic_cdk::api::msg_caller();
    let receipt = store::provision::get_receipt(&request_id)
        .ok_or_else(|| "NotFound: provision request not found".to_string())?;
    if receipt.owner != Principal::anonymous()
        && receipt.owner != caller
        && is_controller().is_err()
    {
        return Err("request id belongs to another provisioner".to_string());
    }
    Ok(receipt)
}

#[ic_cdk::query(guard = "is_controller_or_manager")]
fn list_expired_reservations(
    prev: Option<ByteArray<32>>,
    take: Option<u32>,
) -> Result<Vec<ProvisionReceipt>, String> {
    store::provision::ensure_legacy_request_scan_bounded()?;
    Ok(store::provision::list_expired_reservations(
        ic_cdk::api::time() / MILLISECONDS,
        prev,
        take.unwrap_or(100).clamp(1, 1_000) as usize,
    ))
}

/// Bounds scanned records, including non-matching requests. Follow next_cursor even on empty pages.
#[ic_cdk::query(guard = "is_controller_or_manager")]
fn list_expired_reservations_page(
    prev: Option<ByteArray<32>>,
    scan_limit: u32,
) -> Result<ic_cose_types::types::ScanPage<ProvisionReceipt, ByteArray<32>>, String> {
    Ok(store::provision::list_expired_reservations_page(
        ic_cdk::api::time() / MILLISECONDS,
        prev,
        scan_limit.clamp(1, 1_000) as usize,
    ))
}

/// Resolves an interrupted install or upgrade, including after its request
/// epoch expires. Only probes the target: this never installs or upgrades code.
/// An empty reserved target becomes Failed and may then be released normally.
#[ic_cdk::update(guard = "is_provisioner")]
async fn reconcile_provision_request(
    request_id: ByteArray<32>,
) -> Result<ProvisionReceipt, String> {
    let caller = ic_cdk::api::msg_caller();
    let (canister, attempt) = store::provision::begin_reconcile(
        caller,
        is_controller().is_ok(),
        &request_id,
        ic_cdk::api::time() / MILLISECONDS,
    )?;
    let _lock = OperationGuard::adopt(canister, request_id, attempt);
    let result = async {
        let info = management::canister_info(canister).await?;
        store::provision::finish_reconcile(
            &request_id,
            attempt,
            info.module_hash,
            &info.controllers,
            ic_cdk::api::time() / MILLISECONDS,
        )
    }
    .await;
    if let Err(error) = &result {
        store::provision::fail_install(
            &request_id,
            attempt,
            error.clone(),
            ic_cdk::api::time() / MILLISECONDS,
        );
    }
    result
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_release_expired_reservation(
    request_id: ByteArray<32>,
) -> Result<ReleaseReceipt, String> {
    let receipt = store::provision::get_receipt(&request_id)
        .ok_or_else(|| "NotFound: provision request not found".to_string())?;
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    if receipt.expires_at == 0 || receipt.expires_at > now_ms {
        return Err("reservation has not expired".to_string());
    }
    if receipt.stage == ic_cose_types::types::wasm::ProvisionStage::Released {
        return store::provision::release(receipt.owner, now_ms, &request_id, receipt.canister);
    }
    if !matches!(
        receipt.stage,
        ic_cose_types::types::wasm::ProvisionStage::Reserved
            | ic_cose_types::types::wasm::ProvisionStage::Failed
    ) {
        return Err("only an unused reservation can be reclaimed".to_string());
    }
    probe_and_release(receipt.owner, request_id, receipt.canister).await
}

// ----- helpers -----

/// Re-verifies an installed receipt against the live module and repairs a
/// deployment record whose commit was lost, so a replay converges.
async fn confirm_installed(
    receipt: ProvisionReceipt,
    request_id: ByteArray<32>,
    args: &[u8],
) -> Result<ProvisionReceipt, String> {
    let expected = receipt
        .module_hash
        .ok_or_else(|| "installed receipt is missing module_hash".to_string())?;
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    let _lock = OperationGuard::acquire(receipt.canister, request_id, now_ms, now_ms)?;
    assert_module_hash(receipt.canister, expected).await?;
    store::provision::repair_installed_receipt(&receipt, args, ic_cdk::api::time() / MILLISECONDS)?;
    Ok(receipt)
}

/// Records the outcome of an install or upgrade attempt; a failed commit
/// leaves the request `Failed` so it can be reconciled.
fn finish_attempt(
    request_id: &ByteArray<32>,
    attempt: u64,
    outcome: Result<ByteArray<32>, String>,
    args: &[u8],
) -> Result<ProvisionReceipt, String> {
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    let result = outcome.and_then(|module_hash| {
        store::provision::commit_install_success(request_id, attempt, module_hash, now_ms, args)
    });
    if let Err(err) = &result {
        store::provision::fail_install(request_id, attempt, err.clone(), now_ms);
    }
    result
}

/// Returns a reservation's canister to the pool once it is proven empty and
/// still carries the template's controllers.
async fn probe_and_release(
    owner: Principal,
    request_id: ByteArray<32>,
    canister: Principal,
) -> Result<ReleaseReceipt, String> {
    let expected = store::provision::expected_controllers(owner, &request_id)?;
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    let _lock = OperationGuard::acquire(canister, request_id, now_ms, now_ms)?;
    let info = management::canister_info(canister).await?;
    if info.module_hash.is_some() {
        return Err("canister is not empty and cannot be released".to_string());
    }
    store::provision::assert_controllers(&info.controllers, &expected)?;
    store::provision::release(
        owner,
        ic_cdk::api::time() / MILLISECONDS,
        &request_id,
        canister,
    )
}

/// Installs onto an empty canister and returns the resulting module hash.
///
/// A retry whose first attempt succeeded but lost its response finds the
/// expected module already running and converges instead of failing.
async fn install_exact(
    canister: Principal,
    mode: mgt::CanisterInstallMode,
    artifact_hash: ByteArray<32>,
    arg: &[u8],
    expected: ByteArray<32>,
    controllers: &[Principal],
) -> Result<ByteArray<32>, String> {
    let info = management::canister_info(canister).await?;
    // a reserved canister whose controllers drifted is no longer the canister
    // the template approved, so it must not receive the install
    store::provision::assert_controllers(&info.controllers, controllers)?;
    match info.module_hash {
        Some(h) if h == expected => return Ok(h),
        Some(h) => {
            return Err(format!(
                "canister {} already runs module {}",
                canister.to_text(),
                hex::encode(h.as_ref())
            ))
        }
        None => {}
    }

    management::install_stored_code(canister, mode, artifact_hash, arg).await?;
    assert_module_hash(canister, expected).await
}

async fn upgrade_exact(req: &DeploymentRequest) -> Result<ByteArray<32>, String> {
    let current = management::canister_info(req.canister).await?.module_hash;
    if current == Some(req.expected_module_hash) {
        // a retry after a lost response: the upgrade already landed
        return Ok(req.expected_module_hash);
    }
    match current {
        Some(h) if h == req.expected_prev_module_hash => {}
        Some(h) => {
            return Err(format!(
                "prev module hash mismatch: canister runs {}, expected {}",
                hex::encode(h.as_ref()),
                hex::encode(req.expected_prev_module_hash.as_ref())
            ))
        }
        None => return Err("canister has no module to upgrade".to_string()),
    }

    management::install_stored_code(
        req.canister,
        mgt::CanisterInstallMode::Upgrade(None),
        req.artifact_hash,
        &req.args,
    )
    .await?;
    assert_module_hash(req.canister, req.expected_module_hash).await
}

async fn assert_module_hash(
    canister: Principal,
    expected: ByteArray<32>,
) -> Result<ByteArray<32>, String> {
    let actual = management::canister_info(canister)
        .await?
        .module_hash
        .ok_or_else(|| "canister reports no module after install".to_string())?;
    if actual != expected {
        return Err(format!(
            "installed module hash {} does not match the approved {}",
            hex::encode(actual.as_ref()),
            hex::encode(expected.as_ref())
        ));
    }
    Ok(actual)
}
