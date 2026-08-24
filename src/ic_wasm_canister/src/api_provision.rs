use candid::Principal;
use ic_cdk_management_canister as mgt;
use ic_cose_types::{
    cose::sha256,
    format_error,
    types::wasm::{
        DeploymentRequest, InstallRequest, ProvisionReceipt, ReleaseReceipt, ReservationReceipt,
        ReserveRequest, MAX_PROVISION_ARGS_BYTES,
    },
};
use serde_bytes::ByteArray;

use crate::{is_provisioner, store, MILLISECONDS};

/// Largest module still installed with a single `install_code` message. Larger
/// artifacts go through the chunk store, which is what lets a module above the
/// ingress/request limits be deployed at all.
const MAX_DIRECT_INSTALL_BYTES: usize = 1_500_000;
/// Management canister chunk limit is 1 MiB.
const UPLOAD_CHUNK_BYTES: usize = 1024 * 1024;

/// Claims one pre-created canister for `request_id`.
///
/// Idempotent and fully synchronous: the `request_id -> canister` binding is
/// committed together with the reply, so a caller that never sees the response
/// recovers the same canister by replaying the call or reading the receipt. It
/// never creates a canister, which is why a lost management-canister create can
/// only ever waste an unpaid pool canister.
#[ic_cdk::update(guard = "is_provisioner")]
fn reserve_canister(req: ReserveRequest) -> Result<ReservationReceipt, String> {
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::provision::validate_epoch(req.expires_at, now_ms)?;
    store::provision::reserve(now_ms, &req)
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

    let (canister, wasm, expected, controllers) =
        match store::provision::begin_install(now_ms, &req)? {
            store::provision::InstallPlan::AlreadyInstalled(receipt) => return Ok(*receipt),
            store::provision::InstallPlan::Install {
                canister,
                wasm,
                expected_module_hash,
                controllers,
            } => (canister, wasm, expected_module_hash, controllers),
        };

    match install_exact(
        canister,
        mgt::CanisterInstallMode::Install,
        wasm,
        req.init_args.to_vec(),
        expected,
        &controllers,
    )
    .await
    {
        Ok(module_hash) => {
            let now_ms = ic_cdk::api::time() / MILLISECONDS;
            let receipt = store::provision::finish_install(&req.request_id, module_hash, now_ms)?;
            let artifact_hash = receipt.artifact_hash;
            let log_id = store::wasm::add_log(store::DeployLog {
                name: receipt.wasm_name.clone(),
                deploy_at: now_ms,
                canister,
                prev_hash: Default::default(),
                wasm_hash: artifact_hash,
                args: req.init_args,
                error: None,
            })?;
            store::state::with_mut(|s| {
                s.deployed_list.insert(canister, (log_id, artifact_hash));
            });
            Ok(receipt)
        }
        Err(err) => {
            let now_ms = ic_cdk::api::time() / MILLISECONDS;
            store::provision::fail_install(&req.request_id, err.clone(), now_ms);
            Err(err)
        }
    }
}

/// Upgrades an already deployed canister to an exact module.
///
/// Compare-and-swaps on `expected_prev_module_hash`, so a stale request can
/// never overwrite a module the caller did not expect to be running, and the
/// result is verified against `expected_module_hash`.
#[ic_cdk::update(guard = "is_provisioner")]
async fn ensure_deployment(req: DeploymentRequest) -> Result<ProvisionReceipt, String> {
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::provision::validate_epoch(req.expires_at, now_ms)?;
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

    let wasm = store::wasm::get_wasm(&req.artifact_hash).ok_or_else(|| {
        format!(
            "NotFound: artifact {} not found",
            hex::encode(req.artifact_hash.as_ref())
        )
    })?;
    if wasm.name != req.wasm_name {
        return Err(format!(
            "artifact belongs to wasm {}, not {}",
            wasm.name, req.wasm_name
        ));
    }

    if let Some(receipt) = store::provision::begin_deployment(
        now_ms,
        &req.request_id,
        req.canister,
        &req.wasm_name,
        req.artifact_hash,
        req.expected_module_hash,
        req.expected_prev_module_hash,
        req.args_hash,
    )? {
        return Ok(receipt);
    }

    match upgrade_exact(&req, wasm).await {
        Ok(module_hash) => {
            let now_ms = ic_cdk::api::time() / MILLISECONDS;
            let receipt = store::provision::finish_install(&req.request_id, module_hash, now_ms)?;
            let log_id = store::wasm::add_log(store::DeployLog {
                name: req.wasm_name,
                deploy_at: now_ms,
                canister: req.canister,
                prev_hash: req.expected_prev_module_hash,
                wasm_hash: req.artifact_hash,
                args: req.args,
                error: None,
            })?;
            store::state::with_mut(|s| {
                s.deployed_list
                    .insert(req.canister, (log_id, req.artifact_hash));
            });
            Ok(receipt)
        }
        Err(err) => {
            let now_ms = ic_cdk::api::time() / MILLISECONDS;
            store::provision::fail_install(&req.request_id, err.clone(), now_ms);
            Err(err)
        }
    }
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
    let expected = store::provision::expected_controllers(&request_id)?;
    let (module_hash, controllers) = inspect_canister(canister).await?;
    if module_hash.is_some() {
        return Err("canister is not empty and cannot be released".to_string());
    }
    store::provision::assert_controllers(&controllers, &expected)?;

    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::provision::release(now_ms, &request_id, canister)
}

/// The durable outcome of a `request_id`, readable after any lost response.
#[ic_cdk::query]
fn get_provision_receipt(request_id: ByteArray<32>) -> Result<ProvisionReceipt, String> {
    store::provision::get_receipt(&request_id)
        .ok_or_else(|| "NotFound: provision request not found".to_string())
}

// ----- helpers -----

/// Reads the module hash and controllers the management canister reports.
async fn inspect_canister(
    canister: Principal,
) -> Result<(Option<ByteArray<32>>, Vec<Principal>), String> {
    let status = mgt::canister_status(&mgt::CanisterStatusArgs {
        canister_id: canister,
    })
    .await
    .map_err(format_error)?;
    let module_hash = match status.module_hash {
        Some(h) => {
            let h: [u8; 32] = h
                .try_into()
                .map_err(|_| "module_hash is not 32 bytes".to_string())?;
            Some(ByteArray::from(h))
        }
        None => None,
    };
    Ok((module_hash, status.settings.controllers))
}

/// Installs onto an empty canister and returns the resulting module hash.
///
/// A retry whose first attempt succeeded but lost its response finds the
/// expected module already running and converges instead of failing.
async fn install_exact(
    canister: Principal,
    mode: mgt::CanisterInstallMode,
    wasm: store::Wasm,
    arg: Vec<u8>,
    expected: ByteArray<32>,
    controllers: &[Principal],
) -> Result<ByteArray<32>, String> {
    let (module_hash, actual_controllers) = inspect_canister(canister).await?;
    // a reserved canister whose controllers drifted is no longer the canister
    // the template approved, so it must not receive the install
    store::provision::assert_controllers(&actual_controllers, controllers)?;
    match module_hash {
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

    install_module(canister, mode, wasm.wasm.into_vec(), arg).await?;
    assert_module_hash(canister, expected).await
}

async fn upgrade_exact(
    req: &DeploymentRequest,
    wasm: store::Wasm,
) -> Result<ByteArray<32>, String> {
    let current = inspect_canister(req.canister).await?.0;
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

    install_module(
        req.canister,
        mgt::CanisterInstallMode::Upgrade(None),
        wasm.wasm.into_vec(),
        req.args.to_vec(),
    )
    .await?;
    assert_module_hash(req.canister, req.expected_module_hash).await
}

async fn assert_module_hash(
    canister: Principal,
    expected: ByteArray<32>,
) -> Result<ByteArray<32>, String> {
    let actual = inspect_canister(canister)
        .await?
        .0
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

/// Installs a module, falling back to the chunk store for artifacts too large
/// for a single inter-canister message.
async fn install_module(
    canister: Principal,
    mode: mgt::CanisterInstallMode,
    wasm_module: Vec<u8>,
    arg: Vec<u8>,
) -> Result<(), String> {
    if wasm_module.len() <= MAX_DIRECT_INSTALL_BYTES {
        return mgt::install_code(&mgt::InstallCodeArgs {
            mode,
            canister_id: canister,
            wasm_module,
            arg,
        })
        .await
        .map_err(format_error);
    }

    let wasm_module_hash = sha256(&wasm_module).to_vec();
    let args = mgt::ClearChunkStoreArgs {
        canister_id: canister,
    };
    mgt::clear_chunk_store(&args).await.map_err(format_error)?;

    let mut chunk_hashes_list = Vec::with_capacity(wasm_module.len() / UPLOAD_CHUNK_BYTES + 1);
    for chunk in wasm_module.chunks(UPLOAD_CHUNK_BYTES) {
        let hash = mgt::upload_chunk(&mgt::UploadChunkArgs {
            canister_id: canister,
            chunk: chunk.to_vec(),
        })
        .await
        .map_err(format_error)?;
        chunk_hashes_list.push(hash);
    }

    let rt = mgt::install_chunked_code(&mgt::InstallChunkedCodeArgs {
        mode,
        target_canister: canister,
        store_canister: None,
        chunk_hashes_list,
        wasm_module_hash,
        arg,
    })
    .await
    .map_err(format_error);
    // the staged chunks are only needed for the install itself
    let _ = mgt::clear_chunk_store(&args).await;
    rt
}
