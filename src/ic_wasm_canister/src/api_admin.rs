use candid::{pretty::candid::value::pp_value, CandidType, IDLArgs, IDLValue, Nat, Principal};
use ic_cdk_management_canister as mgt;
use ic_cose_types::{
    format_error,
    types::wasm::{
        AddWasmInput, CommitWasmChunksInput, DeployWasmInput, ProvisionSettings, ProvisionTemplate,
        ProvisionTemplateInfo,
    },
};
use serde_bytes::{ByteArray, ByteBuf};
use std::collections::BTreeSet;

use crate::{
    create_canister_on, create_pool_canister, is_controller, is_controller_or_manager,
    is_controller_or_manager_or_committer, management, store, validate_principals, CreateOutcome,
    MILLISECONDS,
};

// encoded candid arguments: ()
// println!("{:?}", candid::utils::encode_args(()).unwrap());
static EMPTY_CANDID_ARGS: &[u8] = &[68, 73, 68, 76, 0, 0];
/// Cycles attached to legacy admin canister creation, including the subnet's
/// creation fee.
const DEFAULT_CREATION_BUDGET: u128 = 2_000_000_000_000;

#[ic_cdk::update(guard = "is_controller")]
fn admin_add_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        r.managers.extend(args);
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        r.managers.retain(|p| !args.contains(p));
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_add_committers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        r.committers.extend(args);
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_committers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        r.committers.retain(|p| !args.contains(p));
        Ok(())
    })
}

#[ic_cdk::update]
fn validate_admin_add_managers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update]
fn validate_admin_remove_managers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update]
fn validate_admin_add_committers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update]
fn validate_admin_remove_committers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update(guard = "is_controller_or_manager_or_committer")]
fn admin_add_wasm(
    args: AddWasmInput,
    force_prev_hash: Option<ByteArray<32>>,
) -> Result<(), String> {
    store::wasm::add_wasm(
        ic_cdk::api::msg_caller(),
        ic_cdk::api::time() / MILLISECONDS,
        args,
        force_prev_hash,
        None,
    )
    .map(|_| ())
}

#[ic_cdk::update]
fn validate_admin_add_wasm(
    args: AddWasmInput,
    force_prev_hash: Option<ByteArray<32>>,
) -> Result<String, String> {
    let rt = pretty_format(&(&args.name, &args.description, &force_prev_hash))?;
    store::wasm::validate_wasm(&args, force_prev_hash)?;

    Ok(rt)
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_create_canister(
    wasm_name: String,
    settings: Option<mgt::CanisterSettings>,
    args: Option<ByteBuf>,
) -> Result<Principal, String> {
    create_and_install(None, wasm_name, settings, args).await
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_create_on(
    subnet: Principal,
    wasm_name: String,
    settings: Option<mgt::CanisterSettings>,
    args: Option<ByteBuf>,
) -> Result<Principal, String> {
    create_and_install(Some(subnet), wasm_name, settings, args).await
}

async fn create_and_install(
    subnet: Option<Principal>,
    wasm_name: String,
    settings: Option<mgt::CanisterSettings>,
    args: Option<ByteBuf>,
) -> Result<Principal, String> {
    let self_id = ic_cdk::api::canister_self();
    let mut settings = settings.unwrap_or_default();
    let controllers = settings.controllers.get_or_insert_with(Default::default);
    if !controllers.contains(&self_id) {
        controllers.push(self_id);
    }

    let (hash, wasm) = store::wasm::get_latest(&wasm_name)?;
    let canister_id = match subnet {
        Some(subnet) => create_canister_on(subnet, Some(settings), DEFAULT_CREATION_BUDGET).await?,
        None => management::create_canister(settings, DEFAULT_CREATION_BUDGET)
            .await
            .map_err(format_error)?,
    };
    let arg = args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    let res = management::install_code(
        canister_id,
        mgt::CanisterInstallMode::Install,
        &wasm.wasm,
        hash,
        &arg,
    )
    .await;

    let id = store::wasm::add_log(store::DeployLog {
        name: wasm_name,
        deploy_at: ic_cdk::api::time() / MILLISECONDS,
        canister: canister_id,
        prev_hash: Default::default(),
        wasm_hash: hash,
        args: arg,
        error: res.clone().err(),
    })?;

    if res.is_ok() {
        store::state::with_mut(|s| {
            s.deployed_list.insert(canister_id, (id, hash));
        })
    }
    // the canister exists either way: report the failure, but keep its id in the
    // error so the caller can retry the install instead of losing track of it.
    res.map_err(|err| {
        format!(
            "canister {} created, but install failed: {}",
            canister_id.to_text(),
            err
        )
    })?;
    Ok(canister_id)
}

#[ic_cdk::update]
fn validate_admin_create_canister(
    wasm_name: String,
    settings: Option<mgt::CanisterSettings>,
    args: Option<ByteBuf>,
) -> Result<String, String> {
    let _ = store::wasm::get_latest(&wasm_name)?;
    let args = IDLArgs::from_bytes(&args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS)))
        .map_err(|err| format!("Invalid args: {err}"))?;
    pretty_format(&(&wasm_name, &settings, &args.to_string()))
}

#[ic_cdk::update]
fn validate_admin_create_on(
    subnet: Principal,
    wasm_name: String,
    settings: Option<mgt::CanisterSettings>,
    args: Option<ByteBuf>,
) -> Result<String, String> {
    let _ = store::wasm::get_latest(&wasm_name)?;
    let args = IDLArgs::from_bytes(&args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS)))
        .map_err(|err| format!("Invalid args: {err}"))?;
    pretty_format(&(&subnet, &wasm_name, &settings, &args.to_string()))
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_deploy(
    args: DeployWasmInput,
    ignore_prev_hash: Option<ByteArray<32>>,
) -> Result<(), String> {
    let info = management::canister_info(args.canister).await?;
    let id = ic_cdk::api::canister_self();
    if !info.controllers.contains(&id) {
        Err(format!(
            "{} is not a controller of the canister {}",
            id.to_text(),
            args.canister.to_text()
        ))?;
    }

    let mode = if info.module_hash.is_none() {
        mgt::CanisterInstallMode::Install
    } else {
        mgt::CanisterInstallMode::Upgrade(None)
    };

    let prev_hash = info.module_hash.unwrap_or_default();
    let (hash, wasm) = if let Some(ignore_prev_hash) = ignore_prev_hash {
        if ignore_prev_hash != prev_hash {
            Err(format!(
                "prev_hash mismatch: {} != {}",
                hex::encode(prev_hash.as_ref()),
                hex::encode(ignore_prev_hash.as_ref())
            ))?;
        }
        store::wasm::get_latest(&args.name)?
    } else {
        store::wasm::next_version(&args.name, prev_hash)?
    };

    let arg = args
        .args
        .unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    let res = management::install_code(args.canister, mode, &wasm.wasm, hash, &arg).await;

    let id = store::wasm::add_log(store::DeployLog {
        name: args.name,
        deploy_at: ic_cdk::api::time() / MILLISECONDS,
        canister: args.canister,
        prev_hash,
        wasm_hash: hash,
        args: arg,
        error: res.clone().err(),
    })?;

    if res.is_ok() {
        store::state::with_mut(|s| {
            s.deployed_list.insert(args.canister, (id, hash));
        })
    }
    res
}

#[ic_cdk::update]
async fn validate_admin_deploy(
    args: DeployWasmInput,
    ignore_prev_hash: Option<ByteArray<32>>,
) -> Result<String, String> {
    let args_ = IDLArgs::from_bytes(
        &args
            .args
            .unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS)),
    )
    .map_err(|err| format!("Invalid args: {err}"))?;
    let rt = pretty_format(&(
        &args.name,
        &args.canister,
        &args_.to_string(),
        &ignore_prev_hash,
    ))?;
    let info = management::canister_info(args.canister).await?;
    let id = ic_cdk::api::canister_self();
    if !info.controllers.contains(&id) {
        Err(format!(
            "{} is not a controller of the canister {}",
            id.to_text(),
            args.canister.to_text()
        ))?;
    }

    let prev_hash = info.module_hash.unwrap_or_default();
    if let Some(ignore_prev_hash) = ignore_prev_hash {
        if ignore_prev_hash != prev_hash {
            Err(format!(
                "prev_hash mismatch: {} != {}",
                hex::encode(prev_hash.as_ref()),
                hex::encode(ignore_prev_hash.as_ref())
            ))?;
        }
        // mirror admin_deploy: an unknown name must report the name, not a
        // "wasm not found: 000...0" for the default hash.
        store::wasm::get_latest(&args.name)?;
    } else {
        store::wasm::next_version(&args.name, prev_hash)?;
    }

    Ok(rt)
}

#[ic_cdk::update(guard = "is_controller_or_manager")]
async fn admin_batch_call(
    canisters: BTreeSet<Principal>,
    method: String,
    args: Option<ByteBuf>,
) -> Result<Vec<ByteBuf>, String> {
    let ids = store::state::with(|s| {
        for id in &canisters {
            if !s.deployed_list.contains_key(id) {
                return Err(format!("canister {} is not deployed", id));
            }
        }
        if canisters.is_empty() {
            Ok(s.deployed_list.keys().cloned().collect())
        } else {
            Ok(canisters)
        }
    })?;

    let args = args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    let mut res = Vec::with_capacity(ids.len());
    for id in ids {
        let data = ic_cdk::call::Call::bounded_wait(id, &method)
            .with_raw_args(&args)
            .await
            .map_err(format_error)?;
        res.push(ByteBuf::from(data.into_bytes()));
    }

    Ok(res)
}

#[ic_cdk::update(guard = "is_controller_or_manager")]
async fn admin_batch_topup() -> Result<u128, String> {
    let (threshold, amount, canisters) = store::state::with(|s| {
        (
            s.topup_threshold,
            s.topup_amount,
            s.deployed_list.keys().cloned().collect::<Vec<_>>(),
        )
    });

    if threshold == 0 || amount == 0 {
        Err("canister topup is disabled".to_string())?;
    }
    if canisters.is_empty() {
        Err("no canister deployed".to_string())?;
    }

    let mut total = 0u128;
    for ids in canisters.chunks(7) {
        // the whole chunk runs concurrently and the balance does not drop until
        // the deposits settle, so every canister in it must be covered up front:
        // checking `threshold + amount` once per future would let a chunk deposit
        // up to `ids.len()` times what the guard allows.
        let balance = ic_cdk::api::canister_cycle_balance();
        let required = threshold.saturating_add(amount.saturating_mul(ids.len() as u128));
        if balance < required {
            Err(format!(
                "balance {} is less than threshold {} + amount {} x {}",
                balance,
                threshold,
                amount,
                ids.len()
            ))?;
        }

        let res = futures::future::try_join_all(ids.iter().map(|id| async {
            let arg = mgt::CanisterStatusArgs { canister_id: *id };
            let cycles = management::cycle_balance(*id).await?;
            if cycles <= threshold {
                mgt::deposit_cycles(&arg, amount)
                    .await
                    .map_err(format_error)?;
                return Ok::<u128, String>(amount);
            }
            Ok::<u128, String>(0)
        }))
        .await?;
        total += res.iter().sum::<u128>();
    }

    Ok(total)
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_update_canister_settings(args: mgt::UpdateSettingsArgs) -> Result<(), String> {
    store::state::with(|s| {
        if !s.deployed_list.contains_key(&args.canister_id) {
            return Err("NotFound: canister not found".to_string());
        }
        Ok(())
    })?;
    mgt::update_settings(&args).await.map_err(format_error)?;
    Ok(())
}

#[ic_cdk::update]
fn validate_admin_batch_call(
    canisters: BTreeSet<Principal>,
    method: String,
    args: Option<ByteBuf>,
) -> Result<String, String> {
    let args = IDLArgs::from_bytes(&args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS)))
        .map_err(|err| format!("Invalid args: {err}"))?;
    pretty_format(&(&canisters, &method, &args.to_string()))
}

#[ic_cdk::update]
fn validate_admin_batch_topup() -> Result<String, String> {
    Ok("ok".to_string())
}

#[ic_cdk::update]
fn validate_admin_update_canister_settings(
    args: mgt::UpdateSettingsArgs,
) -> Result<String, String> {
    store::state::with(|s| {
        if !s.deployed_list.contains_key(&args.canister_id) {
            return Err("NotFound: canister not found".to_string());
        }
        Ok(())
    })?;
    pretty_format(&args)
}

fn pretty_format<T>(data: &T) -> Result<String, String>
where
    T: CandidType,
{
    let val = IDLValue::try_from_candid_type(data).map_err(|err| format!("{err:?}"))?;
    let doc = pp_value(7, &val);

    Ok(format!("{}", doc.pretty(120)))
}

// ----- provisioning: governance-approved templates, roles and pool -----

/// Grants the least-privilege provisioning role.
///
/// A provisioner may only reserve, install and release canisters from approved
/// templates; it cannot manage roles, publish modules or deploy an arbitrary
/// wasm, so this can be granted to another canister without handing over the
/// repository.
#[ic_cdk::update(guard = "is_controller")]
fn admin_add_provisioners(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        r.provisioners.extend(args);
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_provisioners(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        r.provisioners.retain(|p| !args.contains(p));
        Ok(())
    })
}

#[ic_cdk::update]
fn validate_admin_add_provisioners(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update]
fn validate_admin_remove_provisioners(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

/// Approves an immutable provisioning template.
///
/// This is the governance act that fixes which module, settings, controllers,
/// subnet and creation budget a provisioned canister gets: a provisioner can
/// afterwards only name the template by id and hash.
#[ic_cdk::update(guard = "is_controller")]
fn admin_add_provision_template(args: ProvisionTemplate) -> Result<ProvisionTemplateInfo, String> {
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::provision::add_template(ic_cdk::api::msg_caller(), now_ms, args)
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_provision_template(id: String) -> Result<(), String> {
    store::provision::remove_template(&id)
}

#[ic_cdk::update]
fn validate_admin_add_provision_template(args: ProvisionTemplate) -> Result<String, String> {
    args.validate()?;
    pretty_format(&args)
}

#[ic_cdk::update]
fn validate_admin_remove_provision_template(id: String) -> Result<String, String> {
    store::provision::get_template(&id)
        .ok_or_else(|| format!("NotFound: provision template {} not found", id))?;
    pretty_format(&id)
}

/// Creates one more canister for a template's pool.
///
/// Deliberately separate from any paid flow: creation is the one step whose
/// response loss cannot be recovered, so it may only ever waste an unpaid pool
/// canister. An unknown outcome circuit-breaks further refills.
#[ic_cdk::update(guard = "is_controller_or_manager")]
async fn admin_refill_pool(template_id: String) -> Result<Principal, String> {
    let template = store::provision::begin_pool_create(&template_id)?;
    let settings = to_canister_settings(&template.settings);

    match create_pool_canister(template.subnet, settings, template.initial_cycles).await {
        CreateOutcome::Created(canister) => {
            let now_ms = ic_cdk::api::time() / MILLISECONDS;
            store::provision::finish_pool_create(&template_id, canister, now_ms)?;
            Ok(canister)
        }
        CreateOutcome::Refunded(err) => {
            store::provision::fail_pool_create(&template_id, false);
            Err(format!("pool create created no canister: {}", err))
        }
        CreateOutcome::Unknown(err) => {
            store::provision::fail_pool_create(&template_id, true);
            Err(format!(
                "pool create returned an unknown outcome; refill is circuit-broken \
                 until governance reconciles: {}",
                err
            ))
        }
    }
}

/// Clears a `CreateUnknown` breaker after governance has looked for the canister
/// a lost create may have produced.
///
/// `found` adopts that canister into the pool; `None` records the create as lost.
#[ic_cdk::update(guard = "is_controller")]
fn admin_reconcile_pool(template_id: String, found: Option<Principal>) -> Result<(), String> {
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::provision::reconcile_pool(&template_id, found, now_ms)
}

#[ic_cdk::update]
fn validate_admin_reconcile_pool(
    template_id: String,
    found: Option<Principal>,
) -> Result<String, String> {
    store::provision::get_template(&template_id)
        .ok_or_else(|| format!("NotFound: provision template {} not found", template_id))?;
    pretty_format(&(&template_id, &found))
}

fn to_canister_settings(settings: &ProvisionSettings) -> mgt::CanisterSettings {
    mgt::CanisterSettings {
        controllers: Some(settings.controllers.clone()),
        compute_allocation: settings.compute_allocation.map(Nat::from),
        memory_allocation: settings.memory_allocation.map(Nat::from),
        freezing_threshold: settings.freezing_threshold.map(Nat::from),
        reserved_cycles_limit: settings.reserved_cycles_limit.map(Nat::from),
        wasm_memory_limit: settings.wasm_memory_limit.map(Nat::from),
        log_visibility: None,
        wasm_memory_threshold: None,
        log_memory_limit: None,
        environment_variables: None,
    }
}

// ----- chunked artifact upload -----

/// Stages one chunk of a wasm artifact for the caller.
///
/// Publishing a module larger than the 2 MiB ingress limit is impossible in a
/// single `admin_add_wasm` call; chunks are staged here and assembled by
/// `admin_commit_wasm_chunks`.
#[ic_cdk::update(guard = "is_controller_or_manager_or_committer")]
fn admin_add_wasm_chunk(chunk: ByteBuf) -> Result<ByteArray<32>, String> {
    store::provision::add_chunk(ic_cdk::api::msg_caller(), chunk.into_vec())
}

/// Assembles the caller's staged chunks into one artifact and publishes it.
#[ic_cdk::update(guard = "is_controller_or_manager_or_committer")]
fn admin_commit_wasm_chunks(
    args: CommitWasmChunksInput,
    force_prev_hash: Option<ByteArray<32>>,
) -> Result<ByteArray<32>, String> {
    let caller = ic_cdk::api::msg_caller();
    let wasm = store::provision::take_chunks(caller, &args.chunk_hashes)?;
    let hash = store::wasm::add_wasm(
        caller,
        ic_cdk::api::time() / MILLISECONDS,
        AddWasmInput {
            name: args.name,
            description: args.description,
            wasm: ByteBuf::from(wasm),
            encoding: args.encoding,
        },
        force_prev_hash,
        Some(args.artifact_hash),
    )?;
    store::provision::clear_chunks(caller);
    Ok(hash)
}

/// Drops the caller's staged chunks, e.g. after an abandoned upload.
#[ic_cdk::update(guard = "is_controller_or_manager_or_committer")]
fn admin_clear_wasm_chunks() -> Result<u64, String> {
    Ok(store::provision::clear_chunks(ic_cdk::api::msg_caller()))
}
