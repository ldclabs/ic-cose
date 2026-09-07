use candid::{Nat, Principal};
use ic_cdk_management_canister as mgt;
use ic_cose_types::{
    format_error,
    types::wasm::{
        AddWasmInput, BatchCallResult, CommitWasmChunksInput, DeployWasmInput, ProvisionSettings,
        ProvisionTemplate, ProvisionTemplateInfo, TopupResult,
    },
};
use serde_bytes::{ByteArray, ByteBuf};
use std::collections::BTreeSet;
use std::fmt::Debug;

use crate::{
    create_canister_on, create_pool_canister, extend_role_set, is_controller,
    is_controller_or_manager, is_controller_or_manager_or_committer, management, store,
    validate_principals, CreateOutcome, MILLISECONDS,
};

// encoded candid arguments: ()
// println!("{:?}", candid::utils::encode_args(()).unwrap());
static EMPTY_CANDID_ARGS: &[u8] = &[68, 73, 68, 76, 0, 0];
/// Cycles attached to legacy admin canister creation, including the subnet's
/// creation fee.
const DEFAULT_CREATION_BUDGET: u128 = 2_000_000_000_000;
const MAX_TARGET_CONTROLLERS: usize = 10;

// Only controller-authorized adoption may undo an explicit handoff/forget.
// Receipt repair deliberately uses commit_deployment without lifting the barrier.
fn commit_admin_deployment(log: store::DeployLog) -> Result<u64, String> {
    let canister = log.canister;
    let log_id = store::wasm::commit_deployment(log)?;
    store::state::resume_management(&canister);
    Ok(log_id)
}

fn required_template_controllers() -> BTreeSet<Principal> {
    let mut required = BTreeSet::from([ic_cdk::api::canister_self()]);
    if let Some(governance) = store::state::with(|s| s.governance_canister) {
        required.insert(governance);
    }
    required
}

fn validate_template_for_canister(template: &ProvisionTemplate) -> Result<(), String> {
    store::provision::validate_template(template, &required_template_controllers())?;
    if template.subnet.is_none() {
        let fee = ic_cdk::api::cost_create_canister();
        if template.initial_cycles < fee {
            return Err(format!(
                "initial_cycles {} is below the local subnet creation fee {}",
                template.initial_cycles, fee
            ));
        }
    }
    Ok(())
}

async fn validate_reconcile_candidate(
    template_id: &str,
    found: Option<Principal>,
) -> Result<(), String> {
    ic_cose_types::validate_str(template_id)?;
    store::provision::validate_reconcile_pool(template_id, found)?;
    if let Some(canister) = found {
        let template = store::provision::get_template(template_id)
            .ok_or_else(|| format!("NotFound: provision template {} not found", template_id))?;
        let info = management::canister_info(canister).await?;
        if info.module_hash.is_some() {
            return Err("reconciled pool canister is not empty".to_string());
        }
        store::provision::assert_controllers(
            &info.controllers,
            &template.template.settings.controllers,
        )?;
    }
    Ok(())
}

fn validate_target_creation_settings(
    settings: Option<&mgt::CanisterSettings>,
) -> Result<(), String> {
    let Some(controllers) = settings.and_then(|settings| settings.controllers.as_ref()) else {
        return Ok(());
    };
    if controllers.contains(&Principal::anonymous()) {
        return Err("anonymous target controller is not allowed".to_string());
    }
    if controllers.len() > MAX_TARGET_CONTROLLERS {
        return Err(format!(
            "target controllers exceed the limit {MAX_TARGET_CONTROLLERS}"
        ));
    }
    let unique: BTreeSet<_> = controllers.iter().collect();
    if unique.len() != controllers.len() {
        return Err("target controllers must be unique".to_string());
    }
    if !controllers.contains(&ic_cdk::api::canister_self())
        && controllers.len() >= MAX_TARGET_CONTROLLERS
    {
        return Err("cannot add this canister to a full controllers list".to_string());
    }
    Ok(())
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_add_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    store::state::ensure_memory_available()?;
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        extend_role_set(&mut r.managers, args, "managers")?;
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
    store::state::ensure_memory_available()?;
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        extend_role_set(&mut r.committers, args, "committers")?;
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

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_add_managers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_remove_managers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_add_committers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_remove_committers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update(guard = "is_controller_or_manager_or_committer")]
fn admin_add_wasm(
    args: AddWasmInput,
    force_prev_hash: Option<ByteArray<32>>,
) -> Result<(), String> {
    store::state::ensure_memory_available()?;
    store::wasm::add_wasm(
        ic_cdk::api::msg_caller(),
        ic_cdk::api::time() / MILLISECONDS,
        args,
        force_prev_hash,
        None,
    )
    .map(|_| ())
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_wasm(hash: ByteArray<32>) -> Result<(), String> {
    store::wasm::remove_wasm(&hash)
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_add_wasm(
    args: AddWasmInput,
    force_prev_hash: Option<ByteArray<32>>,
) -> Result<String, String> {
    let artifact_hash = store::wasm::validate_wasm(&args, force_prev_hash)?;
    pretty_format(&(
        &args.name,
        &args.description,
        args.encoding,
        args.wasm.len(),
        hex::encode(artifact_hash.as_ref()),
        &force_prev_hash,
    ))
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_remove_wasm(hash: ByteArray<32>) -> Result<String, String> {
    store::wasm::validate_remove_wasm(&hash)?;
    pretty_format(&hex::encode(hash.as_ref()))
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
    store::state::ensure_memory_available()?;
    ic_cose_types::validate_str(&wasm_name)?;
    if subnet == Some(Principal::anonymous()) {
        return Err("subnet must not be anonymous".to_string());
    }
    let self_id = ic_cdk::api::canister_self();
    let mut settings = settings.unwrap_or_default();
    validate_target_creation_settings(Some(&settings))?;
    let controllers = settings.controllers.get_or_insert_with(Default::default);
    if !controllers.contains(&self_id) {
        controllers.push(self_id);
    }

    let (hash, wasm) = store::wasm::get_latest_metadata(&wasm_name)?;
    let expected_module_hash = wasm.module_hash;
    let arg = args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    if arg.len() > 1_500_000 {
        return Err("install arguments exceed 1.5 MB".to_string());
    }
    let canister_id = match subnet {
        Some(subnet) => create_canister_on(subnet, Some(settings), DEFAULT_CREATION_BUDGET).await?,
        None => management::create_canister(settings, DEFAULT_CREATION_BUDGET)
            .await
            .map_err(format_error)?,
    };
    let attempt = ic_cdk::api::time() / MILLISECONDS;
    store::state::acquire_operation(canister_id, hash, attempt, attempt).map_err(|err| {
        format!(
            "canister {} was created, but its install lock failed: {}",
            canister_id.to_text(),
            err
        )
    })?;
    let res = async {
        management::install_stored_code(canister_id, mgt::CanisterInstallMode::Install, hash, &arg)
            .await?;
        let actual = management::canister_info(canister_id)
            .await?
            .module_hash
            .ok_or_else(|| "canister reports no module after install".to_string())?;
        if actual != expected_module_hash {
            return Err("installed module hash does not match the stored artifact".to_string());
        }
        Ok(actual)
    }
    .await;

    let log = store::DeployLog::new(store::DeployLogInput {
        name: wasm_name,
        deploy_at: ic_cdk::api::time() / MILLISECONDS,
        canister: canister_id,
        prev_hash: Default::default(),
        artifact_hash: hash,
        module_hash: res.as_ref().ok().copied(),
        args: &arg,
        error: res.clone().err(),
    });
    let record_result = if res.is_ok() {
        commit_admin_deployment(log).map(|_| ())
    } else {
        store::wasm::add_log(log).map(|_| ())
    };
    store::state::release_operation(canister_id, &hash, attempt);
    if let Err(record_error) = record_result {
        return Err(format!(
            "canister {} was created, but recording its install outcome failed: {}; reconcile it explicitly",
            canister_id.to_text(), record_error
        ));
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

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_create_canister(
    wasm_name: String,
    settings: Option<mgt::CanisterSettings>,
    args: Option<ByteBuf>,
) -> Result<String, String> {
    ic_cose_types::validate_str(&wasm_name)?;
    let _ = store::wasm::get_latest_metadata(&wasm_name)?;
    validate_target_creation_settings(settings.as_ref())?;
    let args = args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    if args.len() > 1_500_000 {
        return Err("install arguments exceed 1.5 MB".to_string());
    }
    pretty_format(&(
        &wasm_name,
        &settings,
        args.len(),
        hex::encode(ic_cose_types::cose::sha256(&args)),
    ))
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_create_on(
    subnet: Principal,
    wasm_name: String,
    settings: Option<mgt::CanisterSettings>,
    args: Option<ByteBuf>,
) -> Result<String, String> {
    ic_cose_types::validate_str(&wasm_name)?;
    if subnet == Principal::anonymous() {
        return Err("subnet must not be anonymous".to_string());
    }
    let _ = store::wasm::get_latest_metadata(&wasm_name)?;
    validate_target_creation_settings(settings.as_ref())?;
    let args = args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    if args.len() > 1_500_000 {
        return Err("install arguments exceed 1.5 MB".to_string());
    }
    pretty_format(&(
        &subnet,
        &wasm_name,
        &settings,
        args.len(),
        hex::encode(ic_cose_types::cose::sha256(&args)),
    ))
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_deploy(
    args: DeployWasmInput,
    ignore_prev_hash: Option<ByteArray<32>>,
) -> Result<(), String> {
    store::state::ensure_memory_available()?;
    let expected_prev_hash = ignore_prev_hash.ok_or_else(|| {
        "admin_deploy requires the expected previous module hash; use ensure_deployment for idempotent upgrades"
            .to_string()
    })?;
    let canister = args.canister;
    let name = args.name;
    ic_cose_types::validate_str(&name)?;
    let (hash, wasm) = store::wasm::get_latest_metadata(&name)?;
    let arg = args
        .args
        .unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    if arg.len() > 1_500_000 {
        return Err("upgrade arguments exceed 1.5 MB".to_string());
    }
    let expected_module_hash = wasm.module_hash;
    let attempt = ic_cdk::api::time() / MILLISECONDS;
    store::state::acquire_operation(canister, hash, attempt, attempt)?;
    let mut observed_prev_hash = ByteArray::from([0u8; 32]);
    let res = async {
        let info = management::canister_info(canister).await?;
        let id = ic_cdk::api::canister_self();
        if !info.controllers.contains(&id) {
            return Err(format!(
                "{} is not a controller of the canister {}",
                id.to_text(),
                canister.to_text()
            ));
        }
        observed_prev_hash = info.module_hash.unwrap_or_default();
        if expected_prev_hash != observed_prev_hash {
            return Err(format!(
                "prev_hash mismatch: {} != {}",
                hex::encode(observed_prev_hash.as_ref()),
                hex::encode(expected_prev_hash.as_ref())
            ));
        }
        let mode = if info.module_hash.is_none() {
            mgt::CanisterInstallMode::Install
        } else {
            mgt::CanisterInstallMode::Upgrade(None)
        };
        management::install_stored_code(canister, mode, hash, &arg).await?;
        let actual = management::canister_info(canister)
            .await?
            .module_hash
            .ok_or_else(|| "canister reports no module after install".to_string())?;
        if actual != expected_module_hash {
            return Err("installed module hash does not match the stored artifact".to_string());
        }
        Ok(actual)
    }
    .await;

    let log = store::DeployLog::new(store::DeployLogInput {
        name,
        deploy_at: ic_cdk::api::time() / MILLISECONDS,
        canister,
        prev_hash: observed_prev_hash,
        artifact_hash: hash,
        module_hash: res.as_ref().ok().copied(),
        args: &arg,
        error: res.clone().err(),
    });
    let record_result = if res.is_ok() {
        commit_admin_deployment(log).map(|_| ())
    } else {
        store::wasm::add_log(log).map(|_| ())
    };
    store::state::release_operation(canister, &hash, attempt);
    if let Err(record_error) = record_result {
        return if res.is_ok() {
            Err(format!(
                "deployment landed on canister {}, but its audit record failed: {}; run admin_reconcile_deployment",
                canister.to_text(), record_error
            ))
        } else {
            Err(format!(
                "{}; additionally failed to append the audit log: {}",
                res.expect_err("the error branch was checked"),
                record_error
            ))
        };
    }
    res.map(|_| ())
}

/// Repairs the deployment index after a successful target install whose local
/// callback could not append its log. The target's live module hash is checked
/// against repository metadata before any record is written.
#[ic_cdk::update(guard = "is_controller")]
async fn admin_reconcile_deployment(
    canister: Principal,
    wasm_name: String,
    artifact_hash: ByteArray<32>,
) -> Result<(), String> {
    ic_cose_types::validate_str(&wasm_name)?;
    let metadata = store::wasm::get_metadata(&artifact_hash)?;
    if metadata.name != wasm_name {
        return Err("artifact belongs to another wasm name".to_string());
    }
    let attempt = ic_cdk::api::time() / MILLISECONDS;
    store::state::acquire_operation(canister, artifact_hash, attempt, attempt)?;
    let result = async {
        let info = management::canister_info(canister).await?;
        if !info.controllers.contains(&ic_cdk::api::canister_self()) {
            return Err("this canister is not a target controller".to_string());
        }
        if info.module_hash != Some(metadata.module_hash) {
            return Err("target module hash does not match the artifact".to_string());
        }
        if store::state::deployed(&canister).is_some_and(|deployment| {
            deployment.artifact_hash == artifact_hash
                && deployment.module_hash == metadata.module_hash
                && deployment.wasm_name == wasm_name
        }) {
            store::state::resume_management(&canister);
            return Ok(());
        }
        let previous = store::state::deployed(&canister)
            .map(|deployment| deployment.module_hash)
            .unwrap_or_default();
        commit_admin_deployment(store::DeployLog {
            name: wasm_name,
            deploy_at: ic_cdk::api::time() / MILLISECONDS,
            canister,
            prev_hash: previous,
            wasm_hash: artifact_hash,
            module_hash: Some(metadata.module_hash),
            args: ByteBuf::new(),
            args_hash: None,
            args_size: 0,
            error: None,
        })?;
        Ok(())
    }
    .await;
    store::state::release_operation(canister, &artifact_hash, attempt);
    result
}

#[ic_cdk::update(guard = "is_controller")]
async fn validate_admin_deploy(
    args: DeployWasmInput,
    ignore_prev_hash: Option<ByteArray<32>>,
) -> Result<String, String> {
    ic_cose_types::validate_str(&args.name)?;
    let args_ = args
        .args
        .as_ref()
        .map_or(EMPTY_CANDID_ARGS, |value| value.as_slice());
    if args_.len() > 1_500_000 {
        return Err("upgrade arguments exceed 1.5 MB".to_string());
    }
    let rt = pretty_format(&(
        &args.name,
        &args.canister,
        args_.len(),
        hex::encode(ic_cose_types::cose::sha256(args_)),
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
    let expected_prev_hash = ignore_prev_hash.ok_or_else(|| {
        "admin_deploy requires the expected previous module hash; use ensure_deployment for idempotent upgrades"
            .to_string()
    })?;
    if expected_prev_hash != prev_hash {
        return Err(format!(
            "prev_hash mismatch: {} != {}",
            hex::encode(prev_hash.as_ref()),
            hex::encode(expected_prev_hash.as_ref())
        ));
    }
    store::wasm::get_latest_metadata(&args.name)?;

    Ok(rt)
}

fn deployed_targets(canisters: BTreeSet<Principal>) -> Result<Vec<Principal>, String> {
    let ids = if canisters.is_empty() {
        store::state::deployed_canisters_page(None, 101)
    } else {
        for id in &canisters {
            if store::state::deployed(id).is_none() {
                return Err(format!("canister {} is not deployed", id));
            }
        }
        canisters.into_iter().collect()
    };
    if ids.len() > 100 {
        return Err("batch operations are limited to 100 canisters".to_string());
    }
    if ids.iter().any(store::state::operation_active) {
        return Err("a target canister has a deployment in flight".to_string());
    }
    Ok(ids)
}

fn validate_batch_input(method: &str, args: &[u8]) -> Result<(), String> {
    if method.is_empty() || method.len() > 128 {
        return Err("method length should be in 1..=128".to_string());
    }
    if args.len() > 256 * 1024 {
        return Err("batch call arguments exceed 256 KiB".to_string());
    }
    Ok(())
}

fn bounded_error(mut value: String) -> String {
    const MAX_ERROR_BYTES: usize = 4 * 1024;
    if value.len() <= MAX_ERROR_BYTES {
        return value;
    }
    let mut end = MAX_ERROR_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push_str("…[truncated]");
    value
}

async fn batch_call_results(
    canisters: BTreeSet<Principal>,
    method: String,
    args: Option<ByteBuf>,
) -> Result<Vec<BatchCallResult>, String> {
    store::state::ensure_memory_available()?;
    let ids = deployed_targets(canisters)?;
    let args = args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    validate_batch_input(&method, &args)?;
    let token = ByteArray::from([0xfc; 32]);
    let attempt = ic_cdk::api::time() / MILLISECONDS;
    let mut locked = Vec::with_capacity(ids.len());
    for id in &ids {
        if let Err(err) = store::state::acquire_operation(*id, token, attempt, attempt) {
            for acquired in locked {
                store::state::release_operation(acquired, &token, attempt);
            }
            return Err(err);
        }
        locked.push(*id);
    }
    let result = async {
        let mut results = Vec::with_capacity(ids.len());
        let mut response_bytes = 0usize;
        for id in ids {
            match ic_cdk::call::Call::unbounded_wait(id, &method)
                .with_raw_args(&args)
                .await
            {
                Ok(data) => {
                    let bytes = data.into_bytes();
                    if bytes.len() > 64 * 1024
                        || response_bytes.saturating_add(bytes.len()) > 1_500_000
                    {
                        results.push(BatchCallResult {
                            canister: id,
                            reply: None,
                            error: Some("reply exceeds the batch response limit".to_string()),
                        });
                    } else {
                        response_bytes = response_bytes.saturating_add(bytes.len());
                        results.push(BatchCallResult {
                            canister: id,
                            reply: Some(ByteBuf::from(bytes)),
                            error: None,
                        });
                    }
                }
                Err(err) => results.push(BatchCallResult {
                    canister: id,
                    reply: None,
                    error: Some(bounded_error(format_error(err))),
                }),
            }
        }
        Ok(results)
    }
    .await;
    for id in locked {
        store::state::release_operation(id, &token, attempt);
    }
    result
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_batch_call(
    canisters: BTreeSet<Principal>,
    method: String,
    args: Option<ByteBuf>,
) -> Result<Vec<ByteBuf>, String> {
    let results = batch_call_results(canisters, method, args).await?;
    if results.iter().any(|result| result.error.is_some()) {
        let failures = results
            .iter()
            .filter_map(|result| {
                result
                    .error
                    .as_ref()
                    .map(|error| format!("{}: {error}", result.canister))
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("batch call completed with failures: {failures}"));
    }
    Ok(results
        .into_iter()
        .filter_map(|result| result.reply)
        .collect())
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_batch_call_v2(
    canisters: BTreeSet<Principal>,
    method: String,
    args: Option<ByteBuf>,
) -> Result<Vec<BatchCallResult>, String> {
    batch_call_results(canisters, method, args).await
}

async fn batch_topup_results(
    prev: Option<Principal>,
    take: usize,
) -> Result<Vec<TopupResult>, String> {
    store::state::ensure_memory_available()?;
    store::state::begin_topup()?;
    let result = async {
        let (threshold, amount) = store::state::with(|s| (s.topup_threshold, s.topup_amount));
        let canisters = store::state::deployed_canisters_page(prev, take);
        if threshold == 0 || amount == 0 {
            return Err("canister topup is disabled".to_string());
        }
        if amount <= threshold {
            return Err("topup_amount must exceed topup_threshold".to_string());
        }
        if canisters.is_empty() {
            return Err("no canister deployed".to_string());
        }
        if canisters.len() > 100 {
            return Err("more than 100 deployed canisters; use admin_batch_topup_page".to_string());
        }

        let mut results = Vec::with_capacity(canisters.len());
        for ids in canisters.chunks(7) {
            let chunk = futures::future::join_all(ids.iter().map(|id| async move {
                match management::cycle_balance(*id).await {
                    Ok(cycles) => TopupResult {
                        canister: *id,
                        balance_before: Some(cycles),
                        deposited: 0,
                        error: None,
                    },
                    Err(err) => TopupResult {
                        canister: *id,
                        balance_before: None,
                        deposited: 0,
                        error: Some(bounded_error(err)),
                    },
                }
            }))
            .await;
            results.extend(chunk);
        }

        let needs_topup: Vec<usize> = results
            .iter()
            .enumerate()
            .filter_map(|(index, result)| {
                result
                    .balance_before
                    .is_some_and(|cycles| cycles <= threshold)
                    .then_some(index)
            })
            .collect();
        if needs_topup.is_empty() {
            return Ok(results);
        }
        let balance = ic_cdk::api::canister_liquid_cycle_balance();
        let required = threshold
            .checked_add(
                amount
                    .checked_mul(needs_topup.len() as u128)
                    .ok_or_else(|| "top-up amount overflowed".to_string())?,
            )
            .ok_or_else(|| "top-up reserve overflowed".to_string())?;
        if balance < required {
            return Err(format!(
                "liquid balance {} is less than reserve {} + amount {} x {}",
                balance,
                threshold,
                amount,
                needs_topup.len()
            ));
        }

        for indexes in needs_topup.chunks(7) {
            let deposits = futures::future::join_all(indexes.iter().map(|index| {
                let canister = results[*index].canister;
                async move {
                    let arg = mgt::CanisterStatusArgs {
                        canister_id: canister,
                    };
                    (canister, mgt::deposit_cycles(&arg, amount).await)
                }
            }))
            .await;
            for (index, (canister, outcome)) in indexes.iter().zip(deposits) {
                debug_assert_eq!(results[*index].canister, canister);
                match outcome {
                    Ok(()) => results[*index].deposited = amount,
                    Err(err) => results[*index].error = Some(bounded_error(format_error(err))),
                }
            }
        }
        Ok(results)
    }
    .await;
    store::state::end_topup();
    result
}

#[ic_cdk::update(guard = "is_controller_or_manager")]
async fn admin_batch_topup() -> Result<u128, String> {
    let results = batch_topup_results(None, 101).await?;
    let total = results.iter().map(|result| result.deposited).sum();
    if results.iter().any(|result| result.error.is_some()) {
        let failures = results
            .iter()
            .filter_map(|result| {
                result
                    .error
                    .as_ref()
                    .map(|error| format!("{}: {error}", result.canister))
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "top-up completed with {total} cycles deposited and failures: {failures}"
        ));
    }
    Ok(total)
}

#[ic_cdk::update(guard = "is_controller_or_manager")]
async fn admin_batch_topup_v2() -> Result<Vec<TopupResult>, String> {
    batch_topup_results(None, 101).await
}

#[ic_cdk::update(guard = "is_controller_or_manager")]
async fn admin_batch_topup_page(
    prev: Option<Principal>,
    take: Option<u32>,
) -> Result<Vec<TopupResult>, String> {
    batch_topup_results(prev, take.unwrap_or(100).clamp(1, 100) as usize).await
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_update_canister_settings(args: mgt::UpdateSettingsArgs) -> Result<(), String> {
    if store::state::deployed(&args.canister_id).is_none() {
        return Err("NotFound: canister not found".to_string());
    }
    if store::state::operation_active(&args.canister_id) {
        return Err("a deployment is in flight for this canister".to_string());
    }
    if let Some(controllers) = args.settings.controllers.as_ref() {
        if !controllers.contains(&ic_cdk::api::canister_self()) {
            return Err(
                "refusing to remove the wasm canister from target controllers; use an explicit handoff flow"
                    .to_string(),
            );
        }
        let unique: BTreeSet<_> = controllers.iter().collect();
        if unique.len() != controllers.len() || controllers.contains(&Principal::anonymous()) {
            return Err("controllers must be unique and non-anonymous".to_string());
        }
        if controllers.len() > MAX_TARGET_CONTROLLERS {
            return Err(format!(
                "controllers exceed the limit {MAX_TARGET_CONTROLLERS}"
            ));
        }
    }
    let token = ByteArray::from([0xfe; 32]);
    let attempt = ic_cdk::api::time() / MILLISECONDS;
    store::state::acquire_operation(args.canister_id, token, attempt, attempt)?;
    let result = mgt::update_settings(&args).await.map_err(format_error);
    store::state::release_operation(args.canister_id, &token, attempt);
    result
}

/// Explicitly transfers target control away from this canister and removes the
/// target from the managed deployment index after the settings call succeeds.
#[ic_cdk::update(guard = "is_controller")]
async fn admin_handoff_canister(args: mgt::UpdateSettingsArgs) -> Result<(), String> {
    if store::state::deployed(&args.canister_id).is_none() {
        return Err("NotFound: canister not found".to_string());
    }
    if store::state::operation_active(&args.canister_id) {
        return Err("a deployment is in flight for this canister".to_string());
    }
    let controllers = args
        .settings
        .controllers
        .as_ref()
        .ok_or_else(|| "handoff requires an explicit controllers list".to_string())?;
    if controllers.is_empty()
        || controllers.contains(&Principal::anonymous())
        || controllers.contains(&ic_cdk::api::canister_self())
    {
        return Err(
            "handoff controllers must be non-empty, non-anonymous, and exclude this canister"
                .to_string(),
        );
    }
    let unique: BTreeSet<_> = controllers.iter().collect();
    if unique.len() != controllers.len() {
        return Err("handoff controllers must be unique".to_string());
    }
    if controllers.len() > MAX_TARGET_CONTROLLERS {
        return Err(format!(
            "handoff controllers exceed the limit {MAX_TARGET_CONTROLLERS}"
        ));
    }
    let canister = args.canister_id;
    let token = ByteArray::from([0xfd; 32]);
    let attempt = ic_cdk::api::time() / MILLISECONDS;
    store::state::acquire_operation(canister, token, attempt, attempt)?;
    let result = mgt::update_settings(&args).await.map_err(format_error);
    if result.is_ok() {
        store::state::forget_deployment(&canister);
    }
    store::state::release_operation(canister, &token, attempt);
    result
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_forget_deployment(canister: Principal) -> Result<bool, String> {
    if store::state::operation_active(&canister) {
        return Err("a deployment is in flight for this canister".to_string());
    }
    Ok(store::state::forget_deployment(&canister))
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_batch_call(
    canisters: BTreeSet<Principal>,
    method: String,
    args: Option<ByteBuf>,
) -> Result<String, String> {
    let _ = deployed_targets(canisters.clone())?;
    let args = args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    validate_batch_input(&method, &args)?;
    pretty_format(&(
        &canisters,
        &method,
        args.len(),
        hex::encode(ic_cose_types::cose::sha256(&args)),
    ))
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_batch_topup() -> Result<String, String> {
    let (threshold, amount) = store::state::with(|s| (s.topup_threshold, s.topup_amount));
    if threshold == 0 || amount == 0 {
        return Err("canister topup is disabled".to_string());
    }
    if amount <= threshold {
        return Err("topup_amount must exceed topup_threshold".to_string());
    }
    if store::state::deployed_canisters_page(None, 1).is_empty() {
        return Err("no canister deployed".to_string());
    }
    pretty_format(&(threshold, amount))
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_update_canister_settings(
    args: mgt::UpdateSettingsArgs,
) -> Result<String, String> {
    if store::state::deployed(&args.canister_id).is_none() {
        return Err("NotFound: canister not found".to_string());
    }
    if store::state::operation_active(&args.canister_id) {
        return Err("a deployment is in flight for this canister".to_string());
    }
    if let Some(controllers) = args.settings.controllers.as_ref() {
        if !controllers.contains(&ic_cdk::api::canister_self()) {
            return Err("controller handoff requires the explicit handoff flow".to_string());
        }
        let unique: BTreeSet<_> = controllers.iter().collect();
        if unique.len() != controllers.len() || controllers.contains(&Principal::anonymous()) {
            return Err("controllers must be unique and non-anonymous".to_string());
        }
        if controllers.len() > MAX_TARGET_CONTROLLERS {
            return Err(format!(
                "controllers exceed the limit {MAX_TARGET_CONTROLLERS}"
            ));
        }
    }
    pretty_format(&args)
}

fn pretty_format<T>(data: &T) -> Result<String, String>
where
    T: Debug,
{
    let value = format!("{data:#?}");
    if value.len() > 16 * 1024 {
        return Err("validation summary exceeds 16 KiB".to_string());
    }
    Ok(value)
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
    store::state::ensure_memory_available()?;
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        extend_role_set(&mut r.provisioners, args, "provisioners")?;
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

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_add_provisioners(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update(guard = "is_controller")]
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
    store::state::ensure_memory_available()?;
    validate_template_for_canister(&args)?;
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::provision::add_template(
        ic_cdk::api::msg_caller(),
        now_ms,
        args,
        &required_template_controllers(),
    )
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_provision_template(id: String) -> Result<(), String> {
    store::provision::remove_template(&id)
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_add_provision_template(args: ProvisionTemplate) -> Result<String, String> {
    validate_template_for_canister(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_remove_provision_template(id: String) -> Result<String, String> {
    store::provision::validate_remove_template(&id)?;
    pretty_format(&id)
}

/// Creates one more canister for a template's pool.
///
/// Deliberately separate from any paid flow: creation is the one step whose
/// response loss cannot be recovered, so it may only ever waste an unpaid pool
/// canister. An unknown outcome circuit-breaks further refills.
#[ic_cdk::update(guard = "is_controller_or_manager")]
async fn admin_refill_pool(template_id: String) -> Result<Principal, String> {
    store::state::ensure_memory_available()?;
    let template = store::provision::begin_pool_create(&template_id)?;
    let settings = to_canister_settings(&template.settings);

    match create_pool_canister(template.subnet, settings, template.initial_cycles).await {
        CreateOutcome::Created(canister) => {
            let now_ms = ic_cdk::api::time() / MILLISECONDS;
            if let Err(err) = store::provision::finish_pool_create(&template_id, canister, now_ms) {
                store::provision::fail_pool_create(&template_id, true);
                return Err(format!(
                    "canister {} was created but could not be recorded; reconcile it explicitly: {}",
                    canister.to_text(),
                    err
                ));
            }
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
async fn admin_reconcile_pool(template_id: String, found: Option<Principal>) -> Result<(), String> {
    if found.is_some() {
        store::state::ensure_memory_available()?;
    }
    validate_reconcile_candidate(&template_id, found).await?;
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::provision::reconcile_pool(&template_id, found, now_ms)?;
    if let Some(canister) = found {
        store::state::resume_management(&canister);
    }
    Ok(())
}

#[ic_cdk::update(guard = "is_controller")]
async fn validate_admin_reconcile_pool(
    template_id: String,
    found: Option<Principal>,
) -> Result<String, String> {
    validate_reconcile_candidate(&template_id, found).await?;
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
    store::state::ensure_memory_available()?;
    store::provision::add_chunk(ic_cdk::api::msg_caller(), chunk.into_vec())
}

/// Assembles the caller's staged chunks into one artifact and publishes it.
#[ic_cdk::update(guard = "is_controller_or_manager_or_committer")]
fn admin_commit_wasm_chunks(
    args: CommitWasmChunksInput,
    force_prev_hash: Option<ByteArray<32>>,
) -> Result<ByteArray<32>, String> {
    store::state::ensure_memory_available()?;
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

#[ic_cdk::update(guard = "is_controller")]
fn admin_clear_wasm_chunks_for(uploader: Principal) -> Result<u64, String> {
    Ok(store::provision::clear_chunks(uploader))
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_clear_low_wasm_memory() -> Result<(), String> {
    store::state::set_low_wasm_memory(false);
    Ok(())
}

/// Incrementally builds the per-wasm deployment-log index for records written
/// by versions that only maintained the global stable log.
#[ic_cdk::update(guard = "is_controller_or_manager")]
fn admin_rebuild_log_index(start: u64, take: u32) -> Result<u64, String> {
    store::state::ensure_memory_available()?;
    store::wasm::rebuild_log_index(start, take.clamp(1, 100) as usize)
}

/// Migrates one legacy monolithic artifact into the chunked stable layout.
#[ic_cdk::update(guard = "is_controller_or_manager")]
fn admin_migrate_legacy_wasm_artifact(hash: ByteArray<32>) -> Result<bool, String> {
    store::state::ensure_memory_available()?;
    store::wasm::migrate_legacy_artifact(&hash)
}

/// Compacts old successful request receipts into permanent request-id
/// tombstones. Callers should retain receipts externally before archiving.
#[ic_cdk::update(guard = "is_controller")]
fn admin_archive_completed_requests(before_ms: u64, take: u32) -> Result<u64, String> {
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    if before_ms > now_ms.saturating_sub(30 * 24 * 3600 * 1000) {
        return Err("completed requests must be retained for at least 30 days".to_string());
    }
    Ok(store::provision::archive_completed_requests(
        before_ms,
        take.clamp(1, 1_000) as usize,
    ))
}

#[cfg(test)]
mod tests {
    use super::bounded_error;

    #[test]
    fn batch_errors_are_utf8_safe_and_bounded() {
        assert_eq!(bounded_error("short".to_string()), "short");
        let value = bounded_error("界".repeat(2_000));
        assert!(value.is_char_boundary(value.len()));
        assert!(value.len() < 4 * 1024 + 32);
        assert!(value.ends_with("[truncated]"));
    }
}
