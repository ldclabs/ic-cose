use candid::Principal;
use ic_cdk::api::management_canister::main::*;
use ic_cose_types::{
    format_error,
    types::wasm::{AddWasmInput, DeployWasmInput},
};
use serde_bytes::{ByteArray, ByteBuf};
use std::collections::BTreeSet;

use crate::{
    create_canister_on, is_controller, is_controller_or_manager,
    is_controller_or_manager_or_committer, store, validate_principals, MILLISECONDS,
};

// encoded candid arguments: ()
// println!("{:?}", candid::utils::encode_args(()).unwrap());
static EMPTY_CANDID_ARGS: &[u8] = &[68, 73, 68, 76, 0, 0];

#[ic_cdk::update(guard = "is_controller")]
fn admin_add_managers(mut args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        r.managers.append(&mut args);
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
fn admin_add_committers(mut args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        r.committers.append(&mut args);
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
    Ok("ok".to_string())
}

#[ic_cdk::update]
fn validate_admin_remove_managers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    Ok("ok".to_string())
}

#[ic_cdk::update]
fn validate_admin_add_committers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    Ok("ok".to_string())
}

#[ic_cdk::update]
fn validate_admin_remove_committers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    Ok("ok".to_string())
}

#[ic_cdk::update(guard = "is_controller_or_manager_or_committer")]
async fn admin_add_wasm(
    args: AddWasmInput,
    force_prev_hash: Option<ByteArray<32>>,
) -> Result<(), String> {
    store::wasm::add_wasm(
        ic_cdk::caller(),
        ic_cdk::api::time() / MILLISECONDS,
        args,
        force_prev_hash,
        false,
    )
}

#[ic_cdk::update]
async fn validate_admin_add_wasm(
    args: AddWasmInput,
    force_prev_hash: Option<ByteArray<32>>,
) -> Result<String, String> {
    store::wasm::add_wasm(
        ic_cdk::caller(),
        ic_cdk::api::time() / MILLISECONDS,
        args,
        force_prev_hash,
        true,
    )?;
    Ok("ok".to_string())
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_create_canister(
    wasm_name: String,
    settings: Option<CanisterSettings>,
    args: Option<ByteBuf>,
) -> Result<Principal, String> {
    let self_id = ic_cdk::id();
    let mut settings = settings.unwrap_or_default();
    let controllers = settings.controllers.get_or_insert_with(Default::default);
    if !controllers.contains(&self_id) {
        controllers.push(self_id);
    }

    let (hash, wasm) = store::wasm::get_latest(&wasm_name)?;
    let res = create_canister(
        CreateCanisterArgument {
            settings: Some(settings),
        },
        2_000_000_000_000,
    )
    .await
    .map_err(format_error)?;
    let canister_id = res.0.canister_id;

    let arg = args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    let res = install_code(InstallCodeArgument {
        mode: CanisterInstallMode::Install,
        canister_id,
        wasm_module: wasm.wasm.into_vec(),
        arg: arg.clone().into_vec(),
    })
    .await
    .map_err(format_error);

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
    Ok(canister_id)
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_create_on(
    subnet: Principal,
    wasm_name: String,
    settings: Option<CanisterSettings>,
    args: Option<ByteBuf>,
) -> Result<Principal, String> {
    let self_id = ic_cdk::id();
    let mut settings = settings.unwrap_or_default();
    let controllers = settings.controllers.get_or_insert_with(Default::default);
    if !controllers.contains(&self_id) {
        controllers.push(self_id);
    }

    let (hash, wasm) = store::wasm::get_latest(&wasm_name)?;
    let canister_id = create_canister_on(subnet, Some(settings), 2_000_000_000_000)
        .await
        .map_err(format_error)?;
    let arg = args.unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    let res = install_code(InstallCodeArgument {
        mode: CanisterInstallMode::Install,
        canister_id,
        wasm_module: wasm.wasm.into_vec(),
        arg: arg.clone().into_vec(),
    })
    .await
    .map_err(format_error);

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
    Ok(canister_id)
}

#[ic_cdk::update]
fn validate_admin_create_canister(
    wasm_name: String,
    _settings: Option<CanisterSettings>,
    _args: Option<ByteBuf>,
) -> Result<String, String> {
    let _ = store::wasm::get_latest(&wasm_name)?;
    Ok("ok".to_string())
}

#[ic_cdk::update]
fn validate_admin_create_on(
    _subnet: Principal,
    wasm_name: String,
    _settings: Option<CanisterSettings>,
    _args: Option<ByteBuf>,
) -> Result<String, String> {
    let _ = store::wasm::get_latest(&wasm_name)?;
    Ok("ok".to_string())
}

#[ic_cdk::update(guard = "is_controller")]
async fn admin_deploy(
    args: DeployWasmInput,
    ignore_prev_hash: Option<ByteArray<32>>,
) -> Result<(), String> {
    let (info,) = canister_info(CanisterInfoRequest {
        canister_id: args.canister,
        num_requested_changes: None,
    })
    .await
    .map_err(format_error)?;
    let id = ic_cdk::id();
    if !info.controllers.contains(&id) {
        Err(format!(
            "{} is not a controller of the canister {}",
            id.to_text(),
            args.canister.to_text()
        ))?;
    }

    let mode = if info.module_hash.is_none() {
        CanisterInstallMode::Install
    } else {
        CanisterInstallMode::Upgrade(None)
    };

    let prev_hash: [u8; 32] = if let Some(hash) = info.module_hash {
        hash.try_into().map_err(format_error)?
    } else {
        Default::default()
    };
    let prev_hash = ByteArray::from(prev_hash);
    let (hash, wasm) = if let Some(ignore_prev_hash) = ignore_prev_hash {
        if ignore_prev_hash != prev_hash {
            Err(format!(
                "prev_hash mismatch: {} != {}",
                const_hex::encode(prev_hash.as_ref()),
                const_hex::encode(ignore_prev_hash.as_ref())
            ))?;
        }
        store::wasm::get_latest(&args.name)?
    } else {
        store::wasm::next_version(prev_hash)?
    };

    let arg = args
        .args
        .unwrap_or_else(|| ByteBuf::from(EMPTY_CANDID_ARGS));
    let res = install_code(InstallCodeArgument {
        mode,
        canister_id: args.canister,
        wasm_module: wasm.wasm.into_vec(),
        arg: arg.clone().into_vec(),
    })
    .await
    .map_err(format_error);

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
    let (info,) = canister_info(CanisterInfoRequest {
        canister_id: args.canister,
        num_requested_changes: None,
    })
    .await
    .map_err(format_error)?;
    let id = ic_cdk::id();
    if !info.controllers.contains(&id) {
        Err(format!(
            "{} is not a controller of the canister {}",
            id.to_text(),
            args.canister.to_text()
        ))?;
    }

    let prev_hash: [u8; 32] = if let Some(hash) = info.module_hash {
        hash.try_into().map_err(format_error)?
    } else {
        Default::default()
    };
    let prev_hash = ByteArray::from(prev_hash);
    if let Some(ignore_prev_hash) = ignore_prev_hash {
        if ignore_prev_hash != prev_hash {
            Err(format!(
                "prev_hash mismatch: {} != {}",
                const_hex::encode(prev_hash.as_ref()),
                const_hex::encode(ignore_prev_hash.as_ref())
            ))?;
        }
        let hash = store::state::with(|s| {
            s.latest_version
                .get(&args.name)
                .cloned()
                .unwrap_or_default()
        });
        let _ = store::wasm::get_wasm(&hash)
            .ok_or_else(|| format!("wasm not found: {}", const_hex::encode(hash.as_ref())))?;
    } else {
        store::wasm::next_version(prev_hash)?;
    }

    Ok("ok".to_string())
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
        let data = ic_cdk::api::call::call_raw(id, &method, &args, 0)
            .await
            .map_err(format_error)?;
        res.push(ByteBuf::from(data));
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
        let res = futures::future::try_join_all(ids.iter().map(|id| async {
            let balance = ic_cdk::api::canister_balance128();
            if balance < threshold + amount {
                Err(format!(
                    "balance {} is less than threshold {} + amount {}",
                    balance, threshold, amount
                ))?;
            }

            let arg = CanisterIdRecord { canister_id: *id };
            let (status,) = canister_status(arg).await.map_err(format_error)?;
            if status.cycles <= threshold {
                deposit_cycles(arg, amount).await.map_err(format_error)?;
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
async fn admin_update_canister_settings(args: UpdateSettingsArgument) -> Result<(), String> {
    store::state::with(|s| {
        if !s.deployed_list.contains_key(&args.canister_id) {
            return Err("canister not found".to_string());
        }
        Ok(())
    })?;
    update_settings(args).await.map_err(format_error)?;
    Ok(())
}

#[ic_cdk::update]
async fn validate_admin_batch_call(
    _canisters: BTreeSet<Principal>,
    _method: String,
    _args: Option<ByteBuf>,
) -> Result<String, String> {
    Ok("ok".to_string())
}

#[ic_cdk::update]
async fn validate_admin_batch_topup() -> Result<String, String> {
    Ok("ok".to_string())
}

#[ic_cdk::update]
async fn validate_admin_update_canister_settings(
    args: UpdateSettingsArgument,
) -> Result<String, String> {
    store::state::with(|s| {
        if !s.deployed_list.contains_key(&args.canister_id) {
            return Err("canister not found".to_string());
        }
        Ok(())
    })?;
    Ok("ok".to_string())
}
