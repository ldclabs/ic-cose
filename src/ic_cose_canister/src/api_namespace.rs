use candid::Principal;
use ic_cose_types::{
    types::{namespace::*, state::StateInfo},
    validate_principals, MILLISECONDS,
};
use std::collections::BTreeSet;

use crate::{is_authenticated, store};

#[ic_cdk::query]
fn state_get_info() -> Result<StateInfo, String> {
    store::state::with(|s| {
        let mut info = s.to_info();
        info.namespace_total = store::ns::namespace_count();
        Ok(info)
    })
}

#[ic_cdk::query]
fn namespace_get_info(namespace: String) -> Result<NamespaceInfo, String> {
    let caller = ic_cdk::caller();
    store::ns::get_namespace(&caller, namespace)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_update_info(args: UpdateNamespaceInput) -> Result<(), String> {
    args.validate()?;

    let caller = ic_cdk::caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::update_namespace_info(&caller, args, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_add_managers(namespace: String, mut args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;

    let caller = ic_cdk::caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::with_mut(&namespace, |ns| {
        if !ns.can_write_namespace(&caller) {
            Err("no permission".to_string())?;
        }
        ns.managers.append(&mut args);
        ns.updated_at = now_ms;
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_remove_managers(namespace: String, args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;

    let caller = ic_cdk::caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::with_mut(&namespace, |ns| {
        if !ns.can_write_namespace(&caller) {
            Err("no permission".to_string())?;
        }
        ns.managers.retain(|p| !args.contains(p));
        ns.updated_at = now_ms;
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_add_auditors(namespace: String, mut args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;

    let caller = ic_cdk::caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::with_mut(&namespace, |ns| {
        if !ns.can_write_namespace(&caller) {
            Err("no permission".to_string())?;
        }
        ns.auditors.append(&mut args);
        ns.updated_at = now_ms;
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_remove_auditors(namespace: String, args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;

    let caller = ic_cdk::caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::with_mut(&namespace, |ns| {
        if !ns.can_write_namespace(&caller) {
            Err("no permission".to_string())?;
        }
        ns.auditors.retain(|p| !args.contains(p));
        ns.updated_at = now_ms;
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_add_users(namespace: String, mut args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;

    let caller = ic_cdk::caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::with_mut(&namespace, |ns| {
        if !ns.can_write_namespace(&caller) {
            Err("no permission".to_string())?;
        }
        ns.users.append(&mut args);
        ns.updated_at = now_ms;
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_remove_users(namespace: String, args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;

    let caller = ic_cdk::caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::with_mut(&namespace, |ns| {
        if !ns.can_write_namespace(&caller) {
            Err("no permission".to_string())?;
        }
        ns.users.retain(|p| !args.contains(p));
        ns.updated_at = now_ms;
        Ok(())
    })
}

const MIN_CYCLES: u128 = 1_000_000_000_000;

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_top_up(namespace: String, cycles: u128) -> Result<u128, String> {
    if cycles < MIN_CYCLES {
        Err("cycles should be greater than 1T".to_string())?;
    }
    if cycles > ic_cdk::api::call::msg_cycles_available128() {
        Err("insufficient cycles".to_string())?;
    }

    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::with_mut(&namespace, |ns| {
        let received = ic_cdk::api::call::msg_cycles_accept128(cycles);
        ns.gas_balance = ns.gas_balance.saturating_add(received);
        ns.updated_at = now_ms;
        Ok(received)
    })
}
