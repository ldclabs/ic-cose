use candid::Principal;
use ic_cose_types::validate_principals;
use ic_cose_types::{
    types::namespace::{CreateNamespaceInput, NamespaceInfo},
    MILLISECONDS,
};
use std::collections::BTreeSet;

use crate::{is_controller, store};

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
fn admin_add_auditors(mut args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        r.auditors.append(&mut args);
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|r| {
        r.auditors.retain(|p| !args.contains(p));
        Ok(())
    })
}

#[ic_cdk::update]
async fn admin_create_namespace(args: CreateNamespaceInput) -> Result<NamespaceInfo, String> {
    args.validate()?;

    let caller = ic_cdk::caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::create_namespace(&caller, args, now_ms).await
}

#[ic_cdk::query]
fn admin_list_namespace(
    prev: Option<String>,
    take: Option<u32>,
) -> Result<Vec<NamespaceInfo>, String> {
    let caller = ic_cdk::caller();
    let take = take.unwrap_or(10).min(100);
    store::state::with(|s| {
        if !s.managers.contains(&caller) && !s.auditors.contains(&caller) {
            Err("no permission".to_string())?;
        }

        let namespaces = store::ns::list_namespaces(prev, take as usize);
        Ok(namespaces)
    })
}

#[ic_cdk::update]
fn validate_admin_add_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update]
fn validate_admin_remove_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update]
fn validate_admin_add_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update]
fn validate_admin_remove_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}
