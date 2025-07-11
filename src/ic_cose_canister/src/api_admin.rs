use candid::{pretty::candid::value::pp_value, CandidType, IDLValue, Principal};
use ic_cose_types::validate_principals;
use ic_cose_types::{
    types::namespace::{CreateNamespaceInput, NamespaceInfo},
    MILLISECONDS,
};
use std::collections::BTreeSet;

use crate::{is_controller, store};

#[ic_cdk::update(guard = "is_controller")]
fn admin_add_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|s| {
        s.managers.extend(args);
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|s| {
        s.managers.retain(|v| !args.contains(v));
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_add_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|s| {
        s.auditors.extend(args);
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|s| {
        s.auditors.retain(|v| !args.contains(v));
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_add_allowed_apis(args: BTreeSet<String>) -> Result<(), String> {
    store::state::with_mut(|s| {
        s.allowed_apis.extend(args);
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_allowed_apis(args: BTreeSet<String>) -> Result<(), String> {
    store::state::with_mut(|s| {
        s.allowed_apis.retain(|v| !args.contains(v));
        Ok(())
    })
}

#[ic_cdk::update]
async fn admin_create_namespace(args: CreateNamespaceInput) -> Result<NamespaceInfo, String> {
    store::state::allowed_api("admin_create_namespace")?;
    args.validate()?;

    let caller = ic_cdk::api::msg_caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::create_namespace(&caller, args, now_ms).await
}

#[ic_cdk::query]
fn admin_list_namespace(
    prev: Option<String>,
    take: Option<u32>,
) -> Result<Vec<NamespaceInfo>, String> {
    let caller = ic_cdk::api::msg_caller();
    let take = take.unwrap_or(10).min(100);
    store::state::with(|s| {
        if !s.managers.contains(&caller) && !s.auditors.contains(&caller) {
            Err("no permission".to_string())?;
        }

        let namespaces = store::ns::list_namespaces(prev, take as usize);
        Ok(namespaces)
    })
}

// ----- Use validate2_xxxxxx instead of validate_xxxxxx -----

#[ic_cdk::update]
fn validate_admin_add_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update]
fn validate2_admin_add_managers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update]
fn validate_admin_remove_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update]
fn validate2_admin_remove_managers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update]
fn validate_admin_add_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update]
fn validate2_admin_add_auditors(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update]
fn validate_admin_remove_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update]
fn validate2_admin_remove_auditors(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    pretty_format(&args)
}

#[ic_cdk::update]
fn validate_admin_add_allowed_apis(_args: BTreeSet<String>) -> Result<(), String> {
    Ok(())
}

#[ic_cdk::update]
fn validate2_admin_add_allowed_apis(args: BTreeSet<String>) -> Result<String, String> {
    pretty_format(&args)
}

#[ic_cdk::update]
fn validate_admin_remove_allowed_apis(_args: BTreeSet<String>) -> Result<(), String> {
    Ok(())
}

#[ic_cdk::update]
fn validate2_admin_remove_allowed_apis(args: BTreeSet<String>) -> Result<String, String> {
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
