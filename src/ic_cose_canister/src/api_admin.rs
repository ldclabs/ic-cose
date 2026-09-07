use candid::Principal;
use ic_cose_types::validate_principals;
use ic_cose_types::{
    types::namespace::{CreateNamespaceInput, NamespaceInfo},
    MILLISECONDS,
};
use std::collections::BTreeSet;
use std::fmt::Write;

use crate::{extend_set_bounded, is_controller, is_controller_or_manager, remove_set_items, store};

const MAX_ALLOWED_APIS: usize = 256;

fn validate_allowed_apis(values: &BTreeSet<String>) -> Result<(), String> {
    if values.is_empty() {
        return Err("APIs cannot be empty".to_string());
    }
    if values.len() > MAX_ALLOWED_APIS {
        return Err(format!("APIs count exceeds the limit {MAX_ALLOWED_APIS}"));
    }
    for value in values {
        ic_cose_types::validate_str(value)?;
    }
    Ok(())
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_add_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    store::state::ensure_memory_available()?;
    validate_principals(&args)?;
    store::state::with_mut(|s| {
        extend_set_bounded(
            &mut s.managers,
            args,
            ic_cose_types::MAX_PRINCIPALS_PER_SET,
            "managers",
        )?;
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|s| {
        remove_set_items(&mut s.managers, args);
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_add_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    store::state::ensure_memory_available()?;
    validate_principals(&args)?;
    store::state::with_mut(|s| {
        extend_set_bounded(
            &mut s.auditors,
            args,
            ic_cose_types::MAX_PRINCIPALS_PER_SET,
            "auditors",
        )?;
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    store::state::with_mut(|s| {
        remove_set_items(&mut s.auditors, args);
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_add_allowed_apis(args: BTreeSet<String>) -> Result<(), String> {
    store::state::ensure_memory_available()?;
    validate_allowed_apis(&args)?;
    store::state::with_mut(|s| {
        extend_set_bounded(&mut s.allowed_apis, args, MAX_ALLOWED_APIS, "allowed APIs")?;
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_remove_allowed_apis(args: BTreeSet<String>) -> Result<(), String> {
    validate_allowed_apis(&args)?;
    store::state::with_mut(|s| {
        remove_set_items(&mut s.allowed_apis, args);
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_controller_or_manager")]
fn admin_create_namespace(args: CreateNamespaceInput) -> Result<NamespaceInfo, String> {
    store::state::allowed_api("admin_create_namespace")?;
    store::state::ensure_memory_available()?;
    args.validate()?;

    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::create_namespace(args, now_ms)
}

#[ic_cdk::query]
fn admin_list_namespace(
    prev: Option<String>,
    take: Option<u32>,
) -> Result<Vec<NamespaceInfo>, String> {
    if let Some(cursor) = prev.as_ref() {
        ic_cose_types::validate_str(cursor)?;
    }
    let caller = ic_cdk::api::msg_caller();
    let take = take.unwrap_or(10).min(100);
    let controller_or_manager = is_controller_or_manager().is_ok();
    store::state::with(|s| {
        if !controller_or_manager && !s.auditors.contains(&caller) {
            Err("no permission".to_string())?;
        }

        let namespaces = store::ns::list_namespaces(prev, take as usize);
        Ok(namespaces)
    })
}

/// Incrementally moves legacy monolithic setting records into split metadata
/// and payload stable maps. Re-run until it returns zero.
#[ic_cdk::update(guard = "is_controller")]
fn admin_migrate_legacy_settings(take: u32) -> Result<u64, String> {
    store::state::ensure_memory_available()?;
    Ok(store::ns::migrate_legacy_settings(
        take.clamp(1, 100) as usize
    ))
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_migrate_legacy_namespace_acls(take: u32) -> Result<u64, String> {
    store::state::ensure_memory_available()?;
    Ok(store::ns::migrate_legacy_namespace_acls(
        take.clamp(1, 100) as usize
    ))
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_recover_namespace_managers(
    namespace: String,
    managers: BTreeSet<Principal>,
) -> Result<(), String> {
    ic_cose_types::validate_str(&namespace)?;
    validate_principals(&managers)?;
    store::ns::recover_managers(namespace, managers, ic_cdk::api::time() / MILLISECONDS)
}

#[ic_cdk::update(guard = "is_controller")]
fn admin_clear_low_wasm_memory() -> Result<(), String> {
    store::state::set_low_wasm_memory(false);
    Ok(())
}

// ----- Use validate2_xxxxxx instead of validate_xxxxxx -----

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_add_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update(guard = "is_controller")]
fn validate2_admin_add_managers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    Ok(format_principals(&args))
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_remove_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update(guard = "is_controller")]
fn validate2_admin_remove_managers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    Ok(format_principals(&args))
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_add_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update(guard = "is_controller")]
fn validate2_admin_add_auditors(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    Ok(format_principals(&args))
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_remove_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update(guard = "is_controller")]
fn validate2_admin_remove_auditors(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    Ok(format_principals(&args))
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_add_allowed_apis(args: BTreeSet<String>) -> Result<(), String> {
    validate_allowed_apis(&args)
}

#[ic_cdk::update(guard = "is_controller")]
fn validate2_admin_add_allowed_apis(args: BTreeSet<String>) -> Result<String, String> {
    validate_allowed_apis(&args)?;
    Ok(format_strings(&args))
}

#[ic_cdk::update(guard = "is_controller")]
fn validate_admin_remove_allowed_apis(args: BTreeSet<String>) -> Result<(), String> {
    validate_allowed_apis(&args)
}

#[ic_cdk::update(guard = "is_controller")]
fn validate2_admin_remove_allowed_apis(args: BTreeSet<String>) -> Result<String, String> {
    validate_allowed_apis(&args)?;
    Ok(format_strings(&args))
}

fn format_principals(values: &BTreeSet<Principal>) -> String {
    format_vec(values, |output, principal| {
        write!(output, "principal \"{principal}\"").expect("writing to a String cannot fail");
    })
}

fn format_strings(values: &BTreeSet<String>) -> String {
    format_vec(values, |output, value| {
        write!(output, "{value:?}").expect("writing to a String cannot fail");
    })
}

fn format_vec<T>(values: &BTreeSet<T>, mut format_value: impl FnMut(&mut String, &T)) -> String {
    if values.is_empty() {
        return "vec {}".to_string();
    }

    let mut output = String::from("vec {");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(';');
        }
        output.push(' ');
        format_value(&mut output, value);
    }
    output.push_str(" }");
    output
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn validation_messages_keep_the_candid_vec_shape() {
        let principal = Principal::from_slice(&[1, 2, 3]);
        assert_eq!(
            format_principals(&BTreeSet::from([principal])),
            format!("vec {{ principal \"{principal}\" }}")
        );
        assert_eq!(
            format_strings(&BTreeSet::from([
                "ecdsa_sign".to_string(),
                "setting_create".to_string(),
            ])),
            "vec { \"ecdsa_sign\"; \"setting_create\" }"
        );
        assert_eq!(format_strings(&BTreeSet::new()), "vec {}");
    }
}
