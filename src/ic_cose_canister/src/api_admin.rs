use candid::Principal;
use ic_cose_types::validate_principals;
use ic_cose_types::{
    types::namespace::{CreateNamespaceInput, NamespaceInfo},
    MILLISECONDS,
};
use std::collections::BTreeSet;
use std::fmt::Write;

use crate::{is_controller, remove_set_items, store};

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
        remove_set_items(&mut s.managers, args);
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
        remove_set_items(&mut s.auditors, args);
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
        remove_set_items(&mut s.allowed_apis, args);
        Ok(())
    })
}

#[ic_cdk::update]
fn admin_create_namespace(args: CreateNamespaceInput) -> Result<NamespaceInfo, String> {
    store::state::allowed_api("admin_create_namespace")?;
    let caller = ic_cdk::api::msg_caller();
    if !store::state::is_manager(&caller) {
        return Err("no permission".to_string());
    }
    args.validate()?;

    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::create_namespace(&caller, args, now_ms)
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
    Ok(format_principals(&args))
}

#[ic_cdk::update]
fn validate_admin_remove_managers(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update]
fn validate2_admin_remove_managers(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    Ok(format_principals(&args))
}

#[ic_cdk::update]
fn validate_admin_add_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update]
fn validate2_admin_add_auditors(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    Ok(format_principals(&args))
}

#[ic_cdk::update]
fn validate_admin_remove_auditors(args: BTreeSet<Principal>) -> Result<(), String> {
    validate_principals(&args)?;
    Ok(())
}

#[ic_cdk::update]
fn validate2_admin_remove_auditors(args: BTreeSet<Principal>) -> Result<String, String> {
    validate_principals(&args)?;
    Ok(format_principals(&args))
}

#[ic_cdk::update]
fn validate_admin_add_allowed_apis(_args: BTreeSet<String>) -> Result<(), String> {
    Ok(())
}

#[ic_cdk::update]
fn validate2_admin_add_allowed_apis(args: BTreeSet<String>) -> Result<String, String> {
    Ok(format_strings(&args))
}

#[ic_cdk::update]
fn validate_admin_remove_allowed_apis(_args: BTreeSet<String>) -> Result<(), String> {
    Ok(())
}

#[ic_cdk::update]
fn validate2_admin_remove_allowed_apis(args: BTreeSet<String>) -> Result<String, String> {
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
