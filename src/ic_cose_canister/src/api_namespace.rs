use candid::Principal;
use ic_cose_types::{
    types::{namespace::*, state::StateInfo},
    validate_principals, validate_str, MILLISECONDS,
};
use serde_bytes::ByteBuf;
use std::collections::BTreeSet;

use crate::{is_authenticated, is_controller_or_manager, store};

#[ic_cdk::query]
fn state_get_info() -> Result<StateInfo, String> {
    store::state::with(|s| {
        let with_keys = is_controller_or_manager().is_ok();
        let mut info = s.to_info(with_keys);
        info.namespace_total = store::ns::namespace_count();
        Ok(info)
    })
}

#[ic_cdk::query]
fn namespace_get_info(namespace: String) -> Result<NamespaceInfo, String> {
    validate_str(&namespace)?;
    let caller = ic_cdk::api::msg_caller();
    store::ns::get_namespace(&caller, namespace)
}

#[ic_cdk::query]
fn namespace_get_info_v2(namespace: String, with_members: bool) -> Result<NamespaceInfo, String> {
    validate_str(&namespace)?;
    let caller = ic_cdk::api::msg_caller();
    store::ns::get_namespace_v2(&caller, namespace, with_members)
}

#[ic_cdk::query]
fn namespace_list_members(
    namespace: String,
    member_kind: String,
    prev: Option<Principal>,
    take: Option<u32>,
) -> Result<Vec<Principal>, String> {
    validate_str(&namespace)?;
    store::ns::list_members(
        &namespace,
        &ic_cdk::api::msg_caller(),
        &member_kind,
        prev,
        take.unwrap_or(100).clamp(1, 1_000) as usize,
    )
}

#[ic_cdk::query]
fn namespace_list_fixed_identity_names(
    namespace: String,
    prev: Option<String>,
    take: Option<u32>,
) -> Result<Vec<String>, String> {
    validate_str(&namespace)?;
    if let Some(cursor) = prev.as_ref() {
        validate_str(cursor)?;
    }
    store::ns::list_fixed_identity_names(
        &namespace,
        &ic_cdk::api::msg_caller(),
        prev,
        take.unwrap_or(100).clamp(1, 1_000) as usize,
    )
}

#[ic_cdk::query]
fn namespace_list_setting_keys(
    namespace: String,
    user_owned: bool,
    subject: Option<Principal>,
) -> Result<Vec<(Principal, ByteBuf)>, String> {
    validate_str(&namespace)?;
    let caller = ic_cdk::api::msg_caller();
    store::ns::with(&namespace, |ns| {
        match ns.access(&namespace, &caller).read_permission() {
            store::NamespaceReadPermission::Full => {
                let values =
                    store::ns::list_setting_keys_page(&namespace, user_owned, subject, None, 1_001);
                if values.len() > 1_000 {
                    return Err(
                        "more than 1000 setting keys; use namespace_list_setting_keys_v2"
                            .to_string(),
                    );
                }
                Ok(values)
            }
            store::NamespaceReadPermission::User
                if subject.is_none() || subject == Some(caller) =>
            {
                let values = store::ns::list_setting_keys_page(
                    &namespace,
                    user_owned,
                    Some(caller),
                    None,
                    1_001,
                );
                if values.len() > 1_000 {
                    return Err(
                        "more than 1000 setting keys; use namespace_list_setting_keys_v2"
                            .to_string(),
                    );
                }
                Ok(values)
            }
            _ => Err("no permission".to_string()),
        }
    })
}

#[ic_cdk::query]
fn namespace_list_setting_keys_v2(
    namespace: String,
    user_owned: bool,
    subject: Option<Principal>,
    prev: Option<(Principal, ByteBuf)>,
    take: Option<u32>,
) -> Result<Vec<(Principal, ByteBuf)>, String> {
    validate_str(&namespace)?;
    let caller = ic_cdk::api::msg_caller();
    let take = take.unwrap_or(100).clamp(1, 1_000) as usize;
    if let (Some(subject), Some((cursor_subject, _))) = (subject, prev.as_ref()) {
        if &subject != cursor_subject {
            return Err("pagination cursor belongs to another subject".to_string());
        }
    }
    store::ns::with(&namespace, |ns| {
        match ns.access(&namespace, &caller).read_permission() {
            store::NamespaceReadPermission::Full => Ok(store::ns::list_setting_keys_page(
                &namespace, user_owned, subject, prev, take,
            )),
            store::NamespaceReadPermission::User
                if subject.is_none() || subject == Some(caller) =>
            {
                if prev
                    .as_ref()
                    .is_some_and(|(principal, _)| principal != &caller)
                {
                    return Err("pagination cursor belongs to another subject".to_string());
                }
                Ok(store::ns::list_setting_keys_page(
                    &namespace,
                    user_owned,
                    Some(caller),
                    prev,
                    take,
                ))
            }
            _ => Err("no permission".to_string()),
        }
    })
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_update_info(args: UpdateNamespaceInput) -> Result<(), String> {
    store::state::allowed_api("namespace_update_info")?;
    if args.desc.is_some() {
        store::state::ensure_memory_available()?;
    }
    args.validate()?;

    let caller = ic_cdk::api::msg_caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::update_namespace_info(&caller, args, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_delete(namespace: String) -> Result<(), String> {
    store::state::allowed_api("namespace_delete")?;
    validate_str(&namespace)?;

    let caller = ic_cdk::api::msg_caller();
    store::ns::delete_namespace(&caller, namespace)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_add_managers(namespace: String, args: BTreeSet<Principal>) -> Result<(), String> {
    store::state::allowed_api("namespace_add_managers")?;
    store::state::ensure_memory_available()?;
    validate_str(&namespace)?;
    validate_principals(&args)?;

    let caller = ic_cdk::api::msg_caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::add_managers(namespace, &caller, args, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_remove_managers(namespace: String, args: BTreeSet<Principal>) -> Result<(), String> {
    store::state::allowed_api("namespace_remove_managers")?;
    validate_str(&namespace)?;
    validate_principals(&args)?;

    let caller = ic_cdk::api::msg_caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::remove_managers(namespace, &caller, args, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_add_auditors(namespace: String, args: BTreeSet<Principal>) -> Result<(), String> {
    store::state::allowed_api("namespace_add_auditors")?;
    store::state::ensure_memory_available()?;
    validate_str(&namespace)?;
    validate_principals(&args)?;

    let caller = ic_cdk::api::msg_caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::add_auditors(namespace, &caller, args, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_remove_auditors(namespace: String, args: BTreeSet<Principal>) -> Result<(), String> {
    store::state::allowed_api("namespace_remove_auditors")?;
    validate_str(&namespace)?;
    validate_principals(&args)?;

    let caller = ic_cdk::api::msg_caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::remove_auditors(namespace, &caller, args, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_add_users(namespace: String, args: BTreeSet<Principal>) -> Result<(), String> {
    store::state::allowed_api("namespace_add_users")?;
    store::state::ensure_memory_available()?;
    validate_str(&namespace)?;
    validate_principals(&args)?;

    let caller = ic_cdk::api::msg_caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::add_users(namespace, &caller, args, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_remove_users(namespace: String, args: BTreeSet<Principal>) -> Result<(), String> {
    store::state::allowed_api("namespace_remove_users")?;
    validate_str(&namespace)?;
    validate_principals(&args)?;

    let caller = ic_cdk::api::msg_caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::remove_users(namespace, &caller, args, now_ms)
}

#[ic_cdk::query(guard = "is_authenticated")]
fn namespace_is_member(
    namespace: String,
    member_kind: String,
    user: Principal,
) -> Result<bool, String> {
    validate_str(&namespace)?;
    let caller = ic_cdk::api::msg_caller();
    store::ns::is_member(&namespace, &caller, &member_kind, &user)
}

const MIN_CYCLES: u128 = 1_000_000_000_000;

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_top_up(namespace: String, cycles: u128) -> Result<u128, String> {
    store::state::allowed_api("namespace_top_up")?;
    validate_str(&namespace)?;

    if cycles < MIN_CYCLES {
        Err("cycles should be at least 1T".to_string())?;
    }
    if cycles > ic_cdk::api::msg_cycles_available() {
        Err("insufficient cycles".to_string())?;
    }

    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::top_up_namespace(namespace, cycles, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_rebuild_payload_bytes(namespace: String) -> Result<u64, String> {
    store::state::allowed_api("namespace_rebuild_payload_bytes")?;
    store::state::ensure_memory_available()?;
    validate_str(&namespace)?;
    let caller = ic_cdk::api::msg_caller();
    store::ns::rebuild_payload_bytes(namespace, &caller)
}
