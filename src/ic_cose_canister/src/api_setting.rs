use candid::Principal;
use ic_cose_types::{types::setting::*, validate_principals, MILLISECONDS};
use std::collections::BTreeSet;

use crate::{is_authenticated, store};

#[ic_cdk::query]
fn setting_get_info(path: SettingPath) -> Result<SettingInfo, String> {
    path.validate()?;
    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path, caller);
    store::ns::get_setting_info(&caller, &spk)
}

// Clients should execute this query with update call to make the result of execution goes through consensus.
#[ic_cdk::query]
fn setting_get(path: SettingPath) -> Result<SettingInfo, String> {
    path.validate()?;
    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path, caller);
    store::ns::get_setting(&caller, &spk)
}

#[ic_cdk::query]
fn setting_get_archived_payload(path: SettingPath) -> Result<SettingArchivedPayload, String> {
    path.validate()?;
    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path, caller);
    store::ns::get_setting_archived_payload(&caller, &spk)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn setting_create(
    path: SettingPath,
    input: CreateSettingInput,
) -> Result<CreateSettingOutput, String> {
    path.validate()?;
    input.validate()?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::create_setting(&caller, &spk, input, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn setting_update_info(
    path: SettingPath,
    input: UpdateSettingInfoInput,
) -> Result<UpdateSettingOutput, String> {
    path.validate()?;
    input.validate()?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::update_setting_info(&caller, &spk, input, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn setting_update_payload(
    path: SettingPath,
    input: UpdateSettingPayloadInput,
) -> Result<UpdateSettingOutput, String> {
    path.validate()?;
    input.validate()?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::update_setting_payload(&caller, &spk, input, now_ms)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn setting_add_readers(path: SettingPath, mut input: BTreeSet<Principal>) -> Result<(), String> {
    path.validate()?;
    validate_principals(&input)?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::with_setting_mut(&caller, &spk, |setting| {
        setting.readers.append(&mut input);
        setting.updated_at = now_ms;
        Ok(())
    })
}

#[ic_cdk::update(guard = "is_authenticated")]
fn setting_remove_readers(path: SettingPath, input: BTreeSet<Principal>) -> Result<(), String> {
    path.validate()?;
    validate_principals(&input)?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::with_setting_mut(&caller, &spk, |setting| {
        setting.readers.retain(|p| !input.contains(p));
        setting.updated_at = now_ms;
        Ok(())
    })
}
