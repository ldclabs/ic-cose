use candid::Principal;
use ic_cose_types::{
    cose::{
        ecdh::ecdh_x25519,
        encrypt0::{cose_decrypt0, cose_encrypt0},
        format_error, get_cose_key_secret, mac3_256, CborSerializable, CoseKey,
    },
    types::{setting::*, ECDHInput, ECDHOutput},
    validate_principals, OwnedRef, MILLISECONDS,
};
use std::collections::BTreeSet;

use crate::{is_authenticated, rand_bytes, store};

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
    let (info, _) = store::ns::get_setting(&caller, &spk)?;
    Ok(info)
}

#[ic_cdk::query]
fn setting_get_archived_payload(path: SettingPath) -> Result<SettingArchivedPayload, String> {
    path.validate()?;
    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path, caller);
    store::ns::get_setting_archived_payload(&caller, &spk)
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn ecdh_setting_get(
    path: SettingPath,
    ecdh: ECDHInput,
) -> Result<ECDHOutput<SettingInfo>, String> {
    path.validate()?;

    let caller = ic_cdk::caller();
    let subject = path.subject.unwrap_or(caller);
    let spk = store::SettingPathKey::from_path(path, subject);
    let (mut info, iv) = store::ns::get_setting(&caller, &spk)?;

    let aad = spk.2.as_slice();
    let payload = info.payload.as_ref().ok_or("missing payload")?;
    let data = match info.dek {
        None => OwnedRef::Ref(payload),
        Some(ref dek) => {
            let partial_key = ecdh.partial_key.ok_or("missing partial key")?;
            let key = store::ns::inner_ecdsa_setting_kek(&spk, &iv, partial_key.as_ref()).await?;
            let key = cose_decrypt0(dek, &key, aad)?;
            let key = CoseKey::from_slice(&key).map_err(format_error)?;
            let key = get_cose_key_secret(key)?;
            OwnedRef::Owned(cose_decrypt0(payload, &key, aad)?)
        }
    };

    let secret_key = rand_bytes().await;
    let secret_key = mac3_256(&secret_key, ecdh.nonce.as_ref());
    let (shared_secret, public_key) = ecdh_x25519(secret_key, *ecdh.public_key);
    let payload = cose_encrypt0(data.as_ref(), shared_secret.as_bytes(), aad, *ecdh.nonce)?;
    info.payload = Some(payload);
    Ok(ECDHOutput {
        payload: info,
        public_key: public_key.to_bytes().into(),
    })
}

#[ic_cdk::update(guard = "is_authenticated")]
async fn setting_create(
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
async fn setting_update_info(
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
async fn setting_update_payload(
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
