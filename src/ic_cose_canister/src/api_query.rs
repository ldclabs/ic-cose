use ic_cose_types::{
    cose::PublicKeyInput,
    namespace::NamespaceInfo,
    setting::{SettingInfo, SettingPath},
    state::StateInfo,
};
use serde_bytes::ByteBuf;

use crate::store;

#[ic_cdk::query]
fn get_state() -> Result<StateInfo, String> {
    let caller = ic_cdk::caller();
    store::state::with(|s| {
        let mut info = s.to_info(&caller);
        info.namespace_count = store::ns::namespace_count();
        Ok(info)
    })
}

#[ic_cdk::query]
fn ecdsa_public_key(input: PublicKeyInput) -> Result<ByteBuf, String> {
    let caller = ic_cdk::caller();
    store::ns::ecdsa_public_key(&caller, input.namespace, input.derivation_path)
}

#[ic_cdk::query]
fn schnorr_public_key(_input: PublicKeyInput) -> Result<ByteBuf, String> {
    Err("not implemented".to_string())
}

#[ic_cdk::query]
fn get_namespace(namespace: String) -> Result<NamespaceInfo, String> {
    let caller = ic_cdk::caller();
    store::ns::get_namespace(&caller, namespace)
}

#[ic_cdk::query]
fn list_namespaces(prev: Option<String>, take: Option<u32>) -> Result<Vec<NamespaceInfo>, String> {
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

#[ic_cdk::query]
fn get_setting_info(path: SettingPath) -> Result<SettingInfo, String> {
    path.validate()?;
    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path, caller);
    store::ns::get_setting_info(&caller, &spk)
}

// Clients should execute this query with update call to make the result of execution goes through consensus.
#[ic_cdk::query]
fn get_setting(path: SettingPath) -> Result<SettingInfo, String> {
    path.validate()?;
    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path, caller);
    store::ns::get_setting(&caller, &spk)
}
