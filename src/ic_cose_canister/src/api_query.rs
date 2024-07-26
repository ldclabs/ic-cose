use ic_cose_types::types::{
    namespace::NamespaceInfo,
    setting::{SettingArchivedPayload, SettingInfo, SettingPath},
    state::StateInfo,
};

use crate::store;

#[ic_cdk::query]
fn get_state() -> Result<StateInfo, String> {
    store::state::with(|s| {
        let mut info = s.to_info();
        info.namespace_count = store::ns::namespace_count();
        Ok(info)
    })
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
    let (info, _) = store::ns::get_setting(&caller, &spk)?;
    Ok(info)
}

#[ic_cdk::query]
fn get_setting_archived_payload(path: SettingPath) -> Result<SettingArchivedPayload, String> {
    path.validate()?;
    let caller = ic_cdk::caller();
    let spk = store::SettingPathKey::from_path(path, caller);
    store::ns::get_setting_archived_payload(&caller, &spk)
}
