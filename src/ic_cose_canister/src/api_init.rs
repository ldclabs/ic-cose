use candid::{CandidType, Principal};
use serde::Deserialize;
use std::{collections::BTreeSet, time::Duration};

use crate::store;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum InstallArgs {
    Init(InitArgs),
    Upgrade(UpgradeArgs),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InitArgs {
    name: String,
    ecdsa_key_name: String, // Use "dfx_test_key" for local replica and "test_key_1" for a testing key for testnet and mainnet
    // https://internetcomputer.org/docs/current/developer-docs/smart-contracts/signatures/signing-messages-t-schnorr
    schnorr_key_name: String,
    vetkd_key_name: String,
    allowed_apis: BTreeSet<String>,
    subnet_size: u64, // legacy informational field; dynamic cost APIs are authoritative
    freezing_threshold: u64, // in cycles
    governance_canister: Option<Principal>,
    vetkd_context_version: Option<u8>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UpgradeArgs {
    name: Option<String>, // seconds
    subnet_size: Option<u64>,
    freezing_threshold: Option<u64>, // in cycles
    governance_canister: Option<Principal>,
    vetkd_key_name: Option<String>,
    clear_governance_canister: Option<bool>,
    vetkd_context_version: Option<u8>,
    /// Explicit opt-in for deployments upgrading directly from the legacy
    /// monolithic namespace store. Current deployments must leave this false.
    migrate_legacy_namespaces: Option<bool>,
}

fn validate_governance_canister(value: Option<&Principal>) -> Result<(), String> {
    if value == Some(&Principal::anonymous()) {
        return Err("governance_canister must not be anonymous".to_string());
    }
    Ok(())
}

fn validate_vetkd_context_version(value: u8) -> Result<(), String> {
    if matches!(value, 1 | 2) {
        Ok(())
    } else {
        Err("vetkd_context_version must be 1 or 2".to_string())
    }
}

fn validate_key_name(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 {
        return Err("chain-key name length should be in 1..=128".to_string());
    }
    Ok(())
}

fn validate_instance_name(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 {
        return Err("instance name length should be in 1..=128".to_string());
    }
    Ok(())
}

fn validate_allowed_apis(values: &BTreeSet<String>) -> Result<(), String> {
    const MAX_ALLOWED_APIS: usize = 256;
    if values.len() > MAX_ALLOWED_APIS {
        return Err(format!(
            "allowed APIs count exceeds the limit {MAX_ALLOWED_APIS}"
        ));
    }
    for value in values {
        ic_cose_types::validate_str(value)?;
    }
    Ok(())
}

fn schedule_public_key_init(delay: Duration) {
    let retry_delay = if delay.is_zero() {
        Duration::from_secs(30)
    } else {
        delay.saturating_mul(2).min(Duration::from_secs(3600))
    };
    ic_cdk_timers::set_timer(delay, async move {
        if !store::state::init_public_key().await {
            schedule_public_key_init(retry_delay);
        }
    });
}

#[ic_cdk::init]
fn init(args: Option<InstallArgs>) {
    match args.expect("init args is missing") {
        InstallArgs::Init(args) => {
            validate_instance_name(&args.name).unwrap_or_else(|err| ic_cdk::trap(&err));
            validate_key_name(&args.ecdsa_key_name).unwrap_or_else(|err| ic_cdk::trap(&err));
            validate_key_name(&args.schnorr_key_name).unwrap_or_else(|err| ic_cdk::trap(&err));
            validate_key_name(&args.vetkd_key_name).unwrap_or_else(|err| ic_cdk::trap(&err));
            validate_allowed_apis(&args.allowed_apis).unwrap_or_else(|err| ic_cdk::trap(&err));
            validate_governance_canister(args.governance_canister.as_ref())
                .unwrap_or_else(|err| ic_cdk::trap(&err));
            let vetkd_context_version = args.vetkd_context_version.unwrap_or(2);
            validate_vetkd_context_version(vetkd_context_version)
                .unwrap_or_else(|err| ic_cdk::trap(&err));
            store::state::with_mut(|s| {
                s.name = args.name;
                s.ecdsa_key_name = args.ecdsa_key_name;
                s.schnorr_key_name = args.schnorr_key_name;
                s.vetkd_key_name = args.vetkd_key_name;
                s.allowed_apis = args.allowed_apis;
                s.subnet_size = args.subnet_size;
                s.freezing_threshold = if args.freezing_threshold > 0 {
                    args.freezing_threshold
                } else {
                    1_000_000_000_000
                };
                s.governance_canister = args.governance_canister;
                s.vetkd_context_version = vetkd_context_version;
            });
        }
        InstallArgs::Upgrade(_) => {
            ic_cdk::trap(
                "cannot initialize the canister with an Upgrade args. Please provide an Init args.",
            );
        }
    }

    store::state::initialize_schema();
    schedule_public_key_init(Duration::from_secs(0));
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    store::state::save();
}

#[ic_cdk::post_upgrade]
fn post_upgrade(args: Option<InstallArgs>) {
    let migrate_legacy_namespaces = matches!(
        args.as_ref(),
        Some(InstallArgs::Upgrade(UpgradeArgs {
            migrate_legacy_namespaces: Some(true),
            ..
        }))
    );
    store::state::load(migrate_legacy_namespaces);

    match args {
        Some(InstallArgs::Upgrade(args)) => {
            if let Some(name) = args.name.as_ref() {
                validate_instance_name(name).unwrap_or_else(|err| ic_cdk::trap(&err));
            }
            if let Some(key_name) = args.vetkd_key_name.as_ref() {
                validate_key_name(key_name).unwrap_or_else(|err| ic_cdk::trap(&err));
            }
            validate_governance_canister(args.governance_canister.as_ref())
                .unwrap_or_else(|err| ic_cdk::trap(&err));
            if args.clear_governance_canister == Some(true) && args.governance_canister.is_some() {
                ic_cdk::trap(
                    "governance_canister and clear_governance_canister cannot both be set",
                );
            }
            if let Some(version) = args.vetkd_context_version {
                validate_vetkd_context_version(version).unwrap_or_else(|err| ic_cdk::trap(&err));
            }
            store::state::with_mut(|s| {
                if let Some(name) = args.name {
                    s.name = name;
                }
                if let Some(subnet_size) = args.subnet_size {
                    s.subnet_size = subnet_size;
                }
                if let Some(freezing_threshold) = args.freezing_threshold {
                    s.freezing_threshold = freezing_threshold;
                }
                if args.clear_governance_canister == Some(true) {
                    s.governance_canister = None;
                } else if let Some(governance_canister) = args.governance_canister {
                    s.governance_canister = Some(governance_canister);
                }
                if let Some(vetkd_key_name) = args.vetkd_key_name {
                    s.vetkd_key_name = vetkd_key_name;
                }
                if let Some(version) = args.vetkd_context_version {
                    s.vetkd_context_version = version;
                }
            });
        }
        Some(InstallArgs::Init(_)) => {
            ic_cdk::trap(
                "cannot upgrade the canister with an Init args. Please provide an Upgrade args.",
            );
        }
        _ => {}
    }

    // a key that could not be retrieved during init would otherwise stay missing
    // forever, leaving the ECDSA, Schnorr and KEK APIs permanently broken.
    if store::state::needs_public_key_init() {
        schedule_public_key_init(Duration::from_secs(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_configuration_rejects_anonymous_and_unknown_context_versions() {
        assert!(validate_governance_canister(Some(&Principal::anonymous())).is_err());
        assert!(validate_governance_canister(None).is_ok());
        assert!(validate_vetkd_context_version(1).is_ok());
        assert!(validate_vetkd_context_version(2).is_ok());
        assert!(validate_vetkd_context_version(0).is_err());
        assert!(validate_key_name("test_key_1").is_ok());
        assert!(validate_key_name("").is_err());
        assert!(validate_instance_name("Local IC COSE").is_ok());
        assert!(validate_allowed_apis(&BTreeSet::new()).is_ok());
        assert!(validate_allowed_apis(&BTreeSet::from(["Invalid".to_string()])).is_err());
    }
}
