use candid::{CandidType, Principal};
use serde::Deserialize;

use crate::store;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ChainArgs {
    Init(InitArgs),
    Upgrade(UpgradeArgs),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InitArgs {
    name: String,
    topup_threshold: u128,
    topup_amount: u128,
    governance_canister: Option<Principal>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UpgradeArgs {
    name: Option<String>,
    token_expiration: Option<u64>, // in seconds
    topup_threshold: Option<u128>,
    topup_amount: Option<u128>,
    governance_canister: Option<Principal>,
    clear_governance_canister: Option<bool>,
}

fn validate_governance_canister(value: Option<&Principal>) -> Result<(), String> {
    if value == Some(&Principal::anonymous()) {
        return Err("governance_canister must not be anonymous".to_string());
    }
    Ok(())
}

fn validate_topup(threshold: u128, amount: u128) -> Result<(), String> {
    if threshold == 0 && amount == 0 {
        return Ok(());
    }
    if threshold == 0 || amount <= threshold {
        return Err(
            "topup must be disabled with two zero values or topup_amount must exceed topup_threshold"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_instance_name(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 {
        return Err("instance name length should be in 1..=128".to_string());
    }
    Ok(())
}

#[ic_cdk::init]
fn init(args: Option<ChainArgs>) {
    match args.expect("init args is missing") {
        ChainArgs::Init(args) => {
            validate_instance_name(&args.name).unwrap_or_else(|err| ic_cdk::trap(&err));
            validate_governance_canister(args.governance_canister.as_ref())
                .unwrap_or_else(|err| ic_cdk::trap(&err));
            validate_topup(args.topup_threshold, args.topup_amount)
                .unwrap_or_else(|err| ic_cdk::trap(&err));
            store::state::with_mut(|s| {
                s.name = args.name;
                s.topup_threshold = args.topup_threshold;
                s.topup_amount = args.topup_amount;
                s.governance_canister = args.governance_canister;
            });
            store::state::initialize_schema();
        }
        ChainArgs::Upgrade(_) => {
            ic_cdk::trap(
                "cannot initialize the canister with an Upgrade args. Please provide an Init args.",
            );
        }
    }
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    store::state::save();
}

#[ic_cdk::post_upgrade]
fn post_upgrade(args: Option<ChainArgs>) {
    store::state::load();

    match args {
        Some(ChainArgs::Upgrade(args)) => {
            if let Some(name) = args.name.as_ref() {
                validate_instance_name(name).unwrap_or_else(|err| ic_cdk::trap(&err));
            }
            validate_governance_canister(args.governance_canister.as_ref())
                .unwrap_or_else(|err| ic_cdk::trap(&err));
            if args.clear_governance_canister == Some(true) && args.governance_canister.is_some() {
                ic_cdk::trap(
                    "governance_canister and clear_governance_canister cannot both be set",
                );
            }
            if args.token_expiration.is_some() {
                ic_cdk::trap("token_expiration is unsupported and must be null");
            }
            let (threshold, amount) = store::state::with(|s| {
                (
                    args.topup_threshold.unwrap_or(s.topup_threshold),
                    args.topup_amount.unwrap_or(s.topup_amount),
                )
            });
            validate_topup(threshold, amount).unwrap_or_else(|err| ic_cdk::trap(&err));
            store::state::with_mut(|s| {
                if let Some(name) = args.name {
                    s.name = name;
                }
                if let Some(topup_threshold) = args.topup_threshold {
                    s.topup_threshold = topup_threshold;
                }
                if let Some(topup_amount) = args.topup_amount {
                    s.topup_amount = topup_amount;
                }
                if args.clear_governance_canister == Some(true) {
                    s.governance_canister = None;
                } else if let Some(governance_canister) = args.governance_canister {
                    s.governance_canister = Some(governance_canister);
                }
            });
        }
        Some(ChainArgs::Init(_)) => {
            ic_cdk::trap(
                "cannot upgrade the canister with an Init args. Please provide an Upgrade args.",
            );
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_and_topup_configuration_is_safe_by_default() {
        assert!(validate_governance_canister(Some(&Principal::anonymous())).is_err());
        assert!(validate_governance_canister(None).is_ok());
        assert!(validate_topup(0, 0).is_ok());
        assert!(validate_topup(1, 2).is_ok());
        assert!(validate_topup(1, 1).is_err());
        assert!(validate_topup(0, 1).is_err());
        assert!(validate_instance_name("Wasm Repo").is_ok());
        assert!(validate_instance_name("").is_err());
    }
}
