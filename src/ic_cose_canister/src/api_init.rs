use candid::CandidType;
use serde::Deserialize;
use std::time::Duration;

use crate::store;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ChainArgs {
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
    subnet_size: u64,        // set to 0 to disable receiving cycles
    freezing_threshold: u64, // in cycles
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UpgradeArgs {
    name: Option<String>, // seconds
    subnet_size: Option<u64>,
    freezing_threshold: Option<u64>, // in cycles
}

#[ic_cdk::init]
fn init(args: Option<ChainArgs>) {
    match args.expect("init args is missing") {
        ChainArgs::Init(args) => {
            store::state::with_mut(|s| {
                s.name = args.name;
                s.ecdsa_key_name = args.ecdsa_key_name;
                s.schnorr_key_name = args.schnorr_key_name;
                s.vetkd_key_name = args.vetkd_key_name;
                s.subnet_size = args.subnet_size;
                s.freezing_threshold = if args.freezing_threshold > 0 {
                    args.freezing_threshold
                } else {
                    1_000_000_000_000
                };
            });
        }
        ChainArgs::Upgrade(_) => {
            ic_cdk::trap(
                "cannot initialize the canister with an Upgrade args. Please provide an Init args.",
            );
        }
    }

    ic_cdk_timers::set_timer(Duration::from_secs(0), || {
        ic_cdk::spawn(store::state::init_public_key())
    });
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
