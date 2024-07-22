use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::BTreeSet;

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct StateInfo {
    pub name: String,
    pub ecdsa_key_name: String,
    pub ecdsa_public_key: Option<ByteBuf>,
    pub vetkd_key_name: String,
    pub managers: BTreeSet<Principal>, // managers can read and write namespaces, not settings
    // auditors can read and list namespaces and settings info even if it is private
    pub auditors: BTreeSet<Principal>,
    pub namespace_count: u64,
    pub subnet_size: u64,
    pub service_fee: u64, // in cycles
    pub incoming_cycles: u128,
    pub uncollectible_cycles: u128, // cycles that cannot be collected
    pub freezing_threshold: u128,   // cycles
}
