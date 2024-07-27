use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct StateInfo {
    pub name: String,
    pub ecdsa_key_name: String,
    pub schnorr_key_name: String,
    pub vetkd_key_name: String,
    pub managers: BTreeSet<Principal>, // managers can read and write namespaces, not settings
    // auditors can read and list namespaces and settings info even if it is private
    pub auditors: BTreeSet<Principal>,
    pub namespace_total: u64,
    pub subnet_size: u64,
    pub freezing_threshold: u64,
}
