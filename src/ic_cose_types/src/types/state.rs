use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::PublicKeyOutput;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct StateInfo {
    pub name: String,
    pub ecdsa_key_name: String,
    pub schnorr_key_name: String,
    pub vetkd_key_name: String,
    pub managers: BTreeSet<Principal>, // managers can read and write namespaces, not settings
    // auditors can read and list namespaces and settings info even if it is private
    pub auditors: BTreeSet<Principal>,
    pub allowed_apis: BTreeSet<String>,
    pub namespace_total: u64,
    pub subnet_size: u64,
    pub freezing_threshold: u64,
    pub ecdsa_public_key: Option<PublicKeyOutput>,
    pub schnorr_ed25519_public_key: Option<PublicKeyOutput>,
    pub schnorr_secp256k1_public_key: Option<PublicKeyOutput>,
}
