use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use std::collections::{BTreeMap, BTreeSet};

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct StateInfo {
    pub name: String,
    pub managers: BTreeSet<Principal>,
    pub committers: BTreeSet<Principal>,
    pub latest_version: BTreeMap<String, ByteArray<32>>,
    pub wasm_total: u64,
    pub deployed_total: u64,
    pub deployment_logs: u64,
    pub governance_canister: Option<Principal>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct WasmInfo {
    pub name: String,
    pub created_at: u64, // in milliseconds
    pub created_by: Principal,
    pub description: String,
    pub wasm: ByteBuf,
    pub hash: ByteArray<32>, // sha256 hash of the wasm data
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct AddWasmInput {
    pub name: String,
    pub description: String,
    pub wasm: ByteBuf,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct DeployWasmInput {
    pub name: String,
    pub canister: Principal,
    pub args: Option<ByteBuf>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentInfo {
    pub name: String,
    pub deploy_at: u64, // in milliseconds
    pub canister: Principal,
    pub prev_hash: ByteArray<32>,
    pub wasm_hash: ByteArray<32>,
    pub args: Option<ByteBuf>,
    pub error: Option<String>,
}
