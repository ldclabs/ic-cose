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

#[cfg(test)]
mod tests {
    use super::*;
    use candid::encode_one;

    #[test]
    fn wasm_types_are_constructible() {
        let state = StateInfo {
            name: "wasm".to_string(),
            managers: BTreeSet::from([Principal::management_canister()]),
            committers: BTreeSet::new(),
            latest_version: BTreeMap::from([("module".to_string(), [1u8; 32].into())]),
            wasm_total: 1,
            deployed_total: 2,
            deployment_logs: 3,
            governance_canister: None,
        };
        assert_eq!(state.latest_version["module"].as_ref(), &[1u8; 32]);
        assert!(!format!("{:?}", state.clone()).is_empty());
        assert!(!encode_one(state).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&StateInfo::default()).is_empty());

        let wasm = WasmInfo {
            name: "module".to_string(),
            created_at: 1,
            created_by: Principal::management_canister(),
            description: "desc".to_string(),
            wasm: ByteBuf::from(vec![0, 1]),
            hash: [2u8; 32].into(),
        };
        assert_eq!(wasm.hash.as_ref(), &[2u8; 32]);
        assert!(!format!("{:?}", wasm.clone()).is_empty());
        assert!(!encode_one(wasm.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&wasm).is_empty());

        let add = AddWasmInput {
            name: wasm.name.clone(),
            description: wasm.description.clone(),
            wasm: wasm.wasm.clone(),
        };
        assert_eq!(add.wasm, ByteBuf::from(vec![0, 1]));
        assert!(!format!("{:?}", add.clone()).is_empty());
        assert!(!encode_one(add.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&add).is_empty());

        let deploy = DeployWasmInput {
            name: "module".to_string(),
            canister: Principal::management_canister(),
            args: Some(ByteBuf::from(vec![3])),
        };
        assert_eq!(deploy.args, Some(ByteBuf::from(vec![3])));
        assert!(!format!("{:?}", deploy.clone()).is_empty());
        assert!(!encode_one(deploy.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&deploy).is_empty());

        let deployment = DeploymentInfo {
            name: "module".to_string(),
            deploy_at: 4,
            canister: Principal::management_canister(),
            prev_hash: [5u8; 32].into(),
            wasm_hash: [6u8; 32].into(),
            args: None,
            error: Some("failed".to_string()),
        };
        assert_eq!(deployment.error.as_deref(), Some("failed"));
        assert!(!format!("{:?}", deployment.clone()).is_empty());
        assert!(!encode_one(deployment.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&deployment).is_empty());
    }
}
