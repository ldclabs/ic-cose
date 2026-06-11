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
    pub governance_canister: Option<Principal>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::encode_one;
    use serde_bytes::ByteBuf;

    #[test]
    fn state_info_is_constructible() {
        let state = StateInfo {
            name: "ic_cose".to_string(),
            ecdsa_key_name: "ecdsa".to_string(),
            schnorr_key_name: "schnorr".to_string(),
            vetkd_key_name: "vetkd".to_string(),
            managers: BTreeSet::from([Principal::management_canister()]),
            auditors: BTreeSet::new(),
            allowed_apis: BTreeSet::from(["state_get_info".to_string()]),
            namespace_total: 1,
            subnet_size: 13,
            freezing_threshold: 2,
            ecdsa_public_key: Some(PublicKeyOutput {
                public_key: ByteBuf::from(vec![1]),
                chain_code: ByteBuf::from(vec![2]),
            }),
            schnorr_ed25519_public_key: None,
            schnorr_secp256k1_public_key: None,
            governance_canister: Some(Principal::management_canister()),
        };
        assert_eq!(state.name, "ic_cose");
        assert_eq!(state.namespace_total, 1);
        assert_eq!(state.clone(), state);
        assert!(!format!("{state:?}").is_empty());
        assert!(!encode_one(state.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&state).is_empty());
    }
}
