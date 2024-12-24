use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{validate_key, validate_principals};

pub const MAX_PAYLOAD_SIZE: u64 = 2_000_000; // 2MB

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct NamespaceInfo {
    pub name: String,
    pub desc: String,
    pub created_at: u64,               // unix timestamp in milliseconds
    pub updated_at: u64,               // unix timestamp in milliseconds
    pub max_payload_size: u64,         // max payload size in bytes
    pub payload_bytes_total: u64,      // total payload size in bytes
    pub status: i8,                    // -1: archived; 0: readable and writable; 1: readonly
    pub visibility: u8,                // 0: private; 1: public
    pub managers: BTreeSet<Principal>, // managers can read and write all settings
    pub auditors: BTreeSet<Principal>, // auditors can read all settings
    pub users: BTreeSet<Principal>,    // users can read and write settings they created
    pub gas_balance: u128,             // cycles
    pub fixed_id_names: BTreeMap<String, BTreeSet<Principal>>, // fixed identity names
    pub session_expires_in_ms: u64,    // session expiration in milliseconds for fixed identity
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct CreateNamespaceInput {
    pub name: String,
    pub visibility: u8, // 0: private; 1: public
    pub desc: Option<String>,
    pub max_payload_size: Option<u64>, // max payload size in bytes
    pub managers: BTreeSet<Principal>, // managers can read and write all settings
    pub auditors: BTreeSet<Principal>, // auditors can read all settings
    pub users: BTreeSet<Principal>,    // users can read and write settings they created
    pub session_expires_in_ms: Option<u64>, // session expiration in milliseconds for fixed identity, default to 1 day
}

impl CreateNamespaceInput {
    pub fn validate(&self) -> Result<(), String> {
        validate_key(&self.name)?;
        validate_principals(&self.managers)?;
        if let Some(max_payload_size) = self.max_payload_size {
            if max_payload_size == 0 {
                Err("max_payload_size should be greater than 0".to_string())?;
            }
            if max_payload_size > MAX_PAYLOAD_SIZE {
                Err(format!(
                    "max_payload_size should be less than or equal to {}",
                    MAX_PAYLOAD_SIZE
                ))?;
            }
        }

        if self.visibility != 0 && self.visibility != 1 {
            Err("visibility should be 0 or 1".to_string())?;
        }
        Ok(())
    }
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateNamespaceInput {
    pub name: String,
    pub desc: Option<String>,
    pub max_payload_size: Option<u64>,
    pub status: Option<i8>,
    pub visibility: Option<u8>, // 0: private; 1: public
    pub session_expires_in_ms: Option<u64>,
}

impl UpdateNamespaceInput {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(max_payload_size) = self.max_payload_size {
            if max_payload_size == 0 {
                Err("max_payload_size should be greater than 0".to_string())?;
            }
            if max_payload_size > MAX_PAYLOAD_SIZE {
                Err(format!(
                    "max_payload_size should be less than or equal to {}",
                    MAX_PAYLOAD_SIZE
                ))?;
            }
        }

        if let Some(status) = self.status {
            if !(-1i8..=1i8).contains(&status) {
                Err("status should be -1, 0 or 1".to_string())?;
            }
        }

        if let Some(visibility) = self.visibility {
            if visibility != 0 && visibility != 1 {
                Err("visibility should be 0 or 1".to_string())?;
            }
        }
        Ok(())
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct NamespaceDelegatorsInput {
    pub ns: String,
    pub name: String,
    pub delegators: BTreeSet<Principal>,
}

impl NamespaceDelegatorsInput {
    pub fn validate(&self) -> Result<(), String> {
        validate_key(&self.name)?;
        validate_principals(&self.delegators)?;
        Ok(())
    }
}
