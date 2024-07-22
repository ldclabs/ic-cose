use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::validate_key;

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NamespaceInfo {
    pub key: String,
    pub name: String,
    pub desc: String,
    pub created_at: u64,               // unix timestamp in milliseconds
    pub updated_at: u64,               // unix timestamp in milliseconds
    pub max_payload_size: u64,         // max payload size in bytes
    pub total_payload_size: u64,       // total payload size in bytes
    pub status: i8,                    // -1: archived; 0: readable and writable; 1: readonly
    pub visibility: u8,                // 0: private; 1: public
    pub managers: BTreeSet<Principal>, // managers can read and write all settings
    pub auditors: BTreeSet<Principal>, // auditors can read all settings
    pub members: BTreeSet<Principal>,  // members can read and write settings they created
    pub settings_count: u64,           // settings created by managers for members
    pub client_settings_count: u64,    // settings created by members
    pub balance: u128,                 // cycles
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct CreateNamespaceInput {
    pub key: String,
    pub name: String,
    pub visibility: u8, // 0: private; 1: public
    pub desc: Option<String>,
    pub max_payload_size: Option<u64>, // max payload size in bytes
    pub managers: BTreeSet<Principal>, // managers can read and write all settings
}

impl CreateNamespaceInput {
    pub fn validate(&self) -> Result<(), String> {
        validate_key(&self.key)?;
        if self.name.trim().is_empty() {
            Err("invalid namespace name".to_string())?;
        }
        if let Some(max_payload_size) = self.max_payload_size {
            if max_payload_size == 0 {
                Err("max_payload_size should be greater than 0".to_string())?;
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
    pub name: Option<String>,
    pub desc: Option<String>,
    pub max_payload_size: Option<u64>,
    pub status: Option<i8>,
    pub visibility: Option<u8>, // 0: private; 1: public
}

impl UpdateNamespaceInput {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(name) = &self.name {
            if name.trim().is_empty() {
                Err("invalid namespace name".to_string())?;
            }
        }
        if let Some(max_payload_size) = self.max_payload_size {
            if max_payload_size == 0 {
                Err("max_payload_size should be greater than 0".to_string())?;
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
