use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::validate_desc;
use crate::{validate_principals, validate_principals_not_anonymous, validate_str};

pub const MAX_PAYLOAD_SIZE: u64 = 2_000_000; // 2MB

fn validate_max_payload_size(max_payload_size: u64) -> Result<(), String> {
    if max_payload_size == 0 {
        Err("max_payload_size should be greater than 0".to_string())?;
    }
    if max_payload_size > MAX_PAYLOAD_SIZE {
        Err(format!(
            "max_payload_size should be less than or equal to {}",
            MAX_PAYLOAD_SIZE
        ))?;
    }
    Ok(())
}

fn validate_visibility(visibility: u8) -> Result<(), String> {
    if visibility != 0 && visibility != 1 {
        Err("visibility should be 0 or 1".to_string())?;
    }
    Ok(())
}

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
        validate_str(&self.name)?;
        validate_principals(&self.managers)?;
        validate_principals_not_anonymous(&self.auditors)?;
        validate_principals_not_anonymous(&self.users)?;
        if let Some(ref desc) = self.desc {
            validate_desc(desc)?;
        }
        if let Some(max_payload_size) = self.max_payload_size {
            validate_max_payload_size(max_payload_size)?;
        }
        validate_visibility(self.visibility)?;
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
        validate_str(&self.name)?;
        if let Some(ref desc) = self.desc {
            validate_desc(desc)?;
        }
        if let Some(max_payload_size) = self.max_payload_size {
            validate_max_payload_size(max_payload_size)?;
        }

        if let Some(status) = self.status {
            if !(-1i8..=1i8).contains(&status) {
                Err("status should be -1, 0 or 1".to_string())?;
            }
        }

        if let Some(visibility) = self.visibility {
            validate_visibility(visibility)?;
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
        validate_str(&self.ns)?;
        validate_str(&self.name)?;
        validate_principals(&self.delegators)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use candid::encode_one;

    fn principal_set() -> BTreeSet<Principal> {
        BTreeSet::from([Principal::management_canister()])
    }

    fn create_namespace_input() -> CreateNamespaceInput {
        CreateNamespaceInput {
            name: "namespace_1".to_string(),
            visibility: 0,
            managers: principal_set(),
            ..Default::default()
        }
    }

    #[test]
    fn create_namespace_validate_accepts_valid_input() {
        let input = create_namespace_input();
        assert!(!format!("{:?}", input.clone()).is_empty());
        assert!(!encode_one(input.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&input).is_empty());
        assert!(input.validate().is_ok());
    }

    #[test]
    fn create_namespace_validate_rejects_invalid_input() {
        let mut input = create_namespace_input();
        input.managers.clear();
        assert_eq!(input.validate().unwrap_err(), "principals cannot be empty");

        let mut input = create_namespace_input();
        input.auditors.insert(Principal::anonymous());
        assert_eq!(
            input.validate().unwrap_err(),
            "anonymous user is not allowed"
        );

        let mut input = create_namespace_input();
        input.users.insert(Principal::anonymous());
        assert_eq!(
            input.validate().unwrap_err(),
            "anonymous user is not allowed"
        );

        let mut input = create_namespace_input();
        input.visibility = 2;
        assert_eq!(input.validate().unwrap_err(), "visibility should be 0 or 1");

        let mut input = create_namespace_input();
        input.max_payload_size = Some(0);
        assert_eq!(
            input.validate().unwrap_err(),
            "max_payload_size should be greater than 0"
        );

        let mut input = create_namespace_input();
        input.max_payload_size = Some(MAX_PAYLOAD_SIZE + 1);
        assert_eq!(
            input.validate().unwrap_err(),
            format!(
                "max_payload_size should be less than or equal to {}",
                MAX_PAYLOAD_SIZE
            )
        );
    }

    #[test]
    fn update_namespace_validate_checks_name_and_ranges() {
        assert_eq!(
            UpdateNamespaceInput::default().validate().unwrap_err(),
            "empty string"
        );

        let mut input = UpdateNamespaceInput {
            name: "namespace_1".to_string(),
            ..Default::default()
        };
        assert!(!format!("{:?}", input.clone()).is_empty());
        assert!(!encode_one(input.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&input).is_empty());
        assert!(input.validate().is_ok());

        input.status = Some(2);
        assert_eq!(input.validate().unwrap_err(), "status should be -1, 0 or 1");

        input.status = None;
        input.visibility = Some(3);
        assert_eq!(input.validate().unwrap_err(), "visibility should be 0 or 1");

        input.visibility = None;
        input.max_payload_size = Some(0);
        assert_eq!(
            input.validate().unwrap_err(),
            "max_payload_size should be greater than 0"
        );

        input.max_payload_size = Some(MAX_PAYLOAD_SIZE + 1);
        assert_eq!(
            input.validate().unwrap_err(),
            format!(
                "max_payload_size should be less than or equal to {}",
                MAX_PAYLOAD_SIZE
            )
        );
    }

    #[test]
    fn namespace_delegators_validate_checks_all_fields() {
        let input = NamespaceDelegatorsInput {
            ns: "namespace_1".to_string(),
            name: "fixed_name".to_string(),
            delegators: principal_set(),
        };
        assert!(!format!("{:?}", input.clone()).is_empty());
        assert!(!encode_one(input.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&input).is_empty());
        assert!(input.validate().is_ok());

        let mut invalid = input.clone();
        invalid.ns = String::new();
        assert_eq!(invalid.validate().unwrap_err(), "empty string");

        let mut invalid = input.clone();
        invalid.name = "Invalid".to_string();
        assert_eq!(invalid.validate().unwrap_err(), "invalid character: I");

        let mut invalid = input;
        invalid.delegators.clear();
        assert_eq!(
            invalid.validate().unwrap_err(),
            "principals cannot be empty"
        );
    }

    #[test]
    fn namespace_info_derived_traits_work() {
        let info = NamespaceInfo {
            name: "namespace_1".to_string(),
            desc: "desc".to_string(),
            created_at: 1,
            updated_at: 2,
            max_payload_size: 1024,
            payload_bytes_total: 10,
            status: 0,
            visibility: 1,
            managers: principal_set(),
            auditors: principal_set(),
            users: principal_set(),
            gas_balance: 100,
            fixed_id_names: BTreeMap::from([("fixed".to_string(), principal_set())]),
            session_expires_in_ms: 1000,
        };
        assert_eq!(info.clone(), info);
        assert!(!format!("{info:?}").is_empty());
        assert!(!encode_one(info.clone()).unwrap().is_empty());
        assert!(!crate::to_cbor_bytes(&info).is_empty());
    }
}
