use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, BTreeSet};

use crate::validate_str;

pub const CHUNK_SIZE: u32 = 256 * 1024;
pub const MAX_DEK_SIZE: u64 = 3 * 1024;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SettingInfo {
    pub key: ByteBuf,
    pub subject: Principal,
    pub desc: String,
    pub created_at: u64, // unix timestamp in milliseconds
    pub updated_at: u64, // unix timestamp in milliseconds
    pub status: i8,      // -1: archived; 0: readable and writable; 1: readonly
    pub version: u32,
    pub readers: BTreeSet<Principal>, // readers can read the setting
    pub tags: BTreeMap<String, String>, // tags for query
    pub dek: Option<ByteBuf>, // Data Encryption Key encrypted by BYOK or vetKey in COSE_Encrypt0
    pub payload: Option<ByteBuf>, // encrypted or plain payload
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SettingPath {
    pub ns: String,
    pub user_owned: bool,
    pub subject: Option<Principal>, // default to caller
    pub key: ByteBuf,
    pub version: u32,
}

impl SettingPath {
    pub fn validate(&self) -> Result<(), String> {
        validate_str(&self.ns)?;
        if self.key.is_empty() {
            return Err("key should not be empty".to_string());
        }
        if self.key.len() > 64 {
            return Err("key length exceeds the limit 64".to_string());
        }
        Ok(())
    }
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct CreateSettingInput {
    pub payload: Option<ByteBuf>,
    pub desc: Option<String>,
    pub status: Option<i8>,
    pub tags: Option<BTreeMap<String, String>>,
    pub dek: Option<ByteBuf>,
}

impl CreateSettingInput {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(status) = self.status {
            if !(0i8..=1i8).contains(&status) {
                Err("status should be 0 or 1".to_string())?;
            }
        }
        if let Some(ref tags) = self.tags {
            for (k, _) in tags.iter() {
                validate_str(k)?;
            }
        }
        if let Some(ref dek) = self.dek {
            if dek.len() > MAX_DEK_SIZE as usize {
                Err("DEK size exceeds the limit".to_string())?;
            }
        }
        Ok(())
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct CreateSettingOutput {
    pub created_at: u64,
    pub updated_at: u64,
    pub version: u32,
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateSettingInfoInput {
    pub desc: Option<String>,
    pub status: Option<i8>,
    pub tags: Option<BTreeMap<String, String>>,
}

impl UpdateSettingInfoInput {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(status) = self.status {
            if !(-1i8..=1i8).contains(&status) {
                Err("status should be -1, 0 or 1".to_string())?;
            }
        }
        if let Some(ref tags) = self.tags {
            for (k, _) in tags.iter() {
                validate_str(k)?;
            }
        }
        Ok(())
    }
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateSettingPayloadInput {
    pub payload: Option<ByteBuf>, // plain or encrypted payload
    pub status: Option<i8>,
    pub deprecate_current: Option<bool>, // deprecate the current version
    pub dek: Option<ByteBuf>,
}

impl UpdateSettingPayloadInput {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(status) = self.status {
            if !(-1i8..=1i8).contains(&status) {
                Err("status should be -1, 0 or 1".to_string())?;
            }
        }
        if self.payload.is_none() && self.dek.is_none() {
            Err("payload or dek should be provided".to_string())?;
        }
        if let Some(ref dek) = self.dek {
            if dek.len() > MAX_DEK_SIZE as usize {
                Err("DEK size exceeds the limit".to_string())?;
            }
        }
        Ok(())
    }
}

pub type UpdateSettingOutput = CreateSettingOutput;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SettingArchivedPayload {
    pub version: u32,
    pub archived_at: u64,
    pub deprecated: bool, // true if the payload should not be used for some reason
    pub payload: Option<ByteBuf>,
    pub dek: Option<ByteBuf>, // exist if the payload is encrypted
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn setting_path_validate_checks_namespace_and_key() {
        let path = SettingPath {
            ns: "namespace_1".to_string(),
            key: ByteBuf::from(vec![1]),
            ..Default::default()
        };
        assert!(path.validate().is_ok());

        let mut invalid = path.clone();
        invalid.ns = "Namespace".to_string();
        assert_eq!(invalid.validate().unwrap_err(), "invalid character: N");

        let mut invalid = path.clone();
        invalid.key = ByteBuf::new();
        assert_eq!(invalid.validate().unwrap_err(), "key should not be empty");

        let mut invalid = path;
        invalid.key = ByteBuf::from(vec![1; 65]);
        assert_eq!(
            invalid.validate().unwrap_err(),
            "key length exceeds the limit 64"
        );
    }

    #[test]
    fn create_setting_validate_checks_status_tags_and_dek() {
        assert!(CreateSettingInput::default().validate().is_ok());

        let input = CreateSettingInput {
            status: Some(-1),
            ..Default::default()
        };
        assert_eq!(input.validate().unwrap_err(), "status should be 0 or 1");

        let input = CreateSettingInput {
            tags: Some(BTreeMap::from([(
                "Invalid".to_string(),
                "value".to_string(),
            )])),
            ..Default::default()
        };
        assert_eq!(input.validate().unwrap_err(), "invalid character: I");

        let input = CreateSettingInput {
            dek: Some(ByteBuf::from(vec![0; MAX_DEK_SIZE as usize + 1])),
            ..Default::default()
        };
        assert_eq!(input.validate().unwrap_err(), "DEK size exceeds the limit");
    }

    #[test]
    fn update_setting_info_validate_checks_status_and_tags() {
        assert!(UpdateSettingInfoInput::default().validate().is_ok());

        let input = UpdateSettingInfoInput {
            status: Some(2),
            ..Default::default()
        };
        assert_eq!(input.validate().unwrap_err(), "status should be -1, 0 or 1");

        let input = UpdateSettingInfoInput {
            tags: Some(BTreeMap::from([(
                "invalid-tag".to_string(),
                "value".to_string(),
            )])),
            ..Default::default()
        };
        assert_eq!(input.validate().unwrap_err(), "invalid character: -");
    }

    #[test]
    fn update_setting_payload_validate_checks_payload_status_and_dek() {
        assert_eq!(
            UpdateSettingPayloadInput::default().validate().unwrap_err(),
            "payload or dek should be provided"
        );

        let input = UpdateSettingPayloadInput {
            payload: Some(ByteBuf::new()),
            ..Default::default()
        };
        assert!(input.validate().is_ok());

        let input = UpdateSettingPayloadInput {
            payload: Some(ByteBuf::new()),
            status: Some(2),
            ..Default::default()
        };
        assert_eq!(input.validate().unwrap_err(), "status should be -1, 0 or 1");

        let input = UpdateSettingPayloadInput {
            dek: Some(ByteBuf::from(vec![0; MAX_DEK_SIZE as usize + 1])),
            ..Default::default()
        };
        assert_eq!(input.validate().unwrap_err(), "DEK size exceeds the limit");
    }
}
