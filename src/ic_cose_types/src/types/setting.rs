use candid::{CandidType, Principal};
use ciborium::{from_reader, Value};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, BTreeSet};

use super::CosePath;
use crate::validate_key;

pub const CHUNK_SIZE: u32 = 256 * 1024;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SettingInfo {
    pub key: String,
    pub subject: Principal,
    pub desc: String,
    pub created_at: u64, // unix timestamp in milliseconds
    pub updated_at: u64, // unix timestamp in milliseconds
    pub status: i8, // -1: archived; 0: readable and writable; 1: readonlypub auditors: BTreeSet<Principal>,
    pub version: u32,
    pub readers: BTreeSet<Principal>, // readers can read the setting
    pub tags: BTreeMap<String, String>, // tags for query
    pub dek: Option<ByteBuf>, // Data Encryption Key that encrypted by BYOK or vetKey in COSE_Encrypt0
    pub payload: Option<ByteBuf>, // plain payload
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SettingPath {
    pub ns: String,
    pub client_owned: bool,
    pub subject: Option<Principal>,
    pub key: String,
    pub version: u32,
}

impl SettingPath {
    pub fn validate(&self) -> Result<(), String> {
        validate_key(&self.ns)?;
        validate_key(&self.key)?;
        Ok(())
    }
}

impl From<CosePath> for SettingPath {
    fn from(input: CosePath) -> Self {
        Self {
            ns: input.ns,
            client_owned: input.client_owned,
            subject: input.subject,
            key: input.key.unwrap_or_default(),
            version: 0,
        }
    }
}

pub fn try_decode_payload(max_size: u64, payload: &[u8]) -> Result<Value, String> {
    if max_size > 0 && payload.len() as u64 > max_size {
        return Err(format!(
            "payload size {} exceeds the limit {}",
            payload.len(),
            max_size
        ));
    }

    from_reader(payload).map_err(|err| format!("decode CBOR payload failed: {:?}", err))
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct CreateSettingInput {
    pub payload: ByteBuf,
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
                validate_key(k)?;
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

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
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
                validate_key(k)?;
            }
        }
        Ok(())
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct UpdateSettingPayloadInput {
    pub payload: ByteBuf, // plain or encrypted payload
    pub status: Option<i8>,
}

impl UpdateSettingPayloadInput {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(status) = self.status {
            if !(-1i8..=1i8).contains(&status) {
                Err("status should be -1, 0 or 1".to_string())?;
            }
        }
        Ok(())
    }
}

pub type UpdateSettingOutput = CreateSettingOutput;
