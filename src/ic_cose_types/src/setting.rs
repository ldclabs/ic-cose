use candid::{CandidType, Principal};
use ciborium::{from_reader, Value};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::BTreeSet;

use crate::{format_error, validate_key, ByteN};

pub const CHUNK_SIZE: u32 = 256 * 1024;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SettingInfo {
    pub key: String,
    pub subject: Principal,
    pub desc: String,
    pub created_at: u64,              // unix timestamp in milliseconds
    pub updated_at: u64,              // unix timestamp in milliseconds
    pub status: i8, // -1: archived; 0: readable and writable; 1: readonlypub auditors: BTreeSet<Principal>,
    pub readers: BTreeSet<Principal>, // readers can read the setting
    pub ctype: u8, // CBOR Major type: 2 - byte string; 3 - text string; 4 - array; 5 - map; 6 - tagged item
    pub version: u32,
    pub hash: Option<ByteN<32>>,     // sha3 256,
    pub payload: Option<ByteBuf>,    // plain payload
    pub public_key: Option<ByteBuf>, // ECDH public key from canister
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SettingPath {
    pub ns: String,
    pub key: String,
    pub version: u32,
    pub client: bool,
    pub subject: Option<Principal>,
}

impl SettingPath {
    pub fn validate(&self) -> Result<(), String> {
        validate_key(&self.ns)?;
        validate_key(&self.key)?;
        Ok(())
    }
}

pub fn try_decode_payload(max_size: u64, ctype: u8, payload: &ByteBuf) -> Result<Value, String> {
    if max_size > 0 && payload.len() as u64 > max_size {
        return Err(format!(
            "payload size {} exceeds the limit {}",
            payload.len(),
            max_size
        ));
    }

    let val: Value = from_reader(&payload[..]).map_err(format_error)?;
    match ctype {
        2 => {
            val.as_bytes()
                .ok_or_else(|| "invalid byte string".to_string())?;
        }
        3 => {
            val.as_text()
                .ok_or_else(|| "invalid text string".to_string())?;
        }
        4 => {
            val.as_array()
                .ok_or_else(|| "invalid array items".to_string())?;
        }
        5 => {
            val.as_map()
                .ok_or_else(|| "invalid map items".to_string())?;
        }
        6 => {
            val.as_tag()
                .ok_or_else(|| "invalid tagged item".to_string())?;
        }
        _ => {
            Err("invalid CBOR major type".to_string())?;
        }
    }
    Ok(val)
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct CreateSettingInput {
    pub desc: Option<String>,
    pub status: Option<i8>,
    pub ctype: u8,
    pub payload: Option<ByteBuf>, // plain payload
}

impl CreateSettingInput {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(status) = self.status {
            if !(0i8..=1i8).contains(&status) {
                Err("status should be 0 or 1".to_string())?;
            }

            if status == 1 && self.payload.is_none() {
                Err("readonly setting should have payload".to_string())?;
            }
        }

        if !(2u8..=6u8).contains(&self.ctype) {
            Err("ctype should be in [2..6]".to_string())?;
        }
        Ok(())
    }
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct CreateSettingOutput {
    pub created_at: u64,
    pub updated_at: u64,
    pub version: u32,
    pub hash: Option<ByteN<32>>,       // sha3 256,
    pub public_key: Option<ByteN<32>>, // server side ECDH public key
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateSettingInfoInput {
    pub desc: Option<String>,
    pub status: Option<i8>,
}

impl UpdateSettingInfoInput {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(status) = self.status {
            if !(-1i8..=1i8).contains(&status) {
                Err("status should be -1, 0 or 1".to_string())?;
            }
        }
        Ok(())
    }
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateSettingPayloadInput {
    pub version: u32, // update payload only if version matches and version will be incremented
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
