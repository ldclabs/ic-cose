use candid::CandidType;
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use std::collections::BTreeMap;

pub mod namespace;
pub mod setting;
pub mod state;

pub use setting::SettingPath;

pub type MapValue =
    BTreeMap<String, icrc_ledger_types::icrc::generic_metadata_value::MetadataValue>;

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SchnorrAlgorithm {
    #[serde(rename = "bip340secp256k1")]
    Bip340Secp256k1,
    #[serde(rename = "ed25519")]
    Ed25519,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyInput {
    pub ns: String,
    pub derivation_path: Vec<ByteBuf>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyOutput {
    pub public_key: ByteBuf,
    pub chain_code: ByteBuf,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignInput {
    pub ns: String,
    pub derivation_path: Vec<ByteBuf>,
    pub message: ByteBuf,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignIdentityInput {
    pub ns: String,
    pub audience: String,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ECDHInput {
    pub nonce: ByteArray<12>,      // should be random for each request
    pub public_key: ByteArray<32>, // client side ECDH public key
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ECDHOutput<T> {
    pub payload: T,                // should be random for each request
    pub public_key: ByteArray<32>, // server side ECDH public key
}
