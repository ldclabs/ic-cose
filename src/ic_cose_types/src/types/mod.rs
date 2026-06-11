use candid::CandidType;
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use std::collections::BTreeMap;

pub use ic_cdk_management_canister::SchnorrAlgorithm;
pub mod namespace;
pub mod setting;
pub mod state;
pub mod wasm;

pub use setting::SettingPath;

pub type MapValue =
    BTreeMap<String, icrc_ledger_types::icrc::generic_metadata_value::MetadataValue>;

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
    pub nonce: ByteArray<12>, // must be unique for each request with the derived AES-GCM key
    pub public_key: ByteArray<32>, // client side ECDH public key
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ECDHOutput<T> {
    pub payload: T,                // encrypted response payload
    pub public_key: ByteArray<32>, // server side ECDH public key
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignDelegationInput {
    pub ns: String,
    pub name: String,
    pub pubkey: ByteBuf,
    pub sig: ByteBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::{decode_one, encode_one};

    fn assert_candid_roundtrip<T>(value: T)
    where
        T: CandidType
            + Clone
            + std::fmt::Debug
            + PartialEq
            + serde::Serialize
            + for<'de> candid::Deserialize<'de>,
    {
        let encoded = encode_one(value.clone()).unwrap();
        let decoded: T = decode_one(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert!(!format!("{value:?}").is_empty());
        assert!(!crate::to_cbor_bytes(&value).is_empty());
    }

    #[test]
    fn request_and_response_types_are_constructible() {
        let derivation_path = vec![ByteBuf::from(vec![1, 2])];
        let public_input = PublicKeyInput {
            ns: "namespace_1".to_string(),
            derivation_path: derivation_path.clone(),
        };
        assert_eq!(public_input.derivation_path, derivation_path);
        assert_candid_roundtrip(public_input);

        let public_output = PublicKeyOutput {
            public_key: ByteBuf::from(vec![3]),
            chain_code: ByteBuf::from(vec![4]),
        };
        assert_eq!(public_output.chain_code, ByteBuf::from(vec![4]));
        assert_candid_roundtrip(public_output);

        let sign_input = SignInput {
            ns: "namespace_1".to_string(),
            derivation_path: vec![ByteBuf::from(vec![5])],
            message: ByteBuf::from(vec![6]),
        };
        assert_eq!(sign_input.message, ByteBuf::from(vec![6]));
        assert_candid_roundtrip(sign_input);

        let identity_input = SignIdentityInput {
            ns: "namespace_1".to_string(),
            audience: "audience".to_string(),
        };
        assert_eq!(identity_input.audience, "audience");
        assert_candid_roundtrip(identity_input);

        let ecdh_input = ECDHInput {
            nonce: [1u8; 12].into(),
            public_key: [2u8; 32].into(),
        };
        assert_eq!(ecdh_input.nonce.as_ref(), &[1u8; 12]);
        assert_candid_roundtrip(ecdh_input);

        let ecdh_output = ECDHOutput {
            payload: ByteBuf::from(vec![7]),
            public_key: [8u8; 32].into(),
        };
        assert_eq!(ecdh_output.public_key.as_ref(), &[8u8; 32]);
        assert_candid_roundtrip(ecdh_output);

        let delegation = SignDelegationInput {
            ns: "namespace_1".to_string(),
            name: "fixed".to_string(),
            pubkey: ByteBuf::from(vec![9]),
            sig: ByteBuf::from(vec![10]),
        };
        assert_eq!(delegation.name, "fixed");
        assert_candid_roundtrip(delegation);
        assert_eq!(SchnorrAlgorithm::Ed25519, SchnorrAlgorithm::Ed25519);
    }
}
