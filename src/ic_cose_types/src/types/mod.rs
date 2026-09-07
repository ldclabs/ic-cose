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

/// Maximum byte length of a namespace or setting description.
pub const MAX_DESC_SIZE: usize = 1024;
/// Maximum caller-supplied suffix components. Canisters prepend two internal
/// components before calling the management canister, whose protocol limit is
/// 255 components.
pub const MAX_DERIVATION_PATH_COMPONENTS: usize = 253;
/// Application-level bound for one derivation component.
pub const MAX_DERIVATION_COMPONENT_BYTES: usize = 64;
/// Application-level bound for all caller-supplied derivation bytes.
pub const MAX_DERIVATION_PATH_BYTES: usize = 4 * 1024;
/// Maximum message accepted by the generic Schnorr signing endpoint.
pub const MAX_SIGN_MESSAGE_BYTES: usize = 64 * 1024;
/// Maximum CWT audience length.
pub const MAX_AUDIENCE_BYTES: usize = 1024;
/// Defensive ceiling for DER public keys and basic signatures.
pub const MAX_IDENTITY_CREDENTIAL_BYTES: usize = 1024;

/// Validates a description string against [`MAX_DESC_SIZE`].
pub fn validate_desc(desc: &str) -> Result<(), String> {
    if desc.len() > MAX_DESC_SIZE {
        return Err(format!("desc length exceeds the limit {}", MAX_DESC_SIZE));
    }
    Ok(())
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyInput {
    pub ns: String,
    pub derivation_path: Vec<ByteBuf>,
}

impl PublicKeyInput {
    pub fn validate(&self) -> Result<(), String> {
        crate::validate_str(&self.ns)?;
        validate_derivation_path(&self.derivation_path)
    }
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

impl SignInput {
    pub fn validate(&self) -> Result<(), String> {
        crate::validate_str(&self.ns)?;
        validate_derivation_path(&self.derivation_path)?;
        if self.message.len() > MAX_SIGN_MESSAGE_BYTES {
            return Err(format!(
                "message length exceeds the limit {}",
                MAX_SIGN_MESSAGE_BYTES
            ));
        }
        Ok(())
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignIdentityInput {
    pub ns: String,
    pub audience: String,
}

impl SignIdentityInput {
    pub fn validate(&self) -> Result<(), String> {
        crate::validate_str(&self.ns)?;
        if self.audience.is_empty() {
            return Err("audience should not be empty".to_string());
        }
        if self.audience.len() > MAX_AUDIENCE_BYTES {
            return Err(format!(
                "audience length exceeds the limit {}",
                MAX_AUDIENCE_BYTES
            ));
        }
        Ok(())
    }
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

impl SignDelegationInput {
    pub fn validate(&self) -> Result<(), String> {
        crate::validate_str(&self.ns)?;
        crate::validate_str(&self.name.to_ascii_lowercase())?;
        if self.pubkey.is_empty() || self.pubkey.len() > MAX_IDENTITY_CREDENTIAL_BYTES {
            return Err(format!(
                "public key length should be in 1..={}",
                MAX_IDENTITY_CREDENTIAL_BYTES
            ));
        }
        if self.sig.is_empty() || self.sig.len() > MAX_IDENTITY_CREDENTIAL_BYTES {
            return Err(format!(
                "signature length should be in 1..={}",
                MAX_IDENTITY_CREDENTIAL_BYTES
            ));
        }
        Ok(())
    }
}

pub fn validate_derivation_path(path: &[ByteBuf]) -> Result<(), String> {
    if path.len() > MAX_DERIVATION_PATH_COMPONENTS {
        return Err(format!(
            "derivation path length exceeds the limit {}",
            MAX_DERIVATION_PATH_COMPONENTS
        ));
    }
    let mut total = 0usize;
    for component in path {
        if component.len() > MAX_DERIVATION_COMPONENT_BYTES {
            return Err(format!(
                "derivation path component length exceeds the limit {}",
                MAX_DERIVATION_COMPONENT_BYTES
            ));
        }
        total = total.saturating_add(component.len());
    }
    if total > MAX_DERIVATION_PATH_BYTES {
        return Err(format!(
            "derivation path bytes exceed the limit {}",
            MAX_DERIVATION_PATH_BYTES
        ));
    }
    Ok(())
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

    #[test]
    fn expensive_inputs_are_bounded_before_canister_work() {
        let valid = PublicKeyInput {
            ns: "namespace_1".to_string(),
            derivation_path: vec![ByteBuf::from(vec![1; MAX_DERIVATION_COMPONENT_BYTES])],
        };
        assert!(valid.validate().is_ok());

        let mut oversized = valid.clone();
        oversized.derivation_path[0] = ByteBuf::from(vec![1; MAX_DERIVATION_COMPONENT_BYTES + 1]);
        assert!(oversized.validate().unwrap_err().contains("component"));

        let identity = SignIdentityInput {
            ns: "namespace_1".to_string(),
            audience: String::new(),
        };
        assert_eq!(
            identity.validate().unwrap_err(),
            "audience should not be empty"
        );

        let delegation = SignDelegationInput {
            ns: "namespace_1".to_string(),
            name: "fixed".to_string(),
            pubkey: ByteBuf::new(),
            sig: ByteBuf::from([1]),
        };
        assert!(delegation.validate().unwrap_err().contains("public key"));
    }
}
