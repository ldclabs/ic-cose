//! Adapts the shared chain-key helpers to this canister's Candid key type.
use ic_cdk_management_canister::SchnorrAlgorithm;
use ic_cose_chain_key::{self as chain_key, PublicKey};
use ic_cose_types::types::PublicKeyOutput;

fn to_chain_key(key: &PublicKeyOutput) -> PublicKey {
    PublicKey {
        public_key: key.public_key.to_vec(),
        chain_code: key.chain_code.to_vec(),
    }
}

fn to_output(key: PublicKey) -> PublicKeyOutput {
    PublicKeyOutput {
        public_key: key.public_key.into(),
        chain_code: key.chain_code.into(),
    }
}

pub fn derive_ecdsa_public_key(
    key: &PublicKeyOutput,
    path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    chain_key::derive_ecdsa_public_key(&to_chain_key(key), path).map(to_output)
}

pub fn derive_schnorr_public_key(
    alg: SchnorrAlgorithm,
    key: &PublicKeyOutput,
    path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    chain_key::derive_schnorr_public_key(alg, &to_chain_key(key), path).map(to_output)
}

pub async fn ecdsa_public_key(
    key_name: String,
    path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    chain_key::ecdsa_public_key(key_name, path)
        .await
        .map(to_output)
}

pub async fn schnorr_public_key(
    key_name: String,
    alg: SchnorrAlgorithm,
    path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    chain_key::schnorr_public_key(key_name, alg, path)
        .await
        .map(to_output)
}
