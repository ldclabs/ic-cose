use ic_cdk_management_canister::SchnorrAlgorithm;
use ic_cose_chain_key::{self as chain_key, Operation, PublicKey};
use ic_cose_types::types::PublicKeyOutput;

pub fn sign_with_schnorr_cost(
    key_name: &str,
    alg: SchnorrAlgorithm,
    path: &[Vec<u8>],
    message: &[u8],
) -> Result<u128, String> {
    Operation::schnorr(key_name.into(), alg, path.to_vec(), message.to_vec())
        .cost()?
        .total()
}
pub fn derive_schnorr_public_key(
    alg: SchnorrAlgorithm,
    key: &PublicKeyOutput,
    path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    chain_key::derive_schnorr_public_key(
        alg,
        &PublicKey {
            public_key: key.public_key.to_vec(),
            chain_code: key.chain_code.to_vec(),
        },
        path,
    )
    .map(|p| PublicKeyOutput {
        public_key: p.public_key.into(),
        chain_code: p.chain_code.into(),
    })
}
pub async fn sign_with_schnorr(
    key_name: String,
    alg: SchnorrAlgorithm,
    path: Vec<Vec<u8>>,
    message: Vec<u8>,
) -> Result<Vec<u8>, String> {
    Operation::schnorr(key_name, alg, path, message)
        .execute()
        .await
        .map_err(|e| format!("sign_with_schnorr failed: {e:?}"))
}
pub async fn schnorr_public_key(
    key_name: String,
    alg: SchnorrAlgorithm,
    path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    chain_key::schnorr_public_key(key_name, alg, path)
        .await
        .map(|p| PublicKeyOutput {
            public_key: p.public_key.into(),
            chain_code: p.chain_code.into(),
        })
}
