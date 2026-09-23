use ic_cdk_management_canister::SchnorrAlgorithm;
use ic_cose_chain_key::{self as chain_key, PublicKey};
use ic_cose_types::types::PublicKeyOutput;

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
