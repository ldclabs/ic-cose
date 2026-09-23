use ic_cose_chain_key::{self as chain_key, Operation, PublicKey};
use ic_cose_types::types::PublicKeyOutput;

pub fn sign_with_ecdsa_cost(
    key_name: &str,
    path: &[Vec<u8>],
    message_hash: &[u8],
) -> Result<u128, String> {
    let hash = message_hash
        .try_into()
        .map_err(|_| "message must be 32 bytes")?;
    Operation::ecdsa(key_name.into(), path.to_vec(), hash)
        .cost()?
        .total()
}
pub fn derive_public_key(
    key: &PublicKeyOutput,
    path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    chain_key::derive_ecdsa_public_key(
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
pub async fn sign_with_ecdsa(
    key_name: String,
    path: Vec<Vec<u8>>,
    message_hash: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let hash = message_hash
        .as_slice()
        .try_into()
        .map_err(|_| "message must be 32 bytes")?;
    Operation::ecdsa(key_name, path, hash)
        .execute()
        .await
        .map_err(|e| format!("sign_with_ecdsa failed: {e:?}"))
}
pub async fn ecdsa_public_key(
    key_name: String,
    path: Vec<Vec<u8>>,
) -> Result<PublicKeyOutput, String> {
    chain_key::ecdsa_public_key(key_name, path)
        .await
        .map(|p| PublicKeyOutput {
            public_key: p.public_key.into(),
            chain_code: p.chain_code.into(),
        })
}
