use ic_cose_chain_key::{self as chain_key, PublicKey};
use ic_cose_types::types::PublicKeyOutput;

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
