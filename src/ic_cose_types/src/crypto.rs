use candid::CandidType;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::ByteN;

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyInput {
    pub namespace: String,
    pub derivation_path: Vec<ByteBuf>,
    pub algorithm: Option<String>,
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignInput {
    pub namespace: String,
    pub derivation_path: Vec<ByteBuf>,
    pub message: ByteBuf,
    pub algorithm: Option<String>,
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ECDHInput {
    pub public_key: ByteN<32>,          // client side ECDH public key
    pub nonce: ByteN<16>,               // should be random for each request
    pub partial_key: Option<ByteN<16>>, // should provide for encrypted payload with BYOK
}

pub async fn cose_re_encrypt(
    new_dek: [u8; 32],
    payload: ByteBuf, // COSE_Encrypt0 item
    raw_kek: Option<[u8; 32]>,
    cose_dek: Option<ByteBuf>, // COSE key item
) -> Result<ByteBuf, String> {
    Err("not implemented".to_string())
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha3_256_n<const N: usize>(array: [&[u8]; N]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for data in array {
        hasher.update(data);
    }
    hasher.finalize().into()
}

pub fn mac3_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha3_256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn ecdh_x25519(secret: [u8; 32], their_public: [u8; 32]) -> (SharedSecret, PublicKey) {
    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(&secret);
    (
        secret.diffie_hellman(&PublicKey::from(their_public)),
        public,
    )
}
