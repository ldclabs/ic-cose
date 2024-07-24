use candid::{CandidType, Principal};
use coset::{
    CoseEncrypt0, CoseEncrypt0Builder, CoseKeyBuilder, HeaderBuilder, Label, RegisteredLabel,
    TaggedCborSerializable,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    crypto::{aes256_gcm_decrypt, aes256_gcm_encrypt},
    format_error, skip_prefix, validate_key, ByteN,
};

pub use coset::{iana, CborSerializable, CoseKey};

pub const CBOR_TAG: [u8; 3] = [0xd9, 0xd9, 0xf7];
pub const ENCRYPT0_TAG: [u8; 1] = [0xd0];
pub const SIGN1_TAG: [u8; 1] = [0xd2];

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyInput {
    pub ns: String,
    pub derivation_path: Vec<ByteBuf>,
    pub algorithm: Option<String>,
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignInput {
    pub ns: String,
    pub derivation_path: Vec<ByteBuf>,
    pub message: ByteBuf,
    pub algorithm: Option<String>,
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ECDHInput {
    pub nonce: ByteN<12>,               // should be random for each request
    pub public_key: ByteN<32>,          // client side ECDH public key
    pub partial_key: Option<ByteN<32>>, // should provide for encrypted payload with BYOK
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ECDHOutput<T> {
    pub payload: T,            // should be random for each request
    pub public_key: ByteN<32>, // server side ECDH public key
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SettingPathInput {
    pub ns: String,
    pub client: bool,
    pub subject: Option<Principal>, // default is caller
    pub key: Option<String>,
}

impl SettingPathInput {
    pub fn validate(&self) -> Result<(), String> {
        validate_key(&self.ns)?;
        if let Some(ref key) = self.key {
            validate_key(key)?;
        }
        Ok(())
    }
}

pub fn try_decode_encrypt0(payload: &[u8]) -> Result<CoseEncrypt0, String> {
    CoseEncrypt0::from_slice(skip_prefix(&ENCRYPT0_TAG, payload)).map_err(format_error)
}

pub fn cose_encrypt0(
    payload: &[u8], // plain payload
    secret: &[u8; 32],
    aad: &[u8],
    nonce: [u8; 12],
) -> Result<ByteBuf, String> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::A256GCM)
        .build();
    let unprotected = HeaderBuilder::new().iv(nonce.to_vec());

    let e0 = CoseEncrypt0Builder::new()
        .protected(protected)
        .unprotected(unprotected.build())
        .create_ciphertext(payload, aad, |plain_data, enc| {
            aes256_gcm_encrypt(secret, &nonce, enc, plain_data).unwrap()
        })
        .build();
    let payload = e0.to_tagged_vec().map_err(format_error)?;
    Ok(ByteBuf::from(payload))
}

pub fn cose_decrypt0(
    payload: &[u8], // COSE_Encrypt0 item
    secret: &[u8; 32],
    aad: &[u8],
) -> Result<ByteBuf, String> {
    let e0 = CoseEncrypt0::from_slice(skip_prefix(&ENCRYPT0_TAG, payload)).map_err(format_error)?;
    let nonce = e0.unprotected.iv.first_chunk::<12>().ok_or_else(|| {
        format!(
            "invalid nonce length, expected 12, got {}",
            e0.unprotected.iv.len()
        )
    })?;
    let plain_data = e0.decrypt(aad, |cipher_data, enc| {
        aes256_gcm_decrypt(secret, nonce, enc, cipher_data)
    })?;
    Ok(ByteBuf::from(plain_data))
}

pub fn cose_aes256_key(secret: [u8; 32]) -> CoseKey {
    CoseKeyBuilder::new_symmetric_key(secret.into())
        .algorithm(iana::Algorithm::A256GCM)
        .build()
}

pub fn get_cose_key_secret(key: CoseKey) -> Result<[u8; 32], String> {
    let key_label = match key.kty {
        RegisteredLabel::Assigned(iana::KeyType::Symmetric) => {
            Label::Int(iana::SymmetricKeyParameter::K as i64)
        }
        RegisteredLabel::Assigned(iana::KeyType::OKP) => {
            Label::Int(iana::OkpKeyParameter::D as i64)
        }
        RegisteredLabel::Assigned(iana::KeyType::EC2) => {
            Label::Int(iana::Ec2KeyParameter::D as i64)
        }
        _ => {
            return Err("unsupport key type".to_string());
        }
    };

    for (label, value) in key.params {
        if label == key_label {
            let val: [u8; 32] = value
                .into_bytes()
                .map_err(|_| "invalid secret key".to_string())?
                .try_into()
                .map_err(|_| "invalid secret key".to_string())?;
            return Ok(val);
        }
    }
    Err("missing secret key".to_string())
}
