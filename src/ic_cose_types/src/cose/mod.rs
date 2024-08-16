use coset::{CoseKeyBuilder, Label, RegisteredLabel};
use hmac::{Hmac, Mac};
use sha3::{Digest, Sha3_256};

pub mod aes;
pub mod cwt;
pub mod ecdh;
pub mod ed25519;
pub mod encrypt0;
pub mod k256;
pub mod sign1;

pub use coset::{iana, CborSerializable, CoseKey};

pub const CBOR_TAG: [u8; 3] = [0xd9, 0xd9, 0xf7];
pub const ENCRYPT0_TAG: [u8; 1] = [0xd0];
pub const SIGN1_TAG: [u8; 1] = [0xd2];

pub fn format_error<T>(err: T) -> String
where
    T: std::fmt::Debug,
{
    format!("{:?}", err)
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
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

pub fn skip_prefix<'a>(tag: &'a [u8], data: &'a [u8]) -> &'a [u8] {
    if data.starts_with(tag) {
        &data[tag.len()..]
    } else {
        data
    }
}

pub fn cose_aes256_key(secret: [u8; 32], key_id: Vec<u8>) -> CoseKey {
    CoseKeyBuilder::new_symmetric_key(secret.into())
        .algorithm(iana::Algorithm::A256GCM)
        .key_id(key_id)
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
