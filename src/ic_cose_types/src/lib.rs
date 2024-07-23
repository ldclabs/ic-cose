#![doc(html_root_url = "https://docs.rs/ic-cose-types/latest")]
#![allow(clippy::needless_doctest_main)]

use candid::Principal;
use ciborium::into_writer;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha3::{Digest, Sha3_256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Deref,
};

pub mod cose;
pub mod crypto;
pub mod namespace;
pub mod setting;
pub mod state;

mod bytes;
pub use bytes::*;

pub static ANONYMOUS: Principal = Principal::anonymous();
pub const MILLISECONDS: u64 = 1_000_000u64;

// should update to ICRC3Map
pub type MapValue = BTreeMap<String, icrc_ledger_types::icrc::generic_value::Value>;

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

// to_cbor_bytes returns the CBOR encoding of the given object that implements the Serialize trait.
pub fn to_cbor_bytes(obj: &impl Serialize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    into_writer(obj, &mut buf).expect("failed to encode in CBOR format");
    buf
}

pub fn skip_prefix<'a>(tag: &'a [u8], data: &'a [u8]) -> &'a [u8] {
    if data.starts_with(tag) {
        &data[tag.len()..]
    } else {
        data
    }
}

/// Validates the key of Namespace and Setting
///
/// # Arguments
/// * `s` - A string slice that holds the name to be validated.
///
/// # Returns
/// * `Ok(())` if the name only contains valid characters (a-z, 0-9, '_').
/// * `Err(String)` if the name is empty or contains invalid characters.
///
pub fn validate_key(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("empty string".to_string());
    }

    for c in s.chars() {
        if !matches!(c, 'a'..='z' | '0'..='9' | '_' ) {
            return Err(format!("invalid character: {}", c));
        }
    }
    Ok(())
}

pub fn validate_principals(principals: &BTreeSet<Principal>) -> Result<(), String> {
    if principals.is_empty() {
        return Err("managers cannot be empty".to_string());
    }
    if principals.contains(&ANONYMOUS) {
        return Err("anonymous user is not allowed".to_string());
    }
    Ok(())
}

pub enum OwnedRef<'a, T> {
    Ref(&'a T),
    Owned(T),
}

impl<T> AsRef<T> for OwnedRef<'_, T> {
    fn as_ref(&self) -> &T {
        match self {
            OwnedRef::Ref(r) => r,
            OwnedRef::Owned(o) => o,
        }
    }
}

impl<T> Deref for OwnedRef<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            OwnedRef::Ref(r) => r,
            OwnedRef::Owned(o) => o,
        }
    }
}
