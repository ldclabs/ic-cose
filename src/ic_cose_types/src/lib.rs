#![doc(html_root_url = "https://docs.rs/ic-cose-types/latest")]
#![allow(clippy::needless_doctest_main)]

use candid::Principal;
use ciborium::into_writer;
use serde::Serialize;
use std::{collections::BTreeSet, ops::Deref};

pub mod bytes;
pub mod cose;
pub mod types;

pub use bytes::*;

pub static ANONYMOUS: Principal = Principal::anonymous();
pub const MILLISECONDS: u64 = 1_000_000u64;

// to_cbor_bytes returns the CBOR encoding of the given object that implements the Serialize trait.
pub fn to_cbor_bytes(obj: &impl Serialize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    into_writer(obj, &mut buf).expect("failed to encode in CBOR format");
    buf
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
