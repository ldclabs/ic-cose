#![doc(html_root_url = "https://docs.rs/ic-cose-types/latest")]
#![allow(clippy::needless_doctest_main)]

use candid::Principal;
use ciborium::into_writer;
use serde::Serialize;
use std::{collections::BTreeSet, ops::Deref};

pub mod cose;
pub mod types;

pub use cose::format_error;

pub static ANONYMOUS: Principal = Principal::anonymous();
pub const MILLISECONDS: u64 = 1_000_000u64;

/// Converts a serializable object to CBOR-encoded bytes
///
/// # Arguments
/// * `obj` - A reference to any type implementing Serialize trait
///
/// # Returns
/// Vec<u8> containing the CBOR-encoded data
///
/// # Panics
/// Panics if CBOR serialization fails
pub fn to_cbor_bytes(obj: &impl Serialize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    into_writer(obj, &mut buf).expect("failed to encode in CBOR format");
    buf
}

/// Validates a string against naming conventions
///
/// # Rules
/// - Must not be empty
/// - Length must be ≤ 64 characters
/// - Can only contain: lowercase letters (a-z), digits (0-9), and underscores (_)
///
/// # Returns
/// - Ok(()) if valid
/// - Err(String) with error message if invalid
pub fn validate_str(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("empty string".to_string());
    }

    if s.len() > 64 {
        return Err("string length exceeds the limit 64".to_string());
    }

    for c in s.chars() {
        if !matches!(c, 'a'..='z' | '0'..='9' | '_' ) {
            return Err(format!("invalid character: {}", c));
        }
    }
    Ok(())
}

/// Validates a set of principals
///
/// # Rules
/// - Set must not be empty
/// - Set must not contain anonymous principal
///
/// # Returns
/// - Ok(()) if valid
/// - Err(String) with error message if invalid
pub fn validate_principals(principals: &BTreeSet<Principal>) -> Result<(), String> {
    if principals.is_empty() {
        return Err("principals cannot be empty".to_string());
    }
    if principals.contains(&ANONYMOUS) {
        return Err("anonymous user is not allowed".to_string());
    }
    Ok(())
}

/// A smart pointer that can hold either a reference or an owned value
pub enum OwnedRef<'a, T> {
    /// Holds a reference to a value
    Ref(&'a T),
    /// Holds an owned value
    Owned(T),
}

impl<T> AsRef<T> for OwnedRef<'_, T> {
    /// Returns a reference to the contained value
    fn as_ref(&self) -> &T {
        match self {
            OwnedRef::Ref(r) => r,
            OwnedRef::Owned(o) => o,
        }
    }
}

impl<T> Deref for OwnedRef<'_, T> {
    type Target = T;

    /// Dereferences to the contained value
    fn deref(&self) -> &Self::Target {
        match self {
            OwnedRef::Ref(r) => r,
            OwnedRef::Owned(o) => o,
        }
    }
}
