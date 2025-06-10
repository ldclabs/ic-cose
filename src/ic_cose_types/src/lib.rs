#![doc(html_root_url = "https://docs.rs/ic-cose-types/latest")]
#![allow(clippy::needless_doctest_main)]

use candid::{utils::ArgumentEncoder, CandidType, Principal};
use ciborium::into_writer;
use serde::Serialize;
use std::{collections::BTreeSet, future::Future};

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

/// A type alias for a boxed error that is thread-safe and sendable across threads.
/// This is commonly used as a return type for functions that can return various error types.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A trait for interacting with canisters
pub trait CanisterCaller: Sized {
    /// Performs a query call to a canister (read-only, no state changes)
    ///
    /// # Arguments
    /// * `canister` - Target canister principal
    /// * `method` - Method name to call
    /// * `args` - Input arguments encoded in Candid format
    fn canister_query<
        In: ArgumentEncoder + Send,
        Out: CandidType + for<'a> candid::Deserialize<'a>,
    >(
        &self,
        canister: &Principal,
        method: &str,
        args: In,
    ) -> impl Future<Output = Result<Out, BoxError>> + Send;

    /// Performs an update call to a canister (may modify state)
    ///
    /// # Arguments
    /// * `canister` - Target canister principal
    /// * `method` - Method name to call
    /// * `args` - Input arguments encoded in Candid format
    fn canister_update<
        In: ArgumentEncoder + Send,
        Out: CandidType + for<'a> candid::Deserialize<'a>,
    >(
        &self,
        canister: &Principal,
        method: &str,
        args: In,
    ) -> impl Future<Output = Result<Out, BoxError>> + Send;
}
