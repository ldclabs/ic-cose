#![doc(html_root_url = "https://docs.rs/ic-cose-types/latest")]
#![allow(clippy::needless_doctest_main)]

use candid::{utils::ArgumentEncoder, CandidType, Principal};
use serde::Serialize;
use std::{collections::BTreeSet, future::Future};

pub mod cose;
pub mod types;

pub use cose::format_error;

pub static ANONYMOUS: Principal = Principal::anonymous();
pub const MILLISECONDS: u64 = 1_000_000u64;
/// Maximum principals accepted in one role mutation request.
pub const MAX_PRINCIPALS_PER_REQUEST: usize = 1_000;
/// Maximum principals retained in one role/readers set.
pub const MAX_PRINCIPALS_PER_SET: usize = 10_000;

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
    try_to_cbor_bytes(obj).expect("failed to encode in CBOR format")
}

/// Converts a serializable object to CBOR-encoded bytes.
pub fn try_to_cbor_bytes(obj: &impl Serialize) -> Result<Vec<u8>, String> {
    cbor2::to_vec(obj).map_err(|err| format!("failed to encode in CBOR format: {err:?}"))
}

/// Converts a serializable object to deterministic CBOR-encoded bytes.
///
/// Unlike [`try_to_cbor_bytes`], this applies RFC 8949 §4.2.1 deterministic
/// encoding (shortest-form integers and sorted map keys) rather than the field
/// declaration order of the Rust type, so an independent implementation in
/// another language can reproduce the exact same bytes.
pub fn try_to_canonical_cbor_bytes(obj: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    cbor2::to_canonical_writer(obj, &mut buf)
        .map_err(|err| format!("failed to encode in canonical CBOR format: {err:?}"))?;
    Ok(buf)
}

/// Computes a domain-separated hash of a serializable value.
///
/// The digest is `SHA-256(canonical_cbor([domain, value]))`, where the two-element
/// array is encoded with RFC 8949 §4.2.1 deterministic encoding. Encoding the
/// domain as the first array element rather than as a raw prefix keeps the
/// pre-image unambiguous, and the deterministic encoding lets callers written in
/// other languages reproduce the digest byte for byte.
///
/// Changing the set of hashed fields, or the way they are normalized, requires a
/// new `domain` rather than a silent change of meaning.
pub fn canonical_hash(domain: &str, value: &impl Serialize) -> Result<[u8; 32], String> {
    let buf = try_to_canonical_cbor_bytes(&(domain, value))?;
    Ok(cose::sha256(&buf))
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
    if principals.len() > MAX_PRINCIPALS_PER_REQUEST {
        return Err(format!(
            "principals count exceeds the per-request limit {}",
            MAX_PRINCIPALS_PER_REQUEST
        ));
    }
    validate_principals_not_anonymous(principals)
}

/// Validates that a principal set does not contain anonymous principal.
pub fn validate_principals_not_anonymous(principals: &BTreeSet<Principal>) -> Result<(), String> {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn validate_str_accepts_expected_names() {
        assert!(validate_str("_").is_ok());
        assert!(validate_str("abc_123").is_ok());
        assert!(validate_str(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn cbor_helpers_encode_serializable_values() {
        let value = vec![("key".to_string(), 1u64)];
        let fallible = try_to_cbor_bytes(&value).unwrap();
        assert!(!fallible.is_empty());
        assert_eq!(to_cbor_bytes(&value), fallible);
    }

    #[test]
    fn validate_str_rejects_invalid_names() {
        assert_eq!(validate_str("").unwrap_err(), "empty string");
        assert_eq!(
            validate_str(&"a".repeat(65)).unwrap_err(),
            "string length exceeds the limit 64"
        );
        assert_eq!(validate_str("ABC").unwrap_err(), "invalid character: A");
        assert_eq!(validate_str("abc-123").unwrap_err(), "invalid character: -");
    }

    #[test]
    fn canonical_hash_is_deterministic_and_domain_separated() {
        #[derive(serde::Serialize)]
        struct V {
            b: u64,
            a: String,
        }
        let v = V {
            b: 1,
            a: "x".to_string(),
        };
        let h = canonical_hash("d1", &v).unwrap();
        assert_eq!(h, canonical_hash("d1", &v).unwrap());
        // a different domain must not collide with the same value
        assert_ne!(h, canonical_hash("d2", &v).unwrap());
        // a different value must not collide within the same domain
        assert_ne!(
            h,
            canonical_hash(
                "d1",
                &V {
                    b: 2,
                    a: "x".to_string()
                }
            )
            .unwrap()
        );

        // canonical encoding sorts map keys rather than following declaration order
        let canonical = try_to_canonical_cbor_bytes(&v).unwrap();
        assert_ne!(canonical, try_to_cbor_bytes(&v).unwrap());
        assert_eq!(canonical, try_to_canonical_cbor_bytes(&v).unwrap());
    }

    #[test]
    fn validate_principals_requires_non_empty_set() {
        let principals = BTreeSet::new();
        assert_eq!(
            validate_principals(&principals).unwrap_err(),
            "principals cannot be empty"
        );
    }

    #[test]
    fn validate_principals_rejects_anonymous() {
        let mut principals = BTreeSet::new();
        principals.insert(Principal::anonymous());
        assert_eq!(
            validate_principals(&principals).unwrap_err(),
            "anonymous user is not allowed"
        );
        assert_eq!(
            validate_principals_not_anonymous(&principals).unwrap_err(),
            "anonymous user is not allowed"
        );
    }

    #[test]
    fn validate_principals_accepts_authenticated_principal() {
        let mut principals = BTreeSet::new();
        principals.insert(Principal::management_canister());
        assert!(validate_principals(&principals).is_ok());
        assert!(validate_principals_not_anonymous(&principals).is_ok());
        assert!(validate_principals_not_anonymous(&BTreeSet::new()).is_ok());
    }
}
