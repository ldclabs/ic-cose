use candid::Principal;
use cbor2::to_writer;
use ic_auth_types::{Delegation, SignInResponse, SignedDelegation};
use ic_auth_verifier::{user_public_key_from_der, verify_basic_sig};
use ic_canister_sig_creation::{delegation_signature_msg, CanisterSigPublicKey};
use ic_cose_types::{
    types::{namespace::NamespaceDelegatorsInput, SignDelegationInput},
    validate_str, MILLISECONDS,
};
use serde_bytes::ByteBuf;
use std::collections::BTreeSet;

use crate::{is_authenticated, store};

fn fixed_identity_seed(namespace: &str, name: &str) -> Vec<u8> {
    let mut seed = Vec::with_capacity(namespace.len() + name.len() + 16);
    to_writer(&(namespace, name), &mut seed).expect("failed to encode fixed identity seed");
    seed
}

#[ic_cdk::query]
fn namespace_get_fixed_identity(namespace: String, name: String) -> Result<Principal, String> {
    // the write paths store and sign under the lowercased name; normalizing here
    // too keeps this principal equal to the one namespace_sign_delegation issues.
    let name = name.to_ascii_lowercase();
    validate_str(&namespace)?;
    validate_str(&name)?;
    let seed = fixed_identity_seed(&namespace, &name);
    let user_key = CanisterSigPublicKey::new(ic_cdk::api::canister_self(), seed);
    Ok(Principal::self_authenticating(user_key.to_der().as_slice()))
}

#[ic_cdk::query]
fn namespace_get_delegators(
    namespace: String,
    name: String,
) -> Result<BTreeSet<Principal>, String> {
    let caller = ic_cdk::api::msg_caller();
    let name = name.to_ascii_lowercase();
    validate_str(&namespace)?;
    validate_str(&name)?;
    store::ns::get_delegators(&namespace, &name, &caller)
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_add_delegator(input: NamespaceDelegatorsInput) -> Result<BTreeSet<Principal>, String> {
    store::state::allowed_api("namespace_add_delegator")?;
    store::state::ensure_memory_available()?;
    input.validate()?;

    let caller = ic_cdk::api::msg_caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    // validation already rejected any non-lowercase name
    store::ns::mutate_delegators(
        input.ns,
        input.name,
        &caller,
        input.delegators,
        true,
        now_ms,
    )
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_remove_delegator(input: NamespaceDelegatorsInput) -> Result<(), String> {
    store::state::allowed_api("namespace_remove_delegator")?;
    input.validate()?;

    let caller = ic_cdk::api::msg_caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    store::ns::mutate_delegators(
        input.ns,
        input.name,
        &caller,
        input.delegators,
        false,
        now_ms,
    )
    .map(|_| ())
}

#[ic_cdk::update(guard = "is_authenticated")]
fn namespace_sign_delegation(input: SignDelegationInput) -> Result<SignInResponse, String> {
    store::state::allowed_api("namespace_sign_delegation")?;
    store::state::ensure_memory_available()?;
    input.validate()?;
    let caller = ic_cdk::api::msg_caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    let name = input.name.to_ascii_lowercase();

    // Reject unauthorized callers before parsing keys or verifying signatures.
    let session_expires_in_ms = store::ns::delegation_session_expiry(&input.ns, &name, &caller)?;
    if session_expires_in_ms == 0 {
        return Err("delegation is disabled".to_string());
    }
    // A namespace stored before session_expires_in_ms was bounded can still hold a
    // value that overflows here, which would silently wrap into a bogus expiration.
    let expiration = now_ms
        .checked_add(session_expires_in_ms)
        .and_then(|ms| ms.checked_mul(MILLISECONDS))
        .ok_or("session_expires_in_ms of the namespace is too large")?;

    let (alg, pk) = user_public_key_from_der(input.pubkey.as_slice())?;
    let mut msg = Vec::with_capacity(input.ns.len() + name.len() + caller.as_slice().len() + 24);
    to_writer(&(&input.ns, &name, &caller), &mut msg).expect("failed to encode Delegations data");
    verify_basic_sig(alg, &pk, &msg, input.sig.as_slice())
        .map_err(|err| format!("challenge verification failed: {:?}", err))?;

    let seed = fixed_identity_seed(&input.ns, &name);
    let user_key = CanisterSigPublicKey::new(ic_cdk::api::canister_self(), seed);
    let delegation_hash = delegation_signature_msg(input.pubkey.as_slice(), expiration, None);
    store::state::add_signature(user_key.seed.as_slice(), delegation_hash.as_slice())?;

    Ok(SignInResponse {
        expiration,
        user_key: user_key.to_der().into(),
        seed: user_key.seed.into(),
    })
}

#[ic_cdk::query]
fn get_delegation(
    seed: ByteBuf,
    pubkey: ByteBuf,
    expiration: u64,
) -> Result<SignedDelegation, String> {
    if seed.len() > 256 {
        return Err("seed length exceeds the limit 256".to_string());
    }
    if pubkey.len() > ic_cose_types::types::MAX_IDENTITY_CREDENTIAL_BYTES {
        return Err("public key is too large".to_string());
    }
    let delegation_hash = delegation_signature_msg(pubkey.as_slice(), expiration, None);
    let signature = store::state::get_signature(seed.as_slice(), delegation_hash.as_slice())?;

    Ok(SignedDelegation {
        delegation: Delegation {
            pubkey: pubkey.into(),
            expiration,
            targets: None,
            permissions: None,
        },
        signature: signature.into(),
    })
}
