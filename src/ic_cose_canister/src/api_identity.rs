use candid::Principal;
use ciborium::into_writer;
use ic_canister_sig_creation::{delegation_signature_msg, CanisterSigPublicKey};
use ic_cose_types::{
    types::{
        namespace::NamespaceDelegatorsInput, Delegation, SignDelegationInput, SignDelegationOutput,
        SignedDelegation,
    },
    MILLISECONDS,
};
use ic_crypto_standalone_sig_verifier::{
    user_public_key_from_bytes, verify_basic_sig_by_public_key,
};
use serde_bytes::ByteBuf;
use std::collections::BTreeSet;

use crate::store;

#[ic_cdk::query]
fn namespace_get_fixed_identity(namespace: String, name: String) -> Result<Principal, String> {
    let mut seed = vec![];
    into_writer(&(&namespace, &name), &mut seed).expect("failed to encode seed");
    let user_key = CanisterSigPublicKey::new(ic_cdk::id(), seed);
    Ok(Principal::self_authenticating(user_key.to_der().as_slice()))
}

#[ic_cdk::query]
fn namespace_get_delegators(
    namespace: String,
    name: String,
) -> Result<BTreeSet<Principal>, String> {
    let caller = ic_cdk::caller();
    store::ns::with(&namespace, |ns| {
        if !ns.can_read_namespace(&caller) {
            return Err("no permission".to_string());
        }

        ns.fixed_id_names.get(&name).map_or_else(
            || Err("name not found".to_string()),
            |delegators| Ok(delegators.clone()),
        )
    })
}

#[ic_cdk::update]
fn namespace_add_delegator(
    mut input: NamespaceDelegatorsInput,
) -> Result<BTreeSet<Principal>, String> {
    store::state::allowed_api("namespace_add_delegator")?;
    input.validate()?;

    let caller = ic_cdk::caller();
    store::ns::with_mut(&input.ns, |ns| {
        if !ns.can_write_namespace(&caller) {
            return Err("no permission".to_string());
        }
        let name = input.name.to_ascii_lowercase();
        let delegators = ns.fixed_id_names.entry(name).or_insert_with(BTreeSet::new);
        delegators.append(&mut input.delegators);
        Ok(delegators.clone())
    })
}

#[ic_cdk::update]
fn namespace_remove_delegator(input: NamespaceDelegatorsInput) -> Result<(), String> {
    store::state::allowed_api("namespace_remove_delegator")?;
    input.validate()?;

    let caller = ic_cdk::caller();
    store::ns::with_mut(&input.ns, |ns| {
        if !ns.can_write_namespace(&caller) {
            return Err("no permission".to_string());
        }
        let name = input.name.to_ascii_lowercase();
        if let Some(delegators) = ns.fixed_id_names.get_mut(&name) {
            delegators.retain(|v| !input.delegators.contains(v));
            if delegators.is_empty() {
                ns.fixed_id_names.remove(&name);
            }
        }
        Ok(())
    })
}

#[ic_cdk::update]
fn namespace_sign_delegation(input: SignDelegationInput) -> Result<SignDelegationOutput, String> {
    store::state::allowed_api("namespace_sign_delegation")?;
    let caller = ic_cdk::caller();
    let now_ms = ic_cdk::api::time() / MILLISECONDS;
    let name = input.name.to_ascii_lowercase();

    let (pk, _) = user_public_key_from_bytes(input.pubkey.as_slice())
        .map_err(|err| format!("invalid public key: {:?}", err))?;
    let mut msg = vec![];
    into_writer(&(&input.ns, &name, &caller), &mut msg).expect("failed to encode Delegations data");
    verify_basic_sig_by_public_key(pk.algorithm_id, &msg, input.sig.as_slice(), &pk.key)
        .map_err(|err| format!("challenge verification failed: {:?}", err))?;

    let mut seed = vec![];
    into_writer(&(&input.ns, &name), &mut seed).expect("failed to encode seed");
    let user_key = CanisterSigPublicKey::new(ic_cdk::id(), seed);
    let session_expires_in_ms = store::ns::with(&input.ns, |ns| {
        if let Some(delegators) = ns.fixed_id_names.get(&name) {
            if delegators.contains(&caller) {
                return Ok(ns.session_expires_in_ms);
            }
            return Err("caller is not a delegator".to_string());
        }
        Err("name not found".to_string())
    })?;
    if session_expires_in_ms == 0 {
        return Err("delegation is disabled".to_string());
    }
    let expiration = (now_ms + session_expires_in_ms) * MILLISECONDS;
    let delegation_hash = delegation_signature_msg(input.pubkey.as_slice(), expiration, None);
    store::state::add_signature(user_key.seed.as_slice(), delegation_hash.as_slice());

    Ok(SignDelegationOutput {
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
    let delegation_hash = delegation_signature_msg(pubkey.as_slice(), expiration, None);
    let signature = store::state::get_signature(seed.as_slice(), delegation_hash.as_slice())?;

    Ok(SignedDelegation {
        delegation: Delegation {
            pubkey,
            expiration,
            targets: None,
        },
        signature: ByteBuf::from(signature),
    })
}