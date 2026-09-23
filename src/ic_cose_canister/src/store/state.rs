use super::*;

pub fn with<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with_borrow(f)
}

pub fn with_mut<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with_borrow_mut(f)
}

pub fn is_controller(caller: &Principal) -> bool {
    STATE.with_borrow(|s| s.governance_canister.as_ref() == Some(caller))
}

pub fn is_manager(caller: &Principal) -> bool {
    STATE.with_borrow(|s| s.managers.contains(caller))
}

pub fn set_low_wasm_memory(value: bool) {
    with_mut(|state| state.low_wasm_memory = value);
}

pub fn ensure_memory_available() -> Result<(), String> {
    if with(|state| state.low_wasm_memory) {
        Err("canister is in low Wasm memory mode".to_string())
    } else {
        Ok(())
    }
}

pub fn allowed_api(api: &str) -> Result<(), String> {
    if with(|s| s.allowed_apis.is_empty() || s.allowed_apis.contains(api)) {
        Ok(())
    } else {
        Err(format!("API {} not allowed", api))
    }
}

pub fn add_signature(seed: &[u8], message: &[u8]) -> Result<(), String> {
    const SIGNATURE_TTL_NS: u64 = 60 * 1_000_000_000;
    let now = canister_time_ns();
    let id = signature_intent_id(seed, message);
    SIGNATURE_INTENT_STORE.with_borrow_mut(|store| -> Result<(), String> {
        if !store.contains_key(&id) && store.len() >= MAX_SIGNATURE_INTENTS {
            let expired: Vec<[u8; 32]> = store
                .iter()
                .filter_map(|entry| (entry.value().expires_at_ns <= now).then_some(*entry.key()))
                .collect();
            if store.len().saturating_sub(expired.len() as u64) >= MAX_SIGNATURE_INTENTS {
                return Err(format!(
                    "too many active signature intents; retry after {} seconds",
                    SIGNATURE_TTL_NS / 1_000_000_000
                ));
            }
            for key in expired {
                store.remove(&key);
            }
        }
        store.insert(
            id,
            SignatureIntent {
                seed: seed.to_vec(),
                message: message.to_vec(),
                expires_at_ns: now.saturating_add(SIGNATURE_TTL_NS),
            },
        );
        Ok(())
    })?;
    SIGNATURES.with_borrow_mut(|sigs| {
        let sig_inputs = CanisterSigInputs {
            domain: DELEGATION_SIG_DOMAIN,
            seed,
            message,
        };
        sigs.add_signature(&sig_inputs);
    });
    certify_signature_root();
    Ok(())
}

pub fn get_signature(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    SIGNATURES.with_borrow(|sigs| {
        let sig_inputs = CanisterSigInputs {
            domain: DELEGATION_SIG_DOMAIN,
            seed,
            message,
        };
        sigs.get_signature_as_cbor(&sig_inputs, None)
            .map_err(|err| format!("failed to get signature: {:?}", err))
    })
}

pub async fn init_public_key() -> bool {
    let (ecdsa_key_name, schnorr_ed25519_key_name, schnorr_secp256k1_key_name, needs_iv) =
        with(|r| {
            (
                r.ecdsa_public_key
                    .is_none()
                    .then(|| r.ecdsa_key_name.clone()),
                r.schnorr_ed25519_public_key
                    .is_none()
                    .then(|| r.schnorr_key_name.clone()),
                r.schnorr_secp256k1_public_key
                    .is_none()
                    .then(|| r.schnorr_key_name.clone()),
                *r.init_vector == [0u8; 32],
            )
        });

    let ecdsa_public_key = if let Some(key_name) = ecdsa_key_name {
        ecdsa_public_key(key_name, vec![])
            .await
            .map_err(|err| {
                ic_cdk::api::debug_print(format!("failed to retrieve ECDSA public key: {err}"))
            })
            .ok()
    } else {
        None
    };

    let schnorr_ed25519_public_key = if let Some(key_name) = schnorr_ed25519_key_name {
        schnorr_public_key(key_name, SchnorrAlgorithm::Ed25519, vec![])
            .await
            .map_err(|err| {
                ic_cdk::api::debug_print(format!(
                    "failed to retrieve Schnorr Ed25519 public key: {err}"
                ))
            })
            .ok()
    } else {
        None
    };

    let schnorr_secp256k1_public_key = if let Some(key_name) = schnorr_secp256k1_key_name {
        schnorr_public_key(key_name, SchnorrAlgorithm::Bip340secp256k1, vec![])
            .await
            .map_err(|err| {
                ic_cdk::api::debug_print(format!(
                    "failed to retrieve Schnorr Secp256k1 public key: {err}"
                ))
            })
            .ok()
    } else {
        None
    };

    let iv = if needs_iv {
        rand_bytes::<32>()
            .await
            .map_err(|err| {
                ic_cdk::api::debug_print(format!("failed to generate initialization vector: {err}"))
            })
            .ok()
    } else {
        None
    };

    // this runs again after an upgrade when something is still missing, so it
    // must be idempotent: never clear a key that was already retrieved, and
    // never rotate the IV, which feeds every KEK derived so far.
    with_mut(|r| {
        if ecdsa_public_key.is_some() {
            r.ecdsa_public_key = ecdsa_public_key;
        }
        if schnorr_ed25519_public_key.is_some() {
            r.schnorr_ed25519_public_key = schnorr_ed25519_public_key;
        }
        if schnorr_secp256k1_public_key.is_some() {
            r.schnorr_secp256k1_public_key = schnorr_secp256k1_public_key;
        }
        if *r.init_vector == [0u8; 32] {
            if let Some(iv) = iv {
                r.init_vector = iv.into();
            }
        }
    });
    !needs_public_key_init()
}

/// Returns true if some key material could not be retrieved yet, so that
/// [`init_public_key`] can be retried instead of leaving the ECDSA, Schnorr
/// and KEK APIs permanently broken.
pub fn needs_public_key_init() -> bool {
    with(|s| {
        s.ecdsa_public_key.is_none()
            || s.schnorr_ed25519_public_key.is_none()
            || s.schnorr_secp256k1_public_key.is_none()
            || *s.init_vector == [0u8; 32]
    })
}

pub fn initialize_schema() {
    SCHEMA_STORE.with_borrow_mut(|r| {
        r.set(CURRENT_SCHEMA_VERSION);
    });
    certify_signature_root();
}

fn restore_signature_intents() {
    let now = canister_time_ns();
    let intents: Vec<([u8; 32], SignatureIntent)> = SIGNATURE_INTENT_STORE.with_borrow(|store| {
        store
            .iter()
            .map(|entry| (*entry.key(), entry.value()))
            .collect()
    });
    SIGNATURES.with_borrow_mut(|signatures| {
        for (key, intent) in intents {
            if intent.expires_at_ns <= now {
                SIGNATURE_INTENT_STORE.with_borrow_mut(|store| {
                    store.remove(&key);
                });
                continue;
            }
            signatures.add_signature(&CanisterSigInputs {
                domain: DELEGATION_SIG_DOMAIN,
                seed: &intent.seed,
                message: &intent.message,
            });
        }
    });
}

pub fn load(migrate_legacy_namespaces: bool) {
    STATE_STORE.with_borrow(|r| {
        STATE.with_borrow_mut(|h| {
            let v: State = from_cbor_bytes(r.get(), "STATE_STORE data");
            *h = v;
        });
    });
    with_mut(|state| {
        if state.governance_canister == Some(Principal::anonymous()) {
            state.governance_canister = None;
            ic_cdk::api::debug_print("removed unsafe anonymous governance_canister during upgrade");
        }
        state.managers.remove(&Principal::anonymous());
        state.auditors.remove(&Principal::anonymous());
    });

    let schema = SCHEMA_STORE.with_borrow(|r| *r.get());
    if schema < CURRENT_SCHEMA_VERSION {
        let legacy = NSLEGACY_STORE.with_borrow(|r| r.get().clone());
        if migrate_legacy_namespaces && !legacy.is_empty() {
            if NAMESPACES_STORE.with_borrow(|r| r.len()) > 0 {
                ic_cdk::trap(
                    "legacy namespace migration requested but current namespaces are not empty",
                );
            }
            let m: BTreeMap<String, NamespaceLegacy> = from_cbor_bytes(&legacy, "NS_STORE data");
            ns::migrate(m);
        }
        NSLEGACY_STORE.with_borrow_mut(|r| {
            r.set(Vec::new());
        });
        SCHEMA_STORE.with_borrow_mut(|r| {
            r.set(CURRENT_SCHEMA_VERSION);
        });
    }

    restore_signature_intents();
    certify_signature_root();
}

pub fn save() {
    STATE.with_borrow(|h| {
        STATE_STORE.with_borrow_mut(|r| {
            r.set(to_cbor_bytes(h, 512, "STATE_STORE data"));
        });
    });
}
