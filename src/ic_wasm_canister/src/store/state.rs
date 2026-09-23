use super::*;

pub fn is_controller(caller: &Principal) -> bool {
    STATE.with_borrow(|r| r.governance_canister.as_ref() == Some(caller))
}

pub fn is_manager(caller: &Principal) -> bool {
    STATE.with_borrow(|r| r.managers.contains(caller))
}

pub fn is_committer(caller: &Principal) -> bool {
    STATE.with_borrow(|r| r.committers.contains(caller))
}

pub fn is_provisioner(caller: &Principal) -> bool {
    STATE.with_borrow(|r| r.provisioners.contains(caller))
}

pub fn get_state_info() -> StateInfo {
    let latest_version_total = LATEST_STORE.with_borrow(|r| r.len());
    with(|s| StateInfo {
        name: s.name.clone(),
        managers: s.managers.clone(),
        committers: s.committers.clone(),
        provisioners: s.provisioners.clone(),
        latest_version: LATEST_STORE.with_borrow(|r| {
            r.iter()
                .take(1_000)
                .map(|entry| (entry.key().clone(), ByteArray::from(entry.value())))
                .collect()
        }),
        latest_version_total,
        latest_version_truncated: latest_version_total > 1_000,
        wasm_total: WASM_STORE
            .with(|r| r.borrow().len())
            .saturating_add(ARTIFACT_META_STORE.with_borrow(|r| r.len())),
        deployed_total: DEPLOYED_STORE.with_borrow(|r| r.len()),
        deployment_logs: INSTALL_LOGS.with(|r| r.borrow().len()),
        governance_canister: s.governance_canister,
        topup_threshold: s.topup_threshold,
        topup_amount: s.topup_amount,
        low_wasm_memory: s.low_wasm_memory,
    })
}

pub fn with<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with_borrow(|r| f(r))
}

pub fn with_mut<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with_borrow_mut(|r| f(r))
}

pub fn initialize_schema() {
    #[cfg(target_family = "wasm")]
    with_mut(|state| state.canister_id = Some(ic_cdk::api::canister_self()));
    SCHEMA_STORE.with_borrow_mut(|r| {
        r.set(CURRENT_SCHEMA_VERSION);
    });
}

pub fn load() {
    STATE_STORE.with_borrow(|r| {
        STATE.with_borrow_mut(|h| {
            let s = r.get().to_owned();
            *h = s;
        });
    });
    with_mut(|state| {
        if state.governance_canister == Some(Principal::anonymous()) {
            state.governance_canister = None;
            ic_cdk::api::debug_print("removed unsafe anonymous governance_canister during upgrade");
        }
        state.managers.remove(&Principal::anonymous());
        state.committers.remove(&Principal::anonymous());
        state.provisioners.remove(&Principal::anonymous());
        #[cfg(target_family = "wasm")]
        {
            state.canister_id = Some(ic_cdk::api::canister_self());
        }
    });

    let schema = SCHEMA_STORE.with_borrow(|r| *r.get());
    if schema < CURRENT_SCHEMA_VERSION {
        let (latest, paths, deployed) = with_mut(|s| {
            (
                std::mem::take(&mut s.latest_version),
                std::mem::take(&mut s.upgrade_path),
                std::mem::take(&mut s.deployed_list),
            )
        });

        LATEST_STORE.with_borrow_mut(|r| {
            for (name, hash) in latest {
                r.insert(name, *hash);
            }
        });
        RELEASE_PATH_STORE.with_borrow_mut(|r| {
            let mut paths: Vec<_> = paths.into_iter().collect();
            paths.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
            for (previous_artifact, next_artifact) in paths {
                let Some(next) = WASM_STORE.with_borrow(|store| store.get(&*next_artifact)) else {
                    continue;
                };
                let previous_module = if *previous_artifact == [0u8; 32] {
                    ByteArray::from([0u8; 32])
                } else if let Ok(hash) = wasm::module_hash(&previous_artifact) {
                    hash
                } else {
                    continue;
                };
                r.insert(ReleaseKey(next.name, previous_module), *next_artifact);
            }
            let mut first_by_name = BTreeMap::<String, (u64, [u8; 32])>::new();
            WASM_STORE.with_borrow(|store| {
                for entry in store.iter() {
                    let wasm = entry.value();
                    let candidate = (wasm.created_at, *entry.key());
                    first_by_name
                        .entry(wasm.name)
                        .and_modify(|current| {
                            if candidate < *current {
                                *current = candidate;
                            }
                        })
                        .or_insert(candidate);
                }
            });
            for (name, (_, artifact_hash)) in first_by_name {
                let key = ReleaseKey(name, ByteArray::from([0u8; 32]));
                if !r.contains_key(&key) {
                    r.insert(key, artifact_hash);
                }
            }
        });
        DEPLOYED_STORE.with_borrow_mut(|r| {
            for (canister, (log_id, artifact_hash)) in deployed {
                let Some(wasm_name) =
                    INSTALL_LOGS.with_borrow(|logs| logs.get(log_id).map(|log| log.name))
                else {
                    ic_cdk::api::debug_print(format!(
                        "skipped deployment {} with missing log {} during migration",
                        canister, log_id
                    ));
                    continue;
                };
                let Ok(module_hash) = wasm::module_hash(&artifact_hash) else {
                    ic_cdk::api::debug_print(format!(
                        "skipped deployment {} with invalid artifact {} during migration",
                        canister,
                        hex::encode(artifact_hash.as_ref())
                    ));
                    continue;
                };
                r.insert(
                    canister,
                    DeploymentIndex {
                        log_id,
                        artifact_hash,
                        module_hash,
                        wasm_name,
                    },
                );
            }
        });
        SCHEMA_STORE.with_borrow_mut(|r| {
            r.set(CURRENT_SCHEMA_VERSION);
        });
        save();
    }

    with_mut(|s| {
        s.available_pool.clear();
        s.active_operations.clear();
        s.topup_in_progress = false;
        s.low_wasm_memory = false;
    });
    provision::recover_after_upgrade();
}

pub fn save() {
    STATE.with_borrow(|h| {
        STATE_STORE.with_borrow_mut(|r| {
            r.set(h.clone());
        });
    });
}

pub fn deployed(canister: &Principal) -> Option<DeploymentIndex> {
    DEPLOYED_STORE.with_borrow(|r| r.get(canister))
}

pub fn deployed_canisters_page(prev: Option<Principal>, take: usize) -> Vec<Principal> {
    DEPLOYED_STORE.with_borrow(|r| {
        let lower = prev
            .map(std::ops::Bound::Excluded)
            .unwrap_or(std::ops::Bound::Unbounded);
        r.keys_range((lower, std::ops::Bound::Unbounded))
            .take(take)
            .collect()
    })
}

pub fn latest_versions_page(prev: Option<String>, take: usize) -> Vec<(String, ByteArray<32>)> {
    LATEST_STORE.with_borrow(|r| {
        let lower = prev
            .map(std::ops::Bound::Excluded)
            .unwrap_or(std::ops::Bound::Unbounded);
        r.range((lower, std::ops::Bound::Unbounded))
            .take(take)
            .map(|entry| (entry.key().clone(), ByteArray::from(entry.value())))
            .collect()
    })
}

pub fn record_deployment(canister: Principal, deployment: DeploymentIndex) {
    DEPLOYED_STORE.with_borrow_mut(|r| {
        r.insert(canister, deployment);
    });
}

pub fn forget_deployment(canister: &Principal) -> bool {
    FORGOTTEN_DEPLOYMENT_STORE.with_borrow_mut(|r| r.insert(*canister, 1));
    DEPLOYED_STORE.with_borrow_mut(|r| r.remove(canister).is_some())
}

pub fn ensure_not_forgotten(canister: &Principal) -> Result<(), String> {
    if FORGOTTEN_DEPLOYMENT_STORE.with_borrow(|r| r.contains_key(canister)) {
        return Err(
            "canister was explicitly handed off or forgotten; controller adoption is required"
                .to_string(),
        );
    }
    Ok(())
}

pub fn resume_management(canister: &Principal) {
    FORGOTTEN_DEPLOYMENT_STORE.with_borrow_mut(|r| r.remove(canister));
}

pub fn acquire_operation(
    canister: Principal,
    request_id: ByteArray<32>,
    attempt: u64,
    now_ms: u64,
) -> Result<(), String> {
    with_mut(|s| {
        if let Some(active) = s.active_operations.get(&canister) {
            return Err(format!(
                "an operation is already in flight for canister {} since {}",
                canister.to_text(),
                active.started_at
            ));
        }
        s.active_operations.insert(
            canister,
            OperationLock {
                request_id,
                attempt,
                started_at: now_ms,
            },
        );
        Ok(())
    })
}

pub fn release_operation(canister: Principal, request_id: &ByteArray<32>, attempt: u64) {
    with_mut(|s| {
        if s.active_operations
            .get(&canister)
            .is_some_and(|active| active.request_id == *request_id && active.attempt == attempt)
        {
            s.active_operations.remove(&canister);
        }
    });
}

pub fn operation_active(canister: &Principal) -> bool {
    with(|state| state.active_operations.contains_key(canister))
}

pub fn begin_topup() -> Result<(), String> {
    with_mut(|s| {
        if s.topup_in_progress {
            return Err("a batch top-up is already in flight".to_string());
        }
        s.topup_in_progress = true;
        Ok(())
    })
}

pub fn end_topup() {
    with_mut(|s| s.topup_in_progress = false);
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
