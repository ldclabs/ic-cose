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
        wasm_total: ARTIFACT_META_STORE.with_borrow(|r| r.len()),
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

/// Rejects stable state that still needs a migration removed from this version.
///
/// Versions up to 0.11 carried the schema v1 migration, the monolithic
/// artifact store and the per-wasm log index rebuild. State that has not been
/// through them must first be upgraded to 0.11 and migrated there; trapping
/// here rolls the upgrade back instead of silently dropping that data.
pub(crate) fn ensure_no_legacy_state() -> Result<(), String> {
    let schema = SCHEMA_STORE.with_borrow(|r| *r.get());
    if schema != CURRENT_SCHEMA_VERSION {
        return Err(format!(
            "stable schema {schema} is not {CURRENT_SCHEMA_VERSION}; upgrade through 0.11 first"
        ));
    }
    let legacy_artifacts = retired_map_len::<[u8; 32], _>(
        MEMORY_MANAGER.with_borrow(|m| m.get(LEGACY_WASM_MEMORY_ID)),
    );
    if legacy_artifacts > 0 {
        return Err(format!(
            "{legacy_artifacts} legacy artifacts remain; run admin_migrate_legacy_wasm_artifact on 0.11 first"
        ));
    }
    let logs = INSTALL_LOGS.with_borrow(|r| r.len());
    let indexed = LOG_INDEX_STORE.with_borrow(|r| r.len());
    if indexed != logs {
        return Err(format!(
            "deployment log index covers {indexed} of {logs} logs; run admin_rebuild_log_index on 0.11 first"
        ));
    }
    Ok(())
}

pub fn load() {
    ensure_no_legacy_state().unwrap_or_else(|err| ic_cdk::trap(&err));
    STATE_STORE.with_borrow(|r| {
        STATE.with_borrow_mut(|h| {
            *h = r.get().clone();
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
        // transient fields are never serialized; reset them explicitly so an
        // in-process save/load behaves like a real upgrade
        state.active_operations.clear();
        state.topup_in_progress = false;
        state.low_wasm_memory = false;
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

/// Serializes operations on one target canister.
///
/// The lock is released when the guard drops, which ic-cdk also does when a
/// callback traps and cancels the task, so a failure after an `await` can
/// never strand the target until the next upgrade.
#[must_use = "the lock is released as soon as the guard is dropped"]
#[derive(Debug)]
pub struct OperationGuard {
    canister: Principal,
    request_id: ByteArray<32>,
    attempt: u64,
}

impl OperationGuard {
    pub fn acquire(
        canister: Principal,
        request_id: ByteArray<32>,
        attempt: u64,
        now_ms: u64,
    ) -> Result<Self, String> {
        acquire_operation(canister, request_id, attempt, now_ms)?;
        Ok(Self::adopt(canister, request_id, attempt))
    }

    /// Takes over a lock already acquired by a provisioning step. Releasing is
    /// idempotent, so a step that also releases it explicitly is harmless.
    pub fn adopt(canister: Principal, request_id: ByteArray<32>, attempt: u64) -> Self {
        Self {
            canister,
            request_id,
            attempt,
        }
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        release_operation(self.canister, &self.request_id, self.attempt);
    }
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

/// Marks a batch top-up in flight until dropped, including on a trap.
#[must_use = "the top-up flag is cleared as soon as the guard is dropped"]
pub struct TopupGuard(());

impl TopupGuard {
    pub fn begin() -> Result<Self, String> {
        with_mut(|s| {
            if s.topup_in_progress {
                return Err("a batch top-up is already in flight".to_string());
            }
            s.topup_in_progress = true;
            Ok(Self(()))
        })
    }
}

impl Drop for TopupGuard {
    fn drop(&mut self) {
        with_mut(|s| s.topup_in_progress = false);
    }
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
