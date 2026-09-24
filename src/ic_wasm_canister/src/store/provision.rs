use super::*;
use ic_cose_types::types::wasm::{
    InstallRequest, ReserveRequest, MAX_PROVISION_ARGS_BYTES, MAX_REQUEST_TTL_MS,
    PROVISION_CONTROLLERS,
};

/// How long a released request id stays rejectable after its canister went
/// back to the pool. Covers the longest cross-canister call plus margin.
pub const RELEASE_TOMBSTONE_TTL_MS: u64 = 24 * 3600 * 1000;
/// Bounded ring of release tombstones kept per template.
pub const MAX_RELEASE_TOMBSTONES: u32 = 4096;

fn ensure_request_id_available(request_id: &ByteArray<32>) -> Result<(), String> {
    if COMPLETED_REQUEST_STORE.with_borrow(|store| store.contains_key(&**request_id)) {
        return Err("request id belongs to an archived completed request".to_string());
    }
    Ok(())
}

pub fn recover_after_upgrade() {
    let pending: Vec<String> = TEMPLATE_STORE.with_borrow(|r| {
        r.iter()
            .filter_map(|entry| {
                (entry.value().pool_status == PoolStatus::CreatePending)
                    .then(|| entry.key().clone())
            })
            .collect()
    });
    for id in pending {
        let _ = with_template_mut(&id, |entry| {
            entry.pool_status = PoolStatus::CreateUnknown;
            Ok(())
        });
    }

    // Older versions kept installed canisters in the pool. Their history lives
    // on in the request and deployment stores; dropping them keeps the pool
    // bounded by pool sizes and outstanding reservations, so reservations can
    // scan it directly.
    let installed: Vec<PoolKey> = POOL_STORE.with_borrow(|r| {
        r.iter()
            .filter(|entry| entry.value().state == PoolCanisterState::Installed)
            .map(|entry| entry.key().clone())
            .collect()
    });
    POOL_STORE.with_borrow_mut(|r| {
        for key in installed {
            r.remove(&key);
        }
    });
}

/// Rejects a request whose epoch has elapsed or reaches implausibly far
/// ahead. Together with the release tombstones this keeps a late retry from
/// reaching a canister that has already gone back to the pool.
pub fn validate_epoch(expires_at: u64, now_ms: u64) -> Result<(), String> {
    if expires_at <= now_ms {
        return Err("request epoch has expired".to_string());
    }
    if expires_at > now_ms.saturating_add(MAX_REQUEST_TTL_MS) {
        return Err(format!(
            "request epoch is more than {}ms in the future",
            MAX_REQUEST_TTL_MS
        ));
    }
    Ok(())
}

// ----- templates -----

pub fn add_template(
    caller: Principal,
    now_ms: u64,
    template: ProvisionTemplate,
    required_controllers: &BTreeSet<Principal>,
) -> Result<ProvisionTemplateInfo, String> {
    validate_template(&template, required_controllers)?;
    let entry = TemplateEntry {
        hash: template.hash()?,
        settings_hash: template.settings.hash()?,
        subnet_policy_hash: template.subnet_policy_hash()?,
        template,
        created_at: now_ms,
        created_by: caller,
        pool_status: PoolStatus::Idle,
        available: 0,
        reserved: 0,
        installed: 0,
        tombstones: 0,
    };

    TEMPLATE_STORE.with_borrow_mut(|r| {
        let id = entry.template.id.clone();
        let info = entry.clone().into_info();
        r.insert(id, entry);
        Ok(info)
    })
}

pub fn validate_template(
    template: &ProvisionTemplate,
    required_controllers: &BTreeSet<Principal>,
) -> Result<(), String> {
    template.validate()?;
    let wasm = wasm::get_metadata(&template.artifact_hash)
        .map_err(|_| "NotFound: artifact not found, add the wasm first".to_string())?;
    if wasm.name != template.wasm_name {
        return Err(format!(
            "artifact belongs to wasm {}, not {}",
            wasm.name, template.wasm_name
        ));
    }
    if wasm.encoding != template.encoding {
        return Err("encoding does not match the stored artifact".to_string());
    }
    if wasm.module_hash != template.expected_module_hash {
        return Err(format!(
            "expected_module_hash does not match artifact module hash {}",
            hex::encode(wasm.module_hash.as_ref())
        ));
    }
    let controllers: BTreeSet<Principal> = template.settings.controllers.iter().copied().collect();
    if !required_controllers.is_subset(&controllers) {
        return Err("template controllers must include this canister and governance".to_string());
    }
    if TEMPLATE_STORE.with_borrow(|r| r.contains_key(&template.id)) {
        return Err(format!("provision template {} already exists", template.id));
    }
    Ok(())
}

/// Removing a template is only safe while nothing depends on it: any pooled
/// canister would otherwise lose the settings it must be validated against.
pub fn remove_template(id: &str) -> Result<(), String> {
    validate_remove_template(id)?;
    TEMPLATE_STORE.with_borrow_mut(|r| {
        r.remove(&id.to_string());
        Ok(())
    })
}

pub fn validate_remove_template(id: &str) -> Result<(), String> {
    ic_cose_types::validate_str(id)?;
    let entry = TEMPLATE_STORE
        .with_borrow(|r| r.get(&id.to_string()))
        .ok_or_else(|| format!("NotFound: provision template {} not found", id))?;
    let owned = entry
        .available
        .checked_add(entry.reserved)
        .ok_or_else(|| "template counters overflowed".to_string())?;
    if owned > 0 {
        return Err(format!(
            "provision template {} still owns {} canisters",
            id, owned
        ));
    }
    if entry.pool_status != PoolStatus::Idle {
        return Err(format!(
            "provision template {} pool is {:?}",
            id, entry.pool_status
        ));
    }
    Ok(())
}

pub fn get_template(id: &str) -> Option<ProvisionTemplateInfo> {
    TEMPLATE_STORE.with_borrow(|r| r.get(&id.to_string()).map(|e| e.into_info()))
}

pub fn list_templates_page(prev: Option<String>, take: usize) -> Vec<ProvisionTemplateInfo> {
    TEMPLATE_STORE.with_borrow(|r| {
        let lower = prev
            .map(std::ops::Bound::Excluded)
            .unwrap_or(std::ops::Bound::Unbounded);
        r.range((lower, std::ops::Bound::Unbounded))
            .take(take)
            .map(|e| e.value().into_info())
            .collect()
    })
}

fn load_template(id: &str, hash: &ByteArray<32>) -> Result<TemplateEntry, String> {
    ic_cose_types::validate_str(id)?;
    let entry = TEMPLATE_STORE
        .with_borrow(|r| r.get(&id.to_string()))
        .ok_or_else(|| format!("NotFound: provision template {} not found", id))?;
    if &entry.hash != hash {
        return Err(format!(
            "provision template {} hash mismatch: expected {}, got {}",
            id,
            hex::encode(entry.hash.as_ref()),
            hex::encode(hash.as_ref())
        ));
    }
    let metadata = wasm::get_metadata(&entry.template.artifact_hash)?;
    if metadata.module_hash != entry.template.expected_module_hash {
        return Err("provision template pins the wrong module hash".to_string());
    }
    state::with(|state| {
        if state
            .canister_id
            .is_some_and(|canister_id| !entry.template.settings.controllers.contains(&canister_id))
        {
            return Err(
                "provision template does not include this canister as controller".to_string(),
            );
        }
        if state
            .governance_canister
            .is_some_and(|governance| !entry.template.settings.controllers.contains(&governance))
        {
            return Err("provision template does not include governance as controller".to_string());
        }
        Ok(())
    })?;
    Ok(entry)
}

fn with_template_mut<R>(
    id: &str,
    f: impl FnOnce(&mut TemplateEntry) -> Result<R, String>,
) -> Result<R, String> {
    TEMPLATE_STORE.with_borrow_mut(|r| {
        let mut entry = r
            .get(&id.to_string())
            .ok_or_else(|| format!("NotFound: provision template {} not found", id))?;
        let rt = f(&mut entry)?;
        r.insert(id.to_string(), entry);
        Ok(rt)
    })
}

// ----- pool refill -----

/// Claims the single create slot of a template and persists
/// `PoolCreatePending` *before* the caller performs the outcall, so a lost
/// response cannot be mistaken for "nothing happened".
pub fn begin_pool_create(id: &str) -> Result<ProvisionTemplate, String> {
    let hash = TEMPLATE_STORE
        .with_borrow(|store| store.get(&id.to_string()).map(|entry| entry.hash))
        .ok_or_else(|| format!("NotFound: provision template {} not found", id))?;
    load_template(id, &hash)?;
    with_template_mut(id, |entry| {
        match entry.pool_status {
            PoolStatus::CreatePending => {
                return Err("a pool create is already in flight".to_string())
            }
            PoolStatus::CreateUnknown => {
                return Err(
                    "pool refill is circuit-broken by an unknown create outcome; \
                     governance must reconcile first"
                        .to_string(),
                )
            }
            PoolStatus::Idle => {}
        }
        if entry.available >= entry.template.pool_size as u32 {
            return Err(format!(
                "pool already holds {} available canisters",
                entry.available
            ));
        }
        entry.pool_status = PoolStatus::CreatePending;
        Ok(entry.template.clone())
    })
}

pub fn finish_pool_create(id: &str, canister: Principal, now_ms: u64) -> Result<(), String> {
    validate_pool_candidate(id, canister)?;
    with_template_mut(id, |entry| {
        if entry.pool_status != PoolStatus::CreatePending {
            return Err("pool create is not pending".to_string());
        }
        entry.pool_status = PoolStatus::Idle;
        entry.available = entry
            .available
            .checked_add(1)
            .ok_or_else(|| "available pool counter exhausted".to_string())?;
        Ok(())
    })?;
    POOL_STORE.with_borrow_mut(|r| {
        r.insert(
            PoolKey(id.to_string(), canister),
            PoolCanister {
                state: PoolCanisterState::Available,
                created_at: now_ms,
                request_id: None,
            },
        )
    });
    Ok(())
}

/// `unknown` means the create may still have produced a canister this
/// canister cannot name. That circuit-breaks refill until governance
/// reconciles, rather than looping and leaking one canister per attempt.
pub fn fail_pool_create(id: &str, unknown: bool) {
    let _ = with_template_mut(id, |entry| {
        entry.pool_status = if unknown {
            PoolStatus::CreateUnknown
        } else {
            PoolStatus::Idle
        };
        Ok(())
    });
}

/// Clears a `CreateUnknown` breaker. `found` adopts a canister governance
/// located out of band; `None` declares the create lost.
pub fn reconcile_pool(id: &str, found: Option<Principal>, now_ms: u64) -> Result<(), String> {
    validate_reconcile_pool(id, found)?;
    with_template_mut(id, |entry| {
        if entry.pool_status != PoolStatus::CreateUnknown {
            return Err(format!(
                "provision template {} pool is {:?}, nothing to reconcile",
                id, entry.pool_status
            ));
        }
        entry.pool_status = PoolStatus::Idle;
        if found.is_some() {
            entry.available = entry
                .available
                .checked_add(1)
                .ok_or_else(|| "available pool counter exhausted".to_string())?;
        }
        Ok(())
    })?;
    if let Some(canister) = found {
        POOL_STORE.with_borrow_mut(|r| {
            r.insert(
                PoolKey(id.to_string(), canister),
                PoolCanister {
                    state: PoolCanisterState::Available,
                    created_at: now_ms,
                    request_id: None,
                },
            )
        });
    }
    Ok(())
}

fn validate_pool_candidate(id: &str, canister: Principal) -> Result<(), String> {
    if canister == Principal::anonymous() {
        return Err("pool canister must not be anonymous".to_string());
    }
    if state::deployed(&canister).is_some()
        || POOL_STORE.with_borrow(|r| r.iter().any(|entry| entry.key().1 == canister))
    {
        return Err(format!(
            "canister {} is already tracked by a pool or deployment",
            canister.to_text()
        ));
    }
    if !TEMPLATE_STORE.with_borrow(|r| r.contains_key(&id.to_string())) {
        return Err(format!("NotFound: provision template {} not found", id));
    }
    Ok(())
}

pub fn validate_reconcile_pool(id: &str, found: Option<Principal>) -> Result<(), String> {
    ic_cose_types::validate_str(id)?;
    let entry = TEMPLATE_STORE
        .with_borrow(|r| r.get(&id.to_string()))
        .ok_or_else(|| format!("NotFound: provision template {} not found", id))?;
    if entry.pool_status != PoolStatus::CreateUnknown {
        return Err(format!(
            "provision template {} pool is {:?}, nothing to reconcile",
            id, entry.pool_status
        ));
    }
    if let Some(canister) = found {
        validate_pool_candidate(id, canister)?;
    }
    Ok(())
}

pub fn list_pool_page(id: &str, prev: Option<Principal>, take: usize) -> Vec<PoolCanisterInfo> {
    POOL_STORE.with_borrow(|r| {
        let lower = prev
            .map(|principal| std::ops::Bound::Excluded(PoolKey(id.to_string(), principal)))
            .unwrap_or_else(|| {
                std::ops::Bound::Included(PoolKey(id.to_string(), Principal::management_canister()))
            });
        r.range((lower, std::ops::Bound::Unbounded))
            .take_while(|e| e.key().0 == id)
            .take(take)
            .map(|e| {
                // `LazyEntry::value` deserializes on every call, so load it once.
                let value = e.value();
                PoolCanisterInfo {
                    canister: e.key().1,
                    state: value.state,
                    created_at: value.created_at,
                    request_id: value.request_id,
                }
            })
            .collect()
    })
}

/// The pool holds only available and reserved canisters, so a template's
/// range stays bounded by its pool size and outstanding reservations.
fn take_available(id: &str) -> Option<Principal> {
    POOL_STORE.with_borrow(|r| {
        r.range(ops::RangeFrom {
            start: PoolKey(id.to_string(), Principal::management_canister()),
        })
        .take_while(|e| e.key().0 == id)
        .find(|e| e.value().state == PoolCanisterState::Available)
        .map(|e| e.key().1)
    })
}

// ----- requests -----

pub fn get_receipt(request_id: &ByteArray<32>) -> Option<ProvisionReceipt> {
    REQUEST_STORE
        .with_borrow(|r| r.get(request_id))
        .map(|req| req.into_receipt(*request_id))
}

pub fn ensure_legacy_request_scan_bounded() -> Result<(), String> {
    if REQUEST_STORE.with_borrow(|store| store.len()) > 1_000 {
        return Err("more than 1000 requests; use the corresponding _page method".into());
    }
    Ok(())
}

pub fn list_expired_reservations_page(
    now_ms: u64,
    prev: Option<ByteArray<32>>,
    scan_limit: usize,
) -> ic_cose_types::types::ScanPage<ProvisionReceipt, ByteArray<32>> {
    REQUEST_STORE.with_borrow(|store| {
        let lower = prev
            .map(|key| std::ops::Bound::Excluded(*key))
            .unwrap_or(std::ops::Bound::Unbounded);
        let mut iter = store.range((lower, std::ops::Bound::Unbounded));
        let mut items = Vec::new();
        let mut last = None;
        for entry in iter.by_ref().take(scan_limit.clamp(1, 1_000)) {
            last = Some(ByteArray::from(*entry.key()));
            let request = entry.value();
            if request.template_id.is_some()
                && request.expires_at > 0
                && request.expires_at <= now_ms
                && matches!(
                    request.stage,
                    ProvisionStage::Reserved | ProvisionStage::Failed
                )
            {
                items.push(request.into_receipt(ByteArray::from(*entry.key())));
            }
        }
        let next_cursor = iter.next().and(last);
        ic_cose_types::types::ScanPage { items, next_cursor }
    })
}

pub fn archive_completed_requests_page(
    before_ms: u64,
    prev: Option<ByteArray<32>>,
    scan_limit: usize,
) -> ic_cose_types::types::ScanPage<ByteArray<32>, ByteArray<32>> {
    let (values, next_cursor) = REQUEST_STORE.with_borrow(|store| {
        let lower = prev
            .map(|key| std::ops::Bound::Excluded(*key))
            .unwrap_or(std::ops::Bound::Unbounded);
        let mut iter = store.range((lower, std::ops::Bound::Unbounded));
        let mut values = Vec::new();
        let mut last = None;
        for entry in iter.by_ref().take(scan_limit.clamp(1, 1_000)) {
            last = Some(ByteArray::from(*entry.key()));
            let request = entry.value();
            if request.stage == ProvisionStage::Installed && request.updated_at <= before_ms {
                values.push((
                    *entry.key(),
                    CompletedRequest {
                        owner: request.owner,
                        completed_at: request.updated_at,
                    },
                ));
            }
        }
        (values, iter.next().and(last))
    });
    let mut items = Vec::with_capacity(values.len());
    for (id, completed) in values {
        COMPLETED_REQUEST_STORE.with_borrow_mut(|store| store.insert(id, completed));
        REQUEST_STORE.with_borrow_mut(|store| store.remove(&id));
        items.push(ByteArray::from(id));
    }
    ic_cose_types::types::ScanPage { items, next_cursor }
}

pub fn list_expired_reservations(
    now_ms: u64,
    prev: Option<ByteArray<32>>,
    take: usize,
) -> Vec<ProvisionReceipt> {
    REQUEST_STORE.with_borrow(|r| {
        let lower = prev
            .map(|value| std::ops::Bound::Excluded(*value))
            .unwrap_or(std::ops::Bound::Unbounded);
        r.range((lower, std::ops::Bound::Unbounded))
            .filter_map(|entry| {
                let request = entry.value();
                (request.template_id.is_some()
                    && request.expires_at > 0
                    && request.expires_at <= now_ms
                    && matches!(
                        request.stage,
                        ProvisionStage::Reserved | ProvisionStage::Failed
                    ))
                .then(|| request.into_receipt(ByteArray::from(*entry.key())))
            })
            .take(take)
            .collect()
    })
}

pub fn archive_completed_requests(before_ms: u64, take: usize) -> u64 {
    let values: Vec<([u8; 32], CompletedRequest)> = REQUEST_STORE.with_borrow(|store| {
        store
            .iter()
            .filter_map(|entry| {
                let request = entry.value();
                (request.stage == ProvisionStage::Installed && request.updated_at <= before_ms)
                    .then(|| {
                        (
                            *entry.key(),
                            CompletedRequest {
                                owner: request.owner,
                                completed_at: request.updated_at,
                            },
                        )
                    })
            })
            .take(take)
            .collect()
    });
    for (request_id, completed) in &values {
        COMPLETED_REQUEST_STORE.with_borrow_mut(|store| {
            store.insert(*request_id, completed.clone());
        });
        REQUEST_STORE.with_borrow_mut(|store| {
            store.remove(request_id);
        });
    }
    values.len() as u64
}

fn reservation_receipt(
    request_id: ByteArray<32>,
    owner: Principal,
    expires_at: u64,
    canister: Principal,
    entry: &TemplateEntry,
    reserved_at: u64,
) -> ReservationReceipt {
    ReservationReceipt {
        request_id,
        owner,
        expires_at,
        canister,
        provision_template_id: entry.template.id.clone(),
        provision_template_hash: entry.hash,
        settings_hash: entry.settings_hash,
        controllers: entry.template.settings.controllers.clone(),
        subnet_policy_hash: entry.subnet_policy_hash,
        initial_cycles: entry.template.initial_cycles,
        reserved_at,
    }
}

/// Claims one pre-created canister for `request_id`.
///
/// Fully synchronous: the `request_id → canister` binding is committed with
/// the reply, so a caller that loses the response can recover the same
/// canister by replaying this call or by querying the receipt.
pub fn reserve(
    owner: Principal,
    now_ms: u64,
    req: &ReserveRequest,
) -> Result<ReservationReceipt, String> {
    if *req.request_id == [0u8; 32] {
        return Err("request_id must not be all zero".to_string());
    }
    ensure_request_id_available(&req.request_id)?;
    ic_cose_types::validate_str(&req.provision_template_id)?;
    let entry = load_template(&req.provision_template_id, &req.provision_template_hash)?;

    if let Some(mut existing) = REQUEST_STORE.with_borrow(|r| r.get(&req.request_id)) {
        // a replay must return the original binding, and must never be able
        // to re-point an existing request at a different template
        if existing.stage == ProvisionStage::Released {
            return Err("request has been released and cannot be reused".to_string());
        }
        if existing.template_id.as_deref() != Some(req.provision_template_id.as_str())
            || existing.template_hash != Some(req.provision_template_hash)
        {
            return Err("request id already bound to a different template".to_string());
        }
        if existing.owner != Principal::anonymous() && existing.owner != owner {
            return Err("request id belongs to another provisioner".to_string());
        }
        if existing.expires_at != 0 && existing.expires_at != req.expires_at {
            return Err("request id already bound to a different expiration".to_string());
        }
        if existing.owner == Principal::anonymous() || existing.expires_at == 0 {
            existing.owner = owner;
            existing.expires_at = req.expires_at;
            REQUEST_STORE.with_borrow_mut(|r| {
                r.insert(*req.request_id, existing.clone());
            });
        }
        return Ok(reservation_receipt(
            req.request_id,
            owner,
            req.expires_at,
            existing.canister,
            &entry,
            existing.created_at,
        ));
    }

    if entry.available == 0 {
        return Err(format!(
            "no available canister in the pool of provision template {}",
            req.provision_template_id
        ));
    }
    if entry.reserved == u32::MAX {
        return Err("reserved pool counter exhausted".to_string());
    }

    let canister = take_available(&req.provision_template_id).ok_or_else(|| {
        format!(
            "no available canister in the pool of provision template {}",
            req.provision_template_id
        )
    })?;

    let pool_key = PoolKey(req.provision_template_id.clone(), canister);
    let mut pool = POOL_STORE
        .with_borrow(|r| r.get(&pool_key))
        .ok_or_else(|| "available canister is missing from the pool".to_string())?;
    if pool.state != PoolCanisterState::Available || pool.request_id.is_some() {
        return Err("available pool index is inconsistent".to_string());
    }
    pool.state = PoolCanisterState::Reserved;
    pool.request_id = Some(req.request_id);
    POOL_STORE.with_borrow_mut(|r| r.insert(pool_key, pool));
    with_template_mut(&req.provision_template_id, |e| {
        e.available -= 1;
        e.reserved += 1;
        Ok(())
    })?;
    REQUEST_STORE.with_borrow_mut(|r| {
        r.insert(
            *req.request_id,
            ProvisionRequest {
                stage: ProvisionStage::Reserved,
                owner,
                expires_at: req.expires_at,
                attempt: 0,
                canister,
                wasm_name: entry.template.wasm_name.clone(),
                template_id: Some(entry.template.id.clone()),
                template_hash: Some(entry.hash),
                artifact_hash: entry.template.artifact_hash,
                expected_module_hash: entry.template.expected_module_hash,
                module_hash: None,
                prev_module_hash: None,
                args_hash: None,
                args_size: 0,
                provision_spec_hash: None,
                error: None,
                created_at: now_ms,
                updated_at: now_ms,
            },
        )
    });

    Ok(reservation_receipt(
        req.request_id,
        owner,
        req.expires_at,
        canister,
        &entry,
        now_ms,
    ))
}

/// Outcome of the synchronous checks that precede an install outcall.
#[derive(Debug)]
pub enum InstallPlan {
    /// The request is already `Installed` with matching parameters.
    AlreadyInstalled(Box<ProvisionReceipt>),
    /// Proceed with the install of `wasm` onto `canister`.
    Install {
        attempt: u64,
        canister: Principal,
        artifact_hash: ByteArray<32>,
        expected_module_hash: ByteArray<32>,
        controllers: Vec<Principal>,
    },
}

/// Validates an install request against its reservation and marks it
/// `InstallPending` before any outcall.
pub fn begin_install(
    owner: Principal,
    now_ms: u64,
    req: &InstallRequest,
) -> Result<InstallPlan, String> {
    if *req.request_id == [0u8; 32] {
        return Err("request_id must not be all zero".to_string());
    }
    ensure_request_id_available(&req.request_id)?;
    ic_cose_types::validate_str(&req.provision_template_id)?;
    if req.init_args.len() > MAX_PROVISION_ARGS_BYTES as usize {
        return Err(format!(
            "init_args of {} bytes exceeds the protocol limit {}",
            req.init_args.len(),
            MAX_PROVISION_ARGS_BYTES
        ));
    }
    if sha256(&req.init_args) != *req.init_args_hash {
        return Err("init_args_hash does not match init_args".to_string());
    }

    let existing = REQUEST_STORE
        .with_borrow(|r| r.get(&req.request_id))
        .ok_or_else(|| "NotFound: reserve_canister must be called first".to_string())?;
    if existing.stage == ProvisionStage::Released {
        return Err("request has been released and cannot be reused".to_string());
    }
    if existing.owner != Principal::anonymous() && existing.owner != owner {
        return Err("request id belongs to another provisioner".to_string());
    }
    if existing.expires_at != 0 && existing.expires_at != req.expires_at {
        return Err("request id already bound to a different expiration".to_string());
    }
    if existing.canister != req.canister {
        return Err(format!(
            "request is bound to canister {}, not {}",
            existing.canister.to_text(),
            req.canister.to_text()
        ));
    }
    if existing.template_id.as_deref() != Some(req.provision_template_id.as_str())
        || existing.template_hash != Some(req.provision_template_hash)
    {
        return Err("request id already bound to a different template".to_string());
    }
    if existing.expected_module_hash != req.expected_module_hash {
        return Err(
            "expected_module_hash mismatch: request id is already bound to another module"
                .to_string(),
        );
    }
    state::ensure_not_forgotten(&existing.canister)?;
    // a retry must carry the same arguments, or it is a different request
    if let Some(prev) = existing.args_hash {
        if prev != req.init_args_hash {
            return Err("request id already bound to different init_args".to_string());
        }
    }
    if let Some(prev) = existing.provision_spec_hash {
        if prev != req.provision_spec_hash {
            return Err("request id already bound to a different provision_spec_hash".to_string());
        }
    }
    if existing.stage == ProvisionStage::Installed {
        return Ok(InstallPlan::AlreadyInstalled(Box::new(
            existing.into_receipt(req.request_id),
        )));
    }

    let entry = load_template(&req.provision_template_id, &req.provision_template_hash)?;
    // the caller pays for one exact module hash; refuse to deliver another
    if entry.template.expected_module_hash != req.expected_module_hash {
        return Err(format!(
            "expected_module_hash mismatch: template pins {}, request asks {}",
            hex::encode(entry.template.expected_module_hash.as_ref()),
            hex::encode(req.expected_module_hash.as_ref())
        ));
    }
    if req.init_args.len() > entry.template.max_init_args_bytes as usize {
        return Err(format!(
            "init_args of {} bytes exceeds the template limit {}",
            req.init_args.len(),
            entry.template.max_init_args_bytes
        ));
    }

    wasm::get_metadata(&entry.template.artifact_hash).map_err(|_| {
        format!(
            "NotFound: artifact {} not found",
            hex::encode(entry.template.artifact_hash.as_ref())
        )
    })?;
    let attempt = existing
        .attempt
        .checked_add(1)
        .ok_or_else(|| "request attempt counter exhausted".to_string())?;
    state::acquire_operation(req.canister, req.request_id, attempt, now_ms)?;

    REQUEST_STORE.with_borrow_mut(|r| {
        let mut cur = existing;
        cur.owner = owner;
        cur.expires_at = req.expires_at;
        cur.attempt = attempt;
        cur.stage = ProvisionStage::InstallPending;
        cur.args_hash = Some(req.init_args_hash);
        cur.args_size = req.init_args.len() as u64;
        cur.provision_spec_hash = Some(req.provision_spec_hash);
        cur.error = None;
        cur.updated_at = now_ms;
        r.insert(*req.request_id, cur)
    });

    Ok(InstallPlan::Install {
        attempt,
        canister: req.canister,
        artifact_hash: entry.template.artifact_hash,
        expected_module_hash: entry.template.expected_module_hash,
        controllers: entry.template.settings.controllers.clone(),
    })
}

fn finish_install_state(
    request_id: &ByteArray<32>,
    attempt: u64,
    module_hash: ByteArray<32>,
    now_ms: u64,
) -> Result<ProvisionReceipt, String> {
    let preview = REQUEST_STORE
        .with_borrow(|r| r.get(request_id))
        .ok_or_else(|| "NotFound: request not found".to_string())?;
    if let Some(id) = preview.template_id.as_ref() {
        let template = TEMPLATE_STORE
            .with_borrow(|r| r.get(id))
            .ok_or_else(|| format!("NotFound: provision template {} not found", id))?;
        if preview.stage != ProvisionStage::Installed
            && (template.reserved == 0 || template.installed == u32::MAX)
        {
            return Err("template counters are inconsistent".to_string());
        }
    }
    let (receipt, pooled) = REQUEST_STORE.with_borrow_mut(|r| {
        let mut cur = r
            .get(request_id)
            .ok_or_else(|| "NotFound: request not found".to_string())?;
        if cur.attempt != attempt {
            return Err("stale install attempt callback".to_string());
        }
        if cur.expected_module_hash != module_hash {
            return Err("finish_install received an unexpected module hash".to_string());
        }
        if cur.stage == ProvisionStage::Installed {
            return Ok((cur.into_receipt(*request_id), None));
        }
        if cur.stage != ProvisionStage::InstallPending {
            return Err("request is not pending installation".to_string());
        }
        cur.stage = ProvisionStage::Installed;
        cur.module_hash = Some(module_hash);
        cur.error = None;
        cur.updated_at = now_ms;
        let pooled = cur.template_id.clone().map(|id| (id, cur.canister));
        r.insert(**request_id, cur.clone());
        Ok::<_, String>((cur.into_receipt(*request_id), pooled))
    })?;

    // an installed canister leaves the pool for good
    if let Some((id, canister)) = pooled {
        POOL_STORE.with_borrow_mut(|r| r.remove(&PoolKey(id.clone(), canister)));
        with_template_mut(&id, |e| {
            e.reserved -= 1;
            e.installed += 1;
            Ok(())
        })?;
    }
    Ok(receipt)
}

#[cfg(test)]
pub fn finish_install(
    request_id: &ByteArray<32>,
    attempt: u64,
    module_hash: ByteArray<32>,
    now_ms: u64,
) -> Result<ProvisionReceipt, String> {
    let receipt = finish_install_state(request_id, attempt, module_hash, now_ms)?;
    state::release_operation(receipt.canister, request_id, attempt);
    Ok(receipt)
}

pub fn commit_install_success(
    request_id: &ByteArray<32>,
    attempt: u64,
    module_hash: ByteArray<32>,
    now_ms: u64,
    args: &[u8],
) -> Result<ProvisionReceipt, String> {
    let current = REQUEST_STORE
        .with_borrow(|r| r.get(request_id))
        .ok_or_else(|| "NotFound: request not found".to_string())?;
    if current.args_hash != Some(ByteArray::from(sha256(args))) {
        return Err("install arguments do not match the request".to_string());
    }
    commit_install_record(request_id, attempt, module_hash, now_ms)
}

fn commit_install_record(
    request_id: &ByteArray<32>,
    attempt: u64,
    module_hash: ByteArray<32>,
    now_ms: u64,
) -> Result<ProvisionReceipt, String> {
    let current = REQUEST_STORE
        .with_borrow(|r| r.get(request_id))
        .ok_or_else(|| "NotFound: request not found".to_string())?;
    if current.attempt != attempt || current.stage != ProvisionStage::InstallPending {
        return Err("stale install attempt callback".to_string());
    }
    if current.expected_module_hash != module_hash {
        return Err("installed module hash does not match the request".to_string());
    }
    state::ensure_not_forgotten(&current.canister)?;
    let log = DeployLog {
        name: current.wasm_name.clone(),
        deploy_at: now_ms,
        canister: current.canister,
        prev_hash: current.prev_module_hash.unwrap_or_default(),
        wasm_hash: current.artifact_hash,
        module_hash: Some(module_hash),
        args: ByteBuf::new(),
        args_hash: current.args_hash,
        args_size: current.args_size,
        error: None,
    };
    let log_id = wasm::add_log(log)?;
    let receipt = finish_install_state(request_id, attempt, module_hash, now_ms)?;
    state::record_deployment(
        current.canister,
        DeploymentIndex {
            log_id,
            artifact_hash: current.artifact_hash,
            module_hash,
            wasm_name: current.wasm_name,
        },
    );
    state::release_operation(current.canister, request_id, attempt);
    Ok(receipt)
}

pub fn repair_installed_receipt(
    receipt: &ProvisionReceipt,
    args: &[u8],
    now_ms: u64,
) -> Result<(), String> {
    state::ensure_not_forgotten(&receipt.canister)?;
    let module_hash = receipt
        .module_hash
        .ok_or_else(|| "installed receipt is missing module_hash".to_string())?;
    if state::deployed(&receipt.canister).is_some_and(|deployment| {
        deployment.artifact_hash == receipt.artifact_hash
            && deployment.module_hash == module_hash
            && deployment.wasm_name == receipt.wasm_name
    }) {
        return Ok(());
    }
    wasm::commit_deployment(DeployLog::new(DeployLogInput {
        name: receipt.wasm_name.clone(),
        deploy_at: now_ms,
        canister: receipt.canister,
        prev_hash: receipt.prev_module_hash.unwrap_or_default(),
        artifact_hash: receipt.artifact_hash,
        module_hash: Some(module_hash),
        args,
        error: None,
    }))?;
    Ok(())
}

pub fn fail_install(request_id: &ByteArray<32>, attempt: u64, error: String, now_ms: u64) {
    let mut canister = None;
    REQUEST_STORE.with_borrow_mut(|r| {
        if let Some(mut cur) = r.get(request_id) {
            canister = Some(cur.canister);
            if cur.attempt == attempt && cur.stage != ProvisionStage::Installed {
                cur.stage = ProvisionStage::Failed;
                cur.error = Some(error);
                cur.updated_at = now_ms;
                r.insert(**request_id, cur);
            }
        }
    });
    if let Some(canister) = canister {
        state::release_operation(canister, request_id, attempt);
    }
}

/// Claims an interrupted attempt for a read-only management-canister probe.
/// Unlike a new install, reconciliation is allowed after the bound epoch.
/// It never changes request parameters or dispatches install_code.
pub fn begin_reconcile(
    caller: Principal,
    controller: bool,
    request_id: &ByteArray<32>,
    now_ms: u64,
) -> Result<(Principal, u64), String> {
    let mut current = REQUEST_STORE
        .with_borrow(|r| r.get(request_id))
        .ok_or_else(|| "NotFound: request not found".to_string())?;
    if !controller && (current.owner == Principal::anonymous() || current.owner != caller) {
        return Err("request id belongs to another provisioner".to_string());
    }
    state::ensure_not_forgotten(&current.canister)?;
    if !matches!(
        current.stage,
        ProvisionStage::InstallPending | ProvisionStage::Failed
    ) || current.args_hash.is_none()
    {
        return Err("only an attempted, incomplete installation can be reconciled".to_string());
    }
    let attempt = current
        .attempt
        .checked_add(1)
        .ok_or_else(|| "request attempt counter exhausted".to_string())?;
    let canister = current.canister;
    state::acquire_operation(canister, *request_id, attempt, now_ms)?;
    current.attempt = attempt;
    current.stage = ProvisionStage::InstallPending;
    current.updated_at = now_ms;
    REQUEST_STORE.with_borrow_mut(|r| r.insert(**request_id, current));
    Ok((canister, attempt))
}

pub fn finish_reconcile(
    request_id: &ByteArray<32>,
    attempt: u64,
    actual_module: Option<ByteArray<32>>,
    actual_controllers: &[Principal],
    now_ms: u64,
) -> Result<ProvisionReceipt, String> {
    let current = REQUEST_STORE
        .with_borrow(|r| r.get(request_id))
        .ok_or_else(|| "NotFound: request not found".to_string())?;
    if current.attempt != attempt || current.stage != ProvisionStage::InstallPending {
        return Err("stale reconciliation callback".to_string());
    }
    state::ensure_not_forgotten(&current.canister)?;
    if state::with(|s| {
        s.canister_id
            .is_some_and(|id| !actual_controllers.contains(&id))
    }) {
        return Err("this canister is not a target controller".to_string());
    }
    if current.template_id.is_some() {
        let expected = expected_controllers(current.owner, request_id)?;
        assert_controllers(actual_controllers, &expected)?;
    }
    if actual_module == Some(current.expected_module_hash) {
        return commit_install_record(request_id, attempt, current.expected_module_hash, now_ms);
    }
    let unchanged = if current.template_id.is_some() {
        actual_module.is_none()
    } else {
        actual_module == current.prev_module_hash
    };
    if !unchanged {
        return Err(
            "target module differs from both the requested and previous module".to_string(),
        );
    }
    fail_install(
        request_id,
        attempt,
        "reconciled: installation did not land; no code was installed by reconciliation"
            .to_string(),
        now_ms,
    );
    get_receipt(request_id).ok_or_else(|| "NotFound: request not found".to_string())
}

/// Records an upgrade request keyed by `request_id`, or returns the receipt
/// of an identical one that already completed.
#[derive(Debug)]
pub enum DeploymentPlan {
    AlreadyInstalled(Box<ProvisionReceipt>),
    Deploy { attempt: u64 },
}

#[allow(clippy::too_many_arguments)]
pub fn begin_deployment(
    owner: Principal,
    now_ms: u64,
    request_id: &ByteArray<32>,
    canister: Principal,
    wasm_name: &str,
    artifact_hash: ByteArray<32>,
    expected_module_hash: ByteArray<32>,
    expected_prev_module_hash: ByteArray<32>,
    args_hash: ByteArray<32>,
    args_size: u64,
    expires_at: u64,
) -> Result<DeploymentPlan, String> {
    if **request_id == [0u8; 32] {
        return Err("request_id must not be all zero".to_string());
    }
    ensure_request_id_available(request_id)?;
    state::ensure_not_forgotten(&canister)?;
    ic_cose_types::validate_str(wasm_name)?;
    let (created_at, previous_attempt) =
        if let Some(existing) = REQUEST_STORE.with_borrow(|r| r.get(request_id)) {
            if existing.canister != canister
                || existing.template_id.is_some()
                || existing.wasm_name != wasm_name
                || existing.artifact_hash != artifact_hash
                || existing.expected_module_hash != expected_module_hash
                || existing.args_hash != Some(args_hash)
                || existing.prev_module_hash != Some(expected_prev_module_hash)
            {
                return Err("request id already bound to different parameters".to_string());
            }
            if existing.owner != Principal::anonymous() && existing.owner != owner {
                return Err("request id belongs to another provisioner".to_string());
            }
            if existing.expires_at != 0 && existing.expires_at != expires_at {
                return Err("request id already bound to a different expiration".to_string());
            }
            if existing.stage == ProvisionStage::Installed {
                return Ok(DeploymentPlan::AlreadyInstalled(Box::new(
                    existing.into_receipt(*request_id),
                )));
            }
            (existing.created_at, existing.attempt)
        } else {
            (now_ms, 0)
        };
    assert_upgradable(canister, wasm_name, expected_prev_module_hash)?;
    let attempt = previous_attempt
        .checked_add(1)
        .ok_or_else(|| "request attempt counter exhausted".to_string())?;
    state::acquire_operation(canister, *request_id, attempt, now_ms)?;

    REQUEST_STORE.with_borrow_mut(|r| {
        r.insert(
            **request_id,
            ProvisionRequest {
                stage: ProvisionStage::InstallPending,
                owner,
                expires_at,
                attempt,
                canister,
                wasm_name: wasm_name.to_string(),
                template_id: None,
                template_hash: None,
                artifact_hash,
                expected_module_hash,
                module_hash: None,
                prev_module_hash: Some(expected_prev_module_hash),
                args_hash: Some(args_hash),
                args_size,
                provision_spec_hash: None,
                error: None,
                created_at,
                updated_at: now_ms,
            },
        )
    });
    Ok(DeploymentPlan::Deploy { attempt })
}

/// Returns a reserved canister to the pool.
///
/// Only valid while the request never installed anything; the caller must
/// have verified the canister is still empty and still carries the
/// template's controllers.
pub fn release(
    owner: Principal,
    now_ms: u64,
    request_id: &ByteArray<32>,
    canister: Principal,
) -> Result<ReleaseReceipt, String> {
    let existing = REQUEST_STORE
        .with_borrow(|r| r.get(request_id))
        .ok_or_else(|| "NotFound: request not found".to_string())?;
    if existing.owner != Principal::anonymous() && existing.owner != owner {
        return Err("request id belongs to another provisioner".to_string());
    }
    if existing.stage == ProvisionStage::Released {
        return Ok(ReleaseReceipt {
            request_id: *request_id,
            canister: existing.canister,
            released_at: existing.updated_at,
        });
    }
    if existing.stage == ProvisionStage::Installed {
        return Err("an installed request cannot be released".to_string());
    }
    // the caller checked the canister was empty before awaiting; an install
    // committed in the meantime would otherwise let this hand a canister
    // that is being given code back to the pool as Available.
    if existing.stage == ProvisionStage::InstallPending {
        return Err("an install is in flight for this request".to_string());
    }
    if existing.canister != canister {
        return Err(format!(
            "request is bound to canister {}, not {}",
            existing.canister.to_text(),
            canister.to_text()
        ));
    }
    let template_id = existing
        .template_id
        .clone()
        .ok_or_else(|| "only a template reservation can be released".to_string())?;
    let pool_key = PoolKey(template_id.clone(), canister);
    let pool = POOL_STORE
        .with_borrow(|r| r.get(&pool_key))
        .ok_or_else(|| "reserved canister is missing from the pool".to_string())?;
    if pool.state != PoolCanisterState::Reserved || pool.request_id.as_ref() != Some(request_id) {
        return Err("pool reservation does not match the request".to_string());
    }

    with_template_mut(&template_id, |e| {
        e.reserved = e
            .reserved
            .checked_sub(1)
            .ok_or_else(|| "reserved pool counter is inconsistent".to_string())?;
        e.available = e
            .available
            .checked_add(1)
            .ok_or_else(|| "available pool counter exhausted".to_string())?;
        e.tombstones = e
            .tombstones
            .checked_add(1)
            .ok_or_else(|| "tombstone counter exhausted".to_string())?;
        Ok(())
    })?;
    POOL_STORE.with_borrow_mut(|r| {
        let mut pc = pool;
        pc.state = PoolCanisterState::Available;
        pc.request_id = None;
        r.insert(pool_key, pc);
    });
    REQUEST_STORE.with_borrow_mut(|r| {
        let mut cur = existing;
        cur.stage = ProvisionStage::Released;
        cur.updated_at = now_ms;
        r.insert(**request_id, cur)
    });
    TOMBSTONE_STORE.with_borrow_mut(|r| {
        r.insert(
            TombstoneKey(template_id.clone(), now_ms, *request_id),
            now_ms,
        )
    });
    prune_tombstones(&template_id, now_ms);

    Ok(ReleaseReceipt {
        request_id: *request_id,
        canister,
        released_at: now_ms,
    })
}

/// Drops released request records once they are older than the tombstone
/// TTL, and keeps the per-template ring bounded.
fn prune_tombstones(template_id: &str, now_ms: u64) {
    // the template's counter is only written back after the loop, so track
    // the remaining count locally: re-reading it here would keep reporting
    // the pre-prune value and evict a whole batch of unexpired tombstones
    // for every single one that is actually over the limit.
    let mut count = TEMPLATE_STORE
        .with_borrow(|r| r.get(&template_id.to_string()).map(|e| e.tombstones))
        .unwrap_or(0);
    let mut pruned = 0u32;
    loop {
        let oldest = TOMBSTONE_STORE.with_borrow(|r| {
            r.range(ops::RangeFrom {
                start: TombstoneKey(template_id.to_string(), 0, ByteArray::from([0u8; 32])),
            })
            .next()
            .filter(|e| e.key().0 == template_id)
            .map(|e| e.key().clone())
        });
        let Some(key) = oldest else { break };
        let expired = key.1.saturating_add(RELEASE_TOMBSTONE_TTL_MS) <= now_ms;
        if !expired && count <= MAX_RELEASE_TOMBSTONES {
            break;
        }
        TOMBSTONE_STORE.with_borrow_mut(|r| r.remove(&key));
        REQUEST_STORE.with_borrow_mut(|r| r.remove(&*key.2));
        count = count.saturating_sub(1);
        pruned = pruned.saturating_add(1);
        // bound the work of a single message
        if pruned >= 64 {
            break;
        }
    }
    if pruned > 0 {
        let _ = with_template_mut(template_id, |e| {
            e.tombstones = e.tombstones.saturating_sub(pruned);
            Ok(())
        });
    }
}

/// Asserts the canister is one this canister deployed, and that the upgrade
/// stays within the same wasm name.
///
/// Without this a provisioner could push any published artifact onto any
/// canister this canister happens to control, which is the "arbitrary deploy"
/// power the role is explicitly not meant to have.
pub fn assert_upgradable(
    canister: Principal,
    wasm_name: &str,
    expected_previous: ByteArray<32>,
) -> Result<(), String> {
    let deployed = state::deployed(&canister).ok_or_else(|| {
        format!(
            "NotFound: canister {} was not deployed by this canister",
            canister.to_text()
        )
    })?;
    if deployed.wasm_name != wasm_name {
        return Err(format!(
            "canister {} runs wasm {}, not {}",
            canister.to_text(),
            deployed.wasm_name,
            wasm_name
        ));
    }
    if deployed.module_hash != expected_previous {
        return Err("expected previous module does not match the deployment index".to_string());
    }
    Ok(())
}

/// Controllers the template fixes for a reserved canister, so a release can
/// verify the canister was not re-parented before returning it to the pool.
pub fn expected_controllers(
    owner: Principal,
    request_id: &ByteArray<32>,
) -> Result<Vec<Principal>, String> {
    let req = REQUEST_STORE
        .with_borrow(|r| r.get(request_id))
        .ok_or_else(|| "NotFound: request not found".to_string())?;
    if req.owner != Principal::anonymous() && req.owner != owner {
        return Err("request id belongs to another provisioner".to_string());
    }
    let id = req
        .template_id
        .ok_or_else(|| "only a template reservation can be released".to_string())?;
    let entry = TEMPLATE_STORE
        .with_borrow(|r| r.get(&id))
        .ok_or_else(|| format!("NotFound: provision template {} not found", id))?;
    Ok(entry.template.settings.controllers)
}

/// Verifies the controllers reported by the management canister still match
/// the template, so a release never returns a tampered canister to the pool.
pub fn assert_controllers(actual: &[Principal], expected: &[Principal]) -> Result<(), String> {
    if expected.len() != PROVISION_CONTROLLERS {
        return Err("template controllers are malformed".to_string());
    }
    let actual: BTreeSet<&Principal> = actual.iter().collect();
    let expected: BTreeSet<&Principal> = expected.iter().collect();
    if actual != expected {
        return Err("canister controllers no longer match the template".to_string());
    }
    Ok(())
}

// ----- chunked artifact staging -----

/// Largest chunk one ingress message may stage.
pub const MAX_CHUNK_BYTES: usize = 1024 * 1024;
/// Largest artifact that may be assembled from staged chunks.
pub const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
/// Chunks one uploader may keep staged. With [`MAX_CHUNK_BYTES`] this bounds
/// staged bytes per uploader to [`MAX_ARTIFACT_BYTES`]; without it, staging
/// and never committing would grow stable memory without limit.
pub const MAX_STAGED_CHUNKS: usize = MAX_ARTIFACT_BYTES / MAX_CHUNK_BYTES;
pub const MAX_GLOBAL_STAGED_CHUNKS: u64 = 1_024;

pub fn staged_chunks(caller: Principal) -> usize {
    CHUNK_STORE.with_borrow(|r| {
        r.keys_range(ops::RangeFrom {
            start: ChunkKey(caller, ByteArray::from([0u8; 32])),
        })
        .take_while(|k| k.0 == caller)
        .count()
    })
}

pub fn add_chunk(caller: Principal, chunk: Vec<u8>) -> Result<ByteArray<32>, String> {
    if chunk.is_empty() {
        return Err("chunk should not be empty".to_string());
    }
    if chunk.len() > MAX_CHUNK_BYTES {
        return Err(format!(
            "chunk of {} bytes exceeds the limit {}",
            chunk.len(),
            MAX_CHUNK_BYTES
        ));
    }
    let hash: ByteArray<32> = sha256(&chunk).into();
    let key = ChunkKey(caller, hash);
    let known = CHUNK_STORE.with_borrow(|r| r.contains_key(&key));
    if known {
        // An upload retry is already durably staged. Avoid rewriting up to
        // 1 MiB of stable memory for an identical content-addressed chunk.
        return Ok(hash);
    }
    if staged_chunks(caller) >= MAX_STAGED_CHUNKS {
        return Err(format!(
            "at most {} chunks may be staged at once; commit or clear them first",
            MAX_STAGED_CHUNKS
        ));
    }
    if CHUNK_STORE.with_borrow(|r| r.len()) >= MAX_GLOBAL_STAGED_CHUNKS {
        return Err(format!(
            "global staged chunk limit {} reached",
            MAX_GLOBAL_STAGED_CHUNKS
        ));
    }
    CHUNK_STORE.with_borrow_mut(|r| r.insert(key, chunk));
    Ok(hash)
}

pub fn take_chunks(caller: Principal, hashes: &[ByteArray<32>]) -> Result<Vec<u8>, String> {
    if hashes.is_empty() {
        return Err("chunk_hashes should not be empty".to_string());
    }
    if hashes.len() > MAX_STAGED_CHUNKS {
        return Err(format!(
            "chunk manifest exceeds the limit {}",
            MAX_STAGED_CHUNKS
        ));
    }
    CHUNK_STORE.with_borrow(|r| {
        let mut out: Vec<u8> = Vec::new();
        for h in hashes {
            let chunk = r
                .get(&ChunkKey(caller, *h))
                .ok_or_else(|| format!("NotFound: chunk {} not staged", hex::encode(h.as_ref())))?;
            if out.len().saturating_add(chunk.len()) > MAX_ARTIFACT_BYTES {
                return Err(format!(
                    "assembled artifact exceeds the limit {}",
                    MAX_ARTIFACT_BYTES
                ));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    })
}

pub fn clear_chunks(caller: Principal) -> u64 {
    CHUNK_STORE.with_borrow_mut(|r| {
        let keys: Vec<ChunkKey> = r
            .keys_range(ops::RangeFrom {
                start: ChunkKey(caller, ByteArray::from([0u8; 32])),
            })
            .take_while(|key| key.0 == caller)
            .collect();
        let n = keys.len() as u64;
        for k in keys {
            r.remove(&k);
        }
        n
    })
}
