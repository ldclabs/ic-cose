use super::*;

fn load_setting_metadata(key: &SettingPathKey) -> Option<(Setting, bool)> {
    if let Some(meta) = SETTING_META_STORE.with_borrow(|store| store.get(key)) {
        let mut setting = meta.into_setting(None);
        setting.readers.remove(&Principal::anonymous());
        return Some((setting, false));
    }
    SETTINGS_STORE
        .with_borrow(|store| store.get(key))
        .map(|mut setting| {
            setting.readers.remove(&Principal::anonymous());
            (setting, true)
        })
}

fn load_setting(key: &SettingPathKey) -> Option<Setting> {
    if let Some(meta) = SETTING_META_STORE.with_borrow(|store| store.get(key)) {
        let data = SETTING_DATA_STORE.with_borrow(|store| store.get(key));
        let mut setting = meta.into_setting(data);
        setting.readers.remove(&Principal::anonymous());
        return Some(setting);
    }
    SETTINGS_STORE.with_borrow(|store| {
        store.get(key).map(|mut setting| {
            setting.readers.remove(&Principal::anonymous());
            setting
        })
    })
}

fn contains_setting(key: &SettingPathKey) -> bool {
    SETTING_META_STORE.with_borrow(|store| store.contains_key(key))
        || SETTINGS_STORE.with_borrow(|store| store.contains_key(key))
}

fn save_setting(key: SettingPathKey, setting: Setting) {
    let (meta, data) = setting.into_parts();
    SETTING_META_STORE.with_borrow_mut(|store| {
        store.insert(key.clone(), meta);
    });
    SETTING_DATA_STORE.with_borrow_mut(|store| {
        if data.payload.is_some() || data.dek.is_some() {
            store.insert(key.clone(), data);
        } else {
            store.remove(&key);
        }
    });
    SETTINGS_STORE.with_borrow_mut(|store| {
        store.remove(&key);
    });
}

fn save_setting_metadata(key: SettingPathKey, setting: Setting, was_legacy: bool) {
    if was_legacy {
        save_setting(key, setting);
    } else {
        SETTING_META_STORE.with_borrow_mut(|store| {
            store.insert(key, setting.into_parts().0);
        });
    }
}

fn remove_setting(key: &SettingPathKey) -> Option<Setting> {
    if let Some(meta) = SETTING_META_STORE.with_borrow_mut(|store| store.remove(key)) {
        let data = SETTING_DATA_STORE.with_borrow_mut(|store| store.remove(key));
        return Some(meta.into_setting(data));
    }
    SETTINGS_STORE.with_borrow_mut(|store| store.remove(key))
}

fn ensure_acl_v1(namespace: &str, ns: &mut Namespace) {
    if ns.acl_version != 0 {
        return;
    }
    ACL_STORE.with_borrow_mut(|store| {
        for principal in &ns.managers {
            if *principal != Principal::anonymous() {
                store.insert(AclKey(namespace.to_string(), ROLE_MANAGER, *principal), 0);
            }
        }
        for principal in &ns.auditors {
            if *principal != Principal::anonymous() {
                store.insert(AclKey(namespace.to_string(), ROLE_AUDITOR, *principal), 0);
            }
        }
        for principal in &ns.users {
            if *principal != Principal::anonymous() {
                store.insert(AclKey(namespace.to_string(), ROLE_USER, *principal), 0);
            }
        }
    });
    FIXED_IDENTITY_STORE.with_borrow_mut(|store| {
        for (name, delegators) in &ns.fixed_id_names {
            for principal in delegators {
                if *principal != Principal::anonymous() {
                    store.insert(
                        FixedIdentityKey(namespace.to_string(), name.clone(), *principal),
                        0,
                    );
                }
            }
        }
    });
    ns.manager_count = ns
        .managers
        .iter()
        .filter(|principal| **principal != Principal::anonymous())
        .count() as u32;
    ns.auditor_count = ns
        .auditors
        .iter()
        .filter(|principal| **principal != Principal::anonymous())
        .count() as u32;
    ns.user_count = ns
        .users
        .iter()
        .filter(|principal| **principal != Principal::anonymous())
        .count() as u32;
    ns.fixed_delegator_count = ns
        .fixed_id_names
        .values()
        .map(|values| {
            values
                .iter()
                .filter(|principal| **principal != Principal::anonymous())
                .count()
        })
        .sum::<usize>() as u32;
    ns.managers.clear();
    ns.auditors.clear();
    ns.users.clear();
    ns.fixed_id_names.clear();
    ns.acl_version = 1;
}

fn role_members(namespace: &str, ns: &Namespace, role: u8) -> BTreeSet<Principal> {
    if ns.acl_version == 0 {
        return match role {
            ROLE_MANAGER => ns.managers.clone(),
            ROLE_AUDITOR => ns.auditors.clone(),
            ROLE_USER => ns.users.clone(),
            _ => BTreeSet::new(),
        }
        .into_iter()
        .filter(|principal| *principal != Principal::anonymous())
        .collect();
    }
    ACL_STORE.with_borrow(|store| {
        store
            .range(ops::RangeFrom {
                start: AclKey(
                    namespace.to_string(),
                    role,
                    Principal::management_canister(),
                ),
            })
            .take_while(|entry| entry.key().0 == namespace && entry.key().1 == role)
            .map(|entry| entry.key().2)
            .collect()
    })
}

fn fixed_identities(namespace: &str, ns: &Namespace) -> BTreeMap<String, BTreeSet<Principal>> {
    if ns.acl_version == 0 {
        return ns
            .fixed_id_names
            .iter()
            .filter_map(|(name, principals)| {
                let principals: BTreeSet<_> = principals
                    .iter()
                    .copied()
                    .filter(|principal| *principal != Principal::anonymous())
                    .collect();
                (!principals.is_empty()).then(|| (name.clone(), principals))
            })
            .collect();
    }
    FIXED_IDENTITY_STORE.with_borrow(|store| {
        let mut values = BTreeMap::<String, BTreeSet<Principal>>::new();
        for entry in store
            .range(ops::RangeFrom {
                start: FixedIdentityKey(
                    namespace.to_string(),
                    String::new(),
                    Principal::management_canister(),
                ),
            })
            .take_while(|entry| entry.key().0 == namespace)
        {
            values
                .entry(entry.key().1.clone())
                .or_default()
                .insert(entry.key().2);
        }
        values
    })
}

pub(super) fn namespace_info(name: String, ns: Namespace) -> NamespaceInfo {
    let mut info = ns.clone().into_info(name.clone());
    if ns.acl_version == 0 {
        info.managers.remove(&Principal::anonymous());
        info.auditors.remove(&Principal::anonymous());
        info.users.remove(&Principal::anonymous());
        info.fixed_id_names = fixed_identities(&name, &ns);
    } else {
        info.managers = role_members(&name, &ns, ROLE_MANAGER);
        info.auditors = role_members(&name, &ns, ROLE_AUDITOR);
        info.users = role_members(&name, &ns, ROLE_USER);
        info.fixed_id_names = fixed_identities(&name, &ns);
    }
    info
}

pub(super) fn namespace_summary(name: String, ns: Namespace) -> NamespaceInfo {
    let mut info = ns.into_info(name);
    info.managers.clear();
    info.auditors.clear();
    info.users.clear();
    info.fixed_id_names.clear();
    info
}

fn namespace_info_bounded(name: String, ns: Namespace) -> NamespaceInfo {
    if ns.info_size_hint() > MAX_NAMESPACE_PAGE_BYTES {
        namespace_summary(name, ns)
    } else {
        namespace_info(name, ns)
    }
}

fn remove_namespace_acl(namespace: &str) {
    ACL_STORE.with_borrow_mut(|store| {
        let keys: Vec<AclKey> = store
            .range(ops::RangeFrom {
                start: AclKey(
                    namespace.to_string(),
                    ROLE_MANAGER,
                    Principal::management_canister(),
                ),
            })
            .take_while(|entry| entry.key().0 == namespace)
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys {
            store.remove(&key);
        }
    });
    FIXED_IDENTITY_STORE.with_borrow_mut(|store| {
        let keys: Vec<FixedIdentityKey> = store
            .range(ops::RangeFrom {
                start: FixedIdentityKey(
                    namespace.to_string(),
                    String::new(),
                    Principal::management_canister(),
                ),
            })
            .take_while(|entry| entry.key().0 == namespace)
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys {
            store.remove(&key);
        }
    });
}

fn mutate_members(
    namespace: String,
    caller: &Principal,
    role: u8,
    values: BTreeSet<Principal>,
    add: bool,
    now_ms: u64,
) -> Result<(), String> {
    with_mut(namespace.clone(), |ns| {
        if !ns.can_manage_namespace(&namespace, caller) {
            return Err("no permission".to_string());
        }
        let current_count = if ns.acl_version == 0 {
            role_members(&namespace, ns, role).len()
        } else {
            (match role {
                ROLE_MANAGER => ns.manager_count,
                ROLE_AUDITOR => ns.auditor_count,
                ROLE_USER => ns.user_count,
                _ => unreachable!(),
            }) as usize
        };
        let changes: Vec<_> = values
            .into_iter()
            .filter(|principal| ns.has_role(&namespace, role, principal) != add)
            .collect();
        let count = if add {
            current_count + changes.len()
        } else {
            current_count
                .checked_sub(changes.len())
                .ok_or("namespace role count is inconsistent")?
        };
        if add && count > MAX_NAMESPACE_ROLE_PRINCIPALS {
            return Err(format!(
                "namespace role count exceeds the limit {MAX_NAMESPACE_ROLE_PRINCIPALS}"
            ));
        }
        if !add && role == ROLE_MANAGER && count == 0 {
            return Err("namespace must retain at least one manager".to_string());
        }
        ensure_acl_v1(&namespace, ns);
        ACL_STORE.with_borrow_mut(|store| {
            for principal in changes {
                let key = AclKey(namespace.clone(), role, principal);
                if add {
                    store.insert(key, 0);
                } else {
                    store.remove(&key);
                }
            }
        });
        let count = count as u32;
        match role {
            ROLE_MANAGER => ns.manager_count = count,
            ROLE_AUDITOR => ns.auditor_count = count,
            ROLE_USER => ns.user_count = count,
            _ => unreachable!(),
        }
        ns.updated_at = now_ms;
        Ok(())
    })
}

pub fn add_managers(
    namespace: String,
    caller: &Principal,
    values: BTreeSet<Principal>,
    now_ms: u64,
) -> Result<(), String> {
    mutate_members(namespace, caller, ROLE_MANAGER, values, true, now_ms)
}

pub fn remove_managers(
    namespace: String,
    caller: &Principal,
    values: BTreeSet<Principal>,
    now_ms: u64,
) -> Result<(), String> {
    mutate_members(namespace, caller, ROLE_MANAGER, values, false, now_ms)
}

pub fn recover_managers(
    namespace: String,
    values: BTreeSet<Principal>,
    now_ms: u64,
) -> Result<(), String> {
    with_mut(namespace.clone(), |ns| {
        if !role_members(&namespace, ns, ROLE_MANAGER).is_empty() {
            return Err("namespace still has a manager".to_string());
        }
        ensure_acl_v1(&namespace, ns);
        ACL_STORE.with_borrow_mut(|store| {
            for principal in &values {
                store.insert(AclKey(namespace.clone(), ROLE_MANAGER, *principal), 0);
            }
        });
        ns.manager_count = values.len() as u32;
        ns.updated_at = now_ms;
        Ok(())
    })
}

pub fn add_auditors(
    namespace: String,
    caller: &Principal,
    values: BTreeSet<Principal>,
    now_ms: u64,
) -> Result<(), String> {
    mutate_members(namespace, caller, ROLE_AUDITOR, values, true, now_ms)
}

pub fn remove_auditors(
    namespace: String,
    caller: &Principal,
    values: BTreeSet<Principal>,
    now_ms: u64,
) -> Result<(), String> {
    mutate_members(namespace, caller, ROLE_AUDITOR, values, false, now_ms)
}

pub fn add_users(
    namespace: String,
    caller: &Principal,
    values: BTreeSet<Principal>,
    now_ms: u64,
) -> Result<(), String> {
    mutate_members(namespace, caller, ROLE_USER, values, true, now_ms)
}

pub fn remove_users(
    namespace: String,
    caller: &Principal,
    values: BTreeSet<Principal>,
    now_ms: u64,
) -> Result<(), String> {
    mutate_members(namespace, caller, ROLE_USER, values, false, now_ms)
}

pub fn is_member(
    namespace: &str,
    caller: &Principal,
    member_kind: &str,
    user: &Principal,
) -> Result<bool, String> {
    with(&namespace.to_string(), |ns| {
        if !ns.can_read_namespace(namespace, caller) {
            return Err("no permission".to_string());
        }
        let role = match member_kind {
            "manager" => ROLE_MANAGER,
            "auditor" => ROLE_AUDITOR,
            "user" => ROLE_USER,
            _ => return Err(format!("invalid member kind: {member_kind}")),
        };
        Ok(ns.has_role(namespace, role, user))
    })
}

pub fn list_members(
    namespace: &str,
    caller: &Principal,
    member_kind: &str,
    prev: Option<Principal>,
    take: usize,
) -> Result<Vec<Principal>, String> {
    with(&namespace.to_string(), |ns| {
        if !ns.can_read_namespace(namespace, caller) {
            return Err("no permission".to_string());
        }
        let role = match member_kind {
            "manager" => ROLE_MANAGER,
            "auditor" => ROLE_AUDITOR,
            "user" => ROLE_USER,
            _ => return Err(format!("invalid member kind: {member_kind}")),
        };
        if ns.acl_version == 0 {
            return Ok(role_members(namespace, &ns, role)
                .into_iter()
                .filter(|principal| prev.is_none_or(|cursor| principal > &cursor))
                .take(take)
                .collect());
        }
        let lower = prev
            .map(|principal| {
                std::ops::Bound::Excluded(AclKey(namespace.to_string(), role, principal))
            })
            .unwrap_or_else(|| {
                std::ops::Bound::Included(AclKey(
                    namespace.to_string(),
                    role,
                    Principal::management_canister(),
                ))
            });
        Ok(ACL_STORE.with_borrow(|store| {
            store
                .range((lower, std::ops::Bound::Unbounded))
                .take_while(|entry| entry.key().0 == namespace && entry.key().1 == role)
                .take(take)
                .map(|entry| entry.key().2)
                .collect()
        }))
    })
}

pub fn list_fixed_identity_names(
    namespace: &str,
    caller: &Principal,
    prev: Option<String>,
    take: usize,
) -> Result<Vec<String>, String> {
    with(&namespace.to_string(), |ns| {
        if !ns.can_read_namespace(namespace, caller) {
            return Err("no permission".to_string());
        }
        if ns.acl_version == 0 {
            return Ok(ns
                .fixed_id_names
                .iter()
                .filter(|(_, principals)| {
                    principals
                        .iter()
                        .any(|principal| *principal != Principal::anonymous())
                })
                .map(|(name, _)| name)
                .filter(|name| prev.as_ref().is_none_or(|cursor| *name > cursor))
                .take(take)
                .cloned()
                .collect());
        }

        let start_name = prev.clone().unwrap_or_default();
        Ok(FIXED_IDENTITY_STORE.with_borrow(|store| {
            let mut last_name: Option<String> = None;
            store
                .range(ops::RangeFrom {
                    start: FixedIdentityKey(
                        namespace.to_string(),
                        start_name,
                        Principal::management_canister(),
                    ),
                })
                .take_while(|entry| entry.key().0 == namespace)
                .filter_map(|entry| {
                    let name = &entry.key().1;
                    if prev.as_ref().is_some_and(|cursor| name <= cursor)
                        || last_name.as_ref() == Some(name)
                    {
                        return None;
                    }
                    last_name = Some(name.clone());
                    Some(name.clone())
                })
                .take(take)
                .collect()
        }))
    })
}

pub fn get_delegators(
    namespace: &str,
    name: &str,
    caller: &Principal,
) -> Result<BTreeSet<Principal>, String> {
    with(&namespace.to_string(), |ns| {
        if !ns.can_read_namespace(namespace, caller) {
            return Err("no permission".to_string());
        }
        let values: BTreeSet<Principal> = if ns.acl_version == 0 {
            ns.fixed_id_names
                .get(name)
                .into_iter()
                .flatten()
                .copied()
                .filter(|principal| *principal != Principal::anonymous())
                .collect()
        } else {
            FIXED_IDENTITY_STORE.with_borrow(|store| {
                store
                    .range(ops::RangeFrom {
                        start: FixedIdentityKey(
                            namespace.to_string(),
                            name.to_string(),
                            Principal::management_canister(),
                        ),
                    })
                    .take_while(|entry| entry.key().0 == namespace && entry.key().1 == name)
                    .map(|entry| entry.key().2)
                    .collect()
            })
        };
        if values.is_empty() {
            Err("NotFound: name not found".to_string())
        } else {
            Ok(values)
        }
    })
}

pub fn mutate_delegators(
    namespace: String,
    name: String,
    caller: &Principal,
    values: BTreeSet<Principal>,
    add: bool,
    now_ms: u64,
) -> Result<BTreeSet<Principal>, String> {
    with_mut(namespace.clone(), |ns| {
        if !ns.can_manage_namespace(&namespace, caller) {
            return Err("no permission".to_string());
        }
        let current = if ns.acl_version == 0 {
            ns.fixed_id_names.get(&name).cloned().unwrap_or_default()
        } else {
            FIXED_IDENTITY_STORE.with_borrow(|store| {
                store
                    .range(ops::RangeFrom {
                        start: FixedIdentityKey(
                            namespace.clone(),
                            name.clone(),
                            Principal::management_canister(),
                        ),
                    })
                    .take_while(|entry| entry.key().0 == namespace && entry.key().1 == name)
                    .map(|entry| entry.key().2)
                    .collect()
            })
        };
        let current_len = current.len();
        let current_total = if ns.acl_version == 0 {
            ns.fixed_id_names.values().map(BTreeSet::len).sum::<usize>()
        } else {
            ns.fixed_delegator_count as usize
        };
        let mut next = current;
        if add {
            next.extend(values.iter().copied());
            if next.len() > MAX_NAMESPACE_FIXED_DELEGATORS
                || current_total
                    .saturating_sub(current_len)
                    .saturating_add(next.len())
                    > MAX_NAMESPACE_FIXED_DELEGATORS
            {
                return Err("fixed identity delegators exceed the namespace limit".to_string());
            }
        } else {
            next.retain(|principal| !values.contains(principal));
        }
        let next_total = current_total
            .saturating_sub(current_len)
            .saturating_add(next.len());
        ensure_acl_v1(&namespace, ns);
        FIXED_IDENTITY_STORE.with_borrow_mut(|store| {
            for principal in values {
                let key = FixedIdentityKey(namespace.clone(), name.clone(), principal);
                if add {
                    store.insert(key, 0);
                } else {
                    store.remove(&key);
                }
            }
        });
        ns.fixed_delegator_count = next_total as u32;
        ns.updated_at = now_ms;
        Ok(next)
    })
}

pub fn delegation_session_expiry(
    namespace: &str,
    name: &str,
    caller: &Principal,
) -> Result<u64, String> {
    if caller == &Principal::anonymous() {
        return Err("anonymous user is not a delegator".to_string());
    }
    with(&namespace.to_string(), |ns| {
        let allowed = if ns.acl_version == 0 {
            ns.fixed_id_names
                .get(name)
                .is_some_and(|delegators| delegators.contains(caller))
        } else {
            FIXED_IDENTITY_STORE.with_borrow(|store| {
                store.contains_key(&FixedIdentityKey(
                    namespace.to_string(),
                    name.to_string(),
                    *caller,
                ))
            })
        };
        if allowed {
            Ok(ns.session_expires_in_ms)
        } else {
            Err(format!("caller {} is not a delegator", caller))
        }
    })
}

pub(super) fn debit_namespace_cycles(
    ns: &mut Namespace,
    amount: u128,
    liquid: u128,
    threshold: u128,
) -> Result<(), String> {
    let required = threshold
        .checked_add(amount)
        .ok_or_else(|| "cycle reserve calculation overflowed".to_string())?;
    if liquid < required {
        return Err(format!(
            "insufficient liquid cycles: balance {liquid}, required {required}"
        ));
    }
    if ns.gas_balance < amount {
        return Err(format!(
            "insufficient namespace gas: balance {}, required {}",
            ns.gas_balance, amount
        ));
    }
    ns.gas_balance -= amount;
    Ok(())
}

struct NamespaceCharge {
    namespace: String,
    created_at: u64,
    amount: u128,
}

impl NamespaceCharge {
    fn refund(self, amount: u128) {
        if amount == 0 {
            return;
        }
        // Deleting a namespace forfeits its balance. Do not credit a later
        // namespace incarnation with a refund belonging to an earlier one.
        let _ = with_mut(self.namespace, |ns| {
            if ns.created_at == self.created_at {
                ns.gas_balance = ns.gas_balance.saturating_add(amount.min(self.amount));
            }
            Ok(())
        });
    }
}

fn charge_namespace_cycles(namespace: &str, amount: u128) -> Result<NamespaceCharge, String> {
    let threshold = state::with(|s| u128::from(s.freezing_threshold));
    let liquid = ic_cdk::api::canister_liquid_cycle_balance();
    with_mut(namespace.to_string(), |ns| {
        debit_namespace_cycles(ns, amount, liquid, threshold)?;
        ensure_acl_v1(namespace, ns);
        Ok(NamespaceCharge {
            namespace: namespace.to_string(),
            created_at: ns.created_at,
            amount,
        })
    })
}

async fn execute_chain_key(namespace: &str, operation: Operation) -> Result<Vec<u8>, String> {
    let cost = operation.cost()?;
    let reserved = cost.total()?;
    let charge = charge_namespace_cycles(namespace, reserved)?;
    let result = operation.execute().await;
    // A pre-dispatch failure is not a callback; the refunded-cycles syscall
    // is only legal after a call that was actually sent.
    let not_sent = result
        .as_ref()
        .err()
        .is_some_and(|error| classify_failure(error) == FailureKind::NotSent);
    let refunded = if not_sent {
        0
    } else {
        ic_cdk::api::msg_cycles_refunded()
    };
    charge.refund(reserved.saturating_sub(cost_upper_bound(cost, result.as_ref().err(), refunded)));
    result.map_err(format_error)
}

async fn execute_free_management_call<T>(
    namespace: &str,
    method: &str,
    payload_bytes: usize,
    call: impl std::future::Future<Output = Result<T, ic_cdk::call::Error>>,
) -> Result<T, String> {
    let amount = ic_cdk::api::cost_call(method.len() as u64, payload_bytes as u64);
    let charge = charge_namespace_cycles(namespace, amount)?;
    let result = call.await;
    if matches!(
        &result,
        Err(ic_cdk::call::Error::InsufficientLiquidCycleBalance(_)
            | ic_cdk::call::Error::CallPerformFailed(_))
    ) {
        charge.refund(amount);
    }
    result.map_err(format_error)
}

pub async fn random_bytes<const N: usize>(namespace: &str) -> Result<[u8; N], String> {
    // The management binding sends the six-byte Candid empty argument list.
    let mut bytes = execute_free_management_call(
        namespace,
        "raw_rand",
        6,
        ic_cdk_management_canister::raw_rand(),
    )
    .await?;
    bytes.truncate(N);
    bytes.try_into().map_err(format_error)
}

pub fn top_up_namespace(
    namespace: String,
    requested: u128,
    available: u128,
    now_ms: u64,
) -> Result<u128, String> {
    if requested > available {
        return Err("insufficient cycles".to_string());
    }
    with_mut(namespace.clone(), |ns| {
        ns.gas_balance
            .checked_add(requested)
            .ok_or_else(|| "namespace gas balance overflowed".to_string())?;
        ensure_acl_v1(&namespace, ns);
        let received = ic_cdk::api::msg_cycles_accept(requested);
        ns.gas_balance = ns
            .gas_balance
            .checked_add(received)
            .expect("accepted cycles were pre-validated against the gas balance");
        ns.updated_at = now_ms;
        Ok(received)
    })
}

pub fn migrate(m: BTreeMap<String, NamespaceLegacy>) {
    if m.is_empty() {
        return;
    }

    NAMESPACES_STORE.with_borrow_mut(|r| {
        for (name, ns) in m {
            let mut nns = Namespace {
                desc: ns.desc,
                created_at: ns.created_at,
                updated_at: ns.updated_at,
                max_payload_size: ns.max_payload_size,
                payload_bytes_total: ns.payload_bytes_total,
                status: ns.status,
                visibility: ns.visibility,
                managers: ns.managers,
                auditors: ns.auditors,
                users: ns.users,
                gas_balance: ns.gas_balance,
                fixed_id_names: ns.fixed_id_names,
                session_expires_in_ms: ns.session_expires_in_ms,
                ..Default::default()
            };
            ensure_acl_v1(&name, &mut nns);
            r.insert(name.clone(), nns);
            for (k, setting) in ns.settings {
                let spk = SettingPathKey(name.clone(), 0, k.0, k.1, 0);
                save_setting(spk, setting);
            }
            for (k, setting) in ns.user_settings {
                let spk = SettingPathKey(name.clone(), 1, k.0, k.1, 0);
                save_setting(spk, setting);
            }
        }
    });
}

pub fn namespace_count() -> u64 {
    NAMESPACES_STORE.with_borrow(|r| r.len())
}

pub fn migrate_legacy_settings(take: usize) -> u64 {
    let keys: Vec<SettingPathKey> =
        SETTINGS_STORE.with_borrow(|store| store.keys().take(take).collect());
    for key in &keys {
        if let Some(setting) = SETTINGS_STORE.with_borrow(|store| store.get(key)) {
            save_setting(key.clone(), setting);
        }
    }
    keys.len() as u64
}

pub fn migrate_legacy_namespace_acls_page(
    prev: Option<String>,
    scan_limit: usize,
) -> ic_cose_types::types::ScanPage<String, String> {
    let page = NAMESPACES_STORE.with_borrow(|store| {
        let lower = prev
            .map(std::ops::Bound::Excluded)
            .unwrap_or(std::ops::Bound::Unbounded);
        let mut iter = store.range((lower, std::ops::Bound::Unbounded));
        let mut items = Vec::new();
        let mut last = None;
        for entry in iter.by_ref().take(scan_limit.clamp(1, 100)) {
            last = Some(entry.key().clone());
            if entry.value().acl_version == 0 {
                items.push(entry.key().clone());
            }
        }
        let next_cursor = iter.next().and(last);
        ic_cose_types::types::ScanPage { items, next_cursor }
    });
    for name in &page.items {
        with_mut(name.clone(), |ns| {
            ensure_acl_v1(name, ns);
            Ok(())
        })
        .expect("scanned namespace exists during synchronous migration");
    }
    page
}

pub fn migrate_legacy_namespace_acls(take: usize) -> u64 {
    let names: Vec<String> = NAMESPACES_STORE.with_borrow(|store| {
        store
            .iter()
            .filter_map(|entry| (entry.value().acl_version == 0).then(|| entry.key().clone()))
            .take(take)
            .collect()
    });
    for name in &names {
        let _ = with_mut(name.clone(), |namespace| {
            ensure_acl_v1(name, namespace);
            Ok(())
        });
    }
    names.len() as u64
}

pub fn rebuild_payload_bytes(namespace: String, caller: &Principal) -> Result<u64, String> {
    with_mut(namespace.clone(), |ns| {
        if !ns.can_manage_namespace(&namespace, caller) {
            return Err("no permission".to_string());
        }
        let start = SettingPathKey(
            namespace.clone(),
            0,
            Principal::management_canister(),
            ByteBuf::new(),
            0,
        );
        let legacy = SETTINGS_STORE.with_borrow(|store| {
            store
                .range(ops::RangeFrom {
                    start: start.clone(),
                })
                .take_while(|entry| entry.key().0 == namespace)
                .fold(0u64, |total, entry| {
                    total.saturating_add(entry.value().data_size())
                })
        });
        let current = SETTING_DATA_STORE.with_borrow(|store| {
            store
                .range(ops::RangeFrom {
                    start: start.clone(),
                })
                .take_while(|entry| entry.key().0 == namespace)
                .fold(0u64, |total, entry| {
                    total.saturating_add(entry.value().size() as u64)
                })
        });
        let archived = PAYLOADS_STORE.with_borrow(|store| {
            store
                .range(ops::RangeFrom { start })
                .take_while(|entry| entry.key().0 == namespace)
                .fold(0u64, |total, entry| {
                    total.saturating_add(entry.value().data_size())
                })
        });
        let total = legacy.saturating_add(current).saturating_add(archived);
        ensure_acl_v1(&namespace, ns);
        ns.payload_bytes_total = total;
        Ok(total)
    })
}

const MAX_KEY: [u8; 64] = [255u8; 64];

fn signing_derivation_path(domain: &[u8], namespace: String, suffix: Vec<ByteBuf>) -> Vec<Vec<u8>> {
    let mut path = Vec::with_capacity(suffix.len() + 2);
    path.push(domain.to_vec());
    path.push(namespace.into_bytes());
    path.extend(suffix.into_iter().map(ByteBuf::into_vec));
    path
}

#[cfg(test)]
pub fn list_setting_keys(
    namespace: &str,
    user_owned: bool,
    subject: Option<Principal>,
) -> Vec<(Principal, ByteBuf)> {
    list_setting_keys_page(namespace, user_owned, subject, None, usize::MAX)
}

pub fn list_setting_keys_page(
    namespace: &str,
    user_owned: bool,
    subject: Option<Principal>,
    prev: Option<(Principal, ByteBuf)>,
    take: usize,
) -> Vec<(Principal, ByteBuf)> {
    let kind = u8::from(user_owned);
    let start = SettingPathKey(
        namespace.to_owned(),
        kind,
        subject.unwrap_or_else(Principal::management_canister),
        ByteBuf::new(),
        0,
    );
    let lower = prev
        .map(|(principal, key)| {
            std::ops::Bound::Excluded(SettingPathKey(
                namespace.to_owned(),
                kind,
                principal,
                key,
                u32::MAX,
            ))
        })
        .unwrap_or(std::ops::Bound::Included(start));
    let upper = if let Some(subject) = subject {
        std::ops::Bound::Included(SettingPathKey(
            namespace.to_owned(),
            kind,
            subject,
            ByteBuf::from(MAX_KEY.as_ref()),
            u32::MAX,
        ))
    } else {
        std::ops::Bound::Excluded(SettingPathKey(
            namespace.to_owned(),
            kind + 1,
            Principal::management_canister(),
            ByteBuf::new(),
            0,
        ))
    };
    let legacy = SETTINGS_STORE.with_borrow(|store| {
        store
            .keys_range((lower.clone(), upper.clone()))
            .take(take)
            .collect::<Vec<_>>()
    });
    let modern = SETTING_META_STORE.with_borrow(|store| {
        store
            .keys_range((lower, upper))
            .take(take)
            .collect::<Vec<_>>()
    });
    legacy
        .into_iter()
        .chain(modern)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(take)
        .map(|key| (key.2, key.3))
        .collect()
}

pub fn with<R>(
    namespace: &String,
    f: impl FnOnce(Namespace) -> Result<R, String>,
) -> Result<R, String> {
    NAMESPACES_STORE.with_borrow(|r| {
        r.get(namespace)
            .map(f)
            .unwrap_or_else(|| Err(format!("NotFound: namespace {} not found", namespace)))
    })
}

pub fn with_mut<R>(
    namespace: String,
    f: impl FnOnce(&mut Namespace) -> Result<R, String>,
) -> Result<R, String> {
    NAMESPACES_STORE.with_borrow_mut(|r| match r.get(&namespace) {
        Some(mut ns) => match f(&mut ns) {
            Ok(rt) => {
                r.insert(namespace, ns);
                Ok(rt)
            }
            Err(err) => Err(err),
        },
        None => Err(format!("NotFound: namespace {} not found", namespace)),
    })
}

pub fn has_kek_permission(caller: &Principal, spk: &SettingPathKey) -> bool {
    if caller == &Principal::anonymous() {
        return false;
    }
    with(&spk.0, |ns| {
        if ns.status < 0 && !ns.has_role(&spk.0, ROLE_MANAGER, caller) {
            return Ok(false);
        }

        if ns.has_role(&spk.0, ROLE_AUDITOR, caller)
            || (spk.1 == 0 && ns.has_role(&spk.0, ROLE_MANAGER, caller))
        {
            return Ok(true);
        }

        // Members can prefetch their own key before creating a setting.
        // External subjects and readers need an existing setting grant so
        // arbitrary callers cannot spend another namespace's cycles.
        if caller == &spk.2
            && (ns.has_role(&spk.0, ROLE_USER, caller) || ns.has_role(&spk.0, ROLE_MANAGER, caller))
        {
            return Ok(true);
        }
        let setting = load_setting_metadata(&spk.v0()).map(|(setting, _)| setting);
        Ok(setting.is_some_and(|s| caller == &spk.2 || s.readers.contains(caller)))
    })
    .unwrap_or(false)
}

pub fn has_vetkd_public_key_permission(caller: &Principal, spk: &SettingPathKey) -> bool {
    // Visibility permits reading published data, not spending the namespace's
    // budget on a management call. Members and existing setting grants may pay.
    with(&spk.0, |ns| {
        Ok(ns.can_read_namespace(&spk.0, caller)
            && (ns.has_role(&spk.0, ROLE_MANAGER, caller)
                || ns.has_role(&spk.0, ROLE_AUDITOR, caller)
                || ns.has_role(&spk.0, ROLE_USER, caller)))
    })
    .unwrap_or(false)
        || has_kek_permission(caller, spk)
}

pub fn ecdsa_public_key(
    caller: &Principal,
    namespace: String,
    derivation_path: Vec<ByteBuf>,
) -> Result<PublicKeyOutput, String> {
    ic_cose_types::types::validate_derivation_path(&derivation_path)?;
    with(&namespace, |ns| {
        if !ns.can_read_namespace(&namespace, caller) {
            Err("no permission".to_string())?;
        }
        Ok(())
    })?;

    state::with(|s| {
        let pk = s.ecdsa_public_key.as_ref().ok_or("no ecdsa public key")?;
        let path = signing_derivation_path(b"COSE_ECDSA_Signing", namespace, derivation_path);
        derive_public_key(pk, path)
    })
}

pub async fn ecdsa_sign_with(
    caller: &Principal,
    namespace: String,
    derivation_path: Vec<ByteBuf>,
    message: ByteBuf,
) -> Result<ByteBuf, String> {
    if message.len() != 32 {
        return Err("message must be 32 bytes".to_string());
    }
    ic_cose_types::types::validate_derivation_path(&derivation_path)?;
    with(&namespace, |ns| {
        if !ns.has_ns_signing_permission(&namespace, caller) {
            Err("no permission".to_string())?;
        }
        Ok(())
    })?;

    let key_name = state::with(|s| s.ecdsa_key_name.clone());
    let path = signing_derivation_path(b"COSE_ECDSA_Signing", namespace.clone(), derivation_path);
    let hash: [u8; 32] = message
        .as_slice()
        .try_into()
        .map_err(|_| "message must be 32 bytes")?;
    let sig = execute_chain_key(&namespace, Operation::ecdsa(key_name, path, hash)).await?;
    Ok(ByteBuf::from(sig))
}

pub fn schnorr_public_key(
    caller: &Principal,
    alg: SchnorrAlgorithm,
    namespace: String,
    derivation_path: Vec<ByteBuf>,
) -> Result<PublicKeyOutput, String> {
    ic_cose_types::types::validate_derivation_path(&derivation_path)?;
    with(&namespace, |ns| {
        if !ns.can_read_namespace(&namespace, caller) {
            Err("no permission".to_string())?;
        }
        Ok(())
    })?;

    state::with(|s| {
        let pk = match alg {
            SchnorrAlgorithm::Bip340secp256k1 => s
                .schnorr_secp256k1_public_key
                .as_ref()
                .ok_or("no schnorr secp256k1 public key")?,
            SchnorrAlgorithm::Ed25519 => s
                .schnorr_ed25519_public_key
                .as_ref()
                .ok_or("no schnorr ed25519 public key")?,
        };
        let path = signing_derivation_path(b"COSE_Schnorr_Signing", namespace, derivation_path);
        derive_schnorr_public_key(alg, pk, path)
    })
}

pub async fn schnorr_sign_with(
    caller: &Principal,
    alg: SchnorrAlgorithm,
    namespace: String,
    derivation_path: Vec<ByteBuf>,
    message: ByteBuf,
) -> Result<ByteBuf, String> {
    ic_cose_types::types::validate_derivation_path(&derivation_path)?;
    with(&namespace, |ns| {
        if !ns.has_ns_signing_permission(&namespace, caller) {
            Err("no permission".to_string())?;
        }
        Ok(())
    })?;

    let key_name = state::with(|s| s.schnorr_key_name.clone());
    let path = signing_derivation_path(b"COSE_Schnorr_Signing", namespace.clone(), derivation_path);
    let sig = execute_chain_key(
        &namespace,
        Operation::schnorr(key_name, alg, path, message.into_vec()),
    )
    .await?;
    Ok(ByteBuf::from(sig))
}

const CWT_EXPIRATION_SECONDS: i64 = 3600;
fn identity_permission(namespace: &String, caller: &Principal) -> Result<String, String> {
    with(namespace, |ns| {
        if ns.has_role(namespace, ROLE_MANAGER, caller) {
            Ok(format!("Namespace.*:{namespace}"))
        } else if ns.has_role(namespace, ROLE_USER, caller) {
            if ns.has_role(namespace, ROLE_AUDITOR, caller) {
                Ok(format!(
                    "Namespace.Read:{namespace} Namespace.*.SubjectedSetting:{namespace}"
                ))
            } else {
                Ok(format!(
                    "Namespace.Read.Info:{namespace} Namespace.*.SubjectedSetting:{namespace}"
                ))
            }
        } else if ns.has_role(namespace, ROLE_AUDITOR, caller) {
            Ok(format!("Namespace.Read:{namespace}"))
        } else {
            Err("no permission".to_string())
        }
    })
}

pub async fn sign_identity(
    caller: &Principal,
    namespace: String,
    audience: String,
    algorithm: SchnorrAlgorithm,
) -> Result<ByteBuf, String> {
    let cose_algorithm = identity_cose_algorithm(algorithm)?;
    identity_permission(&namespace, caller)?;

    let key_name = state::with(|s| s.schnorr_key_name.clone());
    let cwt_id: [u8; 16] = random_bytes(&namespace).await?;
    // `raw_rand` is an await boundary: roles may have changed while this
    // message was suspended, before the expensive signature is dispatched.
    let permission = identity_permission(&namespace, caller)?;
    let now_sec = (ic_cdk::api::time() / MILLISECONDS / 1000) as i64;
    let claims = ClaimsSet {
        issuer: Some(ic_cdk::api::canister_self().to_text()),
        subject: Some(caller.to_text()),
        audience: Some(audience.into()),
        expiration: Some((now_sec + CWT_EXPIRATION_SECONDS).into()),
        not_before: Some(now_sec.into()),
        issued_at: Some(now_sec.into()),
        cwt_id: Some(cwt_id.into()),
        extra: scope_claim(permission),
    };
    let payload = claims.to_vec().map_err(format_error)?;
    let mut sign1 = cose_sign1(payload, cose_algorithm, None)?;
    let tbs_data = sign1
        .prepare_signature(None, None, Some(caller.as_slice()))
        .map_err(format_error)?;
    let sig = execute_chain_key(
        &namespace,
        Operation::schnorr(key_name, algorithm, vec![], tbs_data),
    )
    .await?;
    sign1.set_signature(sig).map_err(format_error)?;
    let token = sign1.to_vec().map_err(format_error)?;
    Ok(ByteBuf::from(token))
}

pub fn inner_derive_kek(spk: &SettingPathKey, key_id: &[u8]) -> Result<[u8; 32], String> {
    state::with(|s| {
        if *s.init_vector == [0u8; 32] {
            return Err("key derivation is not initialized".to_string());
        }
        let pk = s
            .schnorr_secp256k1_public_key
            .as_ref()
            .ok_or("no schnorr secp256k1 public key")?;

        let derivation_path = vec![
            b"COSE_Symmetric_Key".to_vec(),
            s.init_vector.to_vec(),
            spk.2.as_slice().to_vec(),
            vec![spk.1],
            spk.0.as_bytes().to_vec(),
        ];
        let pk = derive_schnorr_public_key(SchnorrAlgorithm::Bip340secp256k1, pk, derivation_path)?;
        Ok(mac3_256(&pk.public_key, key_id))
    })
}

pub async fn inner_vetkd_public_key(spk: &SettingPathKey) -> Result<Vec<u8>, String> {
    let (key_name, context_version) =
        state::with(|r| (r.vetkd_key_name.clone(), r.vetkd_context_version));
    let context = [
        b"COSE_Symmetric_Key".as_slice(),
        spk.2.as_slice(),
        &[spk.1],
        spk.0.as_bytes(),
    ];
    let args = ic_cdk_management_canister::VetKDPublicKeyArgs {
        canister_id: None,
        context: derivation_path_to_context(context_version, &context)?,
        key_id: ic_cdk_management_canister::VetKDKeyId {
            curve: ic_cdk_management_canister::VetKDCurve::Bls12_381_G2,
            name: key_name,
        },
    };
    let payload_bytes = candid::encode_one(&args).map_err(format_error)?.len();
    execute_free_management_call(
        &spk.0,
        "vetkd_public_key",
        payload_bytes,
        ic_cdk_management_canister::vetkd_public_key(&args),
    )
    .await
    .map(|result| result.public_key)
}

pub async fn inner_vetkd_encrypted_key(
    spk: &SettingPathKey,
    key_id: Vec<u8>,
    transport_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let (key_name, context_version) =
        state::with(|r| (r.vetkd_key_name.clone(), r.vetkd_context_version));
    let context = [
        b"COSE_Symmetric_Key".as_slice(),
        spk.2.as_slice(),
        &[spk.1],
        spk.0.as_bytes(),
    ];
    let operation = Operation::vetkd(
        key_name,
        derivation_path_to_context(context_version, &context)?,
        key_id,
        transport_public_key,
    );
    execute_chain_key(&spk.0, operation).await
}

pub fn get_namespace(caller: &Principal, namespace: String) -> Result<NamespaceInfo, String> {
    with(&namespace, |ns| {
        if !ns.can_read_namespace(&namespace, caller) {
            Err("no permission".to_string())?;
        }
        Ok(namespace_info_bounded(namespace.clone(), ns))
    })
}

pub fn get_namespace_v2(
    caller: &Principal,
    namespace: String,
    with_members: bool,
) -> Result<NamespaceInfo, String> {
    with(&namespace, |ns| {
        if !ns.can_read_namespace(&namespace, caller) {
            return Err("no permission".to_string());
        }
        if with_members {
            if ns.info_size_hint() > MAX_NAMESPACE_PAGE_BYTES {
                return Err(
                    "namespace members exceed one response; use paginated member methods"
                        .to_string(),
                );
            }
            Ok(namespace_info(namespace.clone(), ns))
        } else {
            Ok(namespace_summary(namespace.clone(), ns))
        }
    })
}

pub fn list_namespaces(prev: Option<String>, take: usize) -> Vec<NamespaceInfo> {
    NAMESPACES_STORE.with_borrow(|r| {
        let mut res = Vec::with_capacity(take);
        let mut estimated_bytes = 0usize;
        match prev {
            Some(p) => {
                for e in r.range(ops::RangeTo { end: p }).rev() {
                    let value = e.value();
                    let item_bytes = value.info_size_hint();
                    if !res.is_empty()
                        && estimated_bytes.saturating_add(item_bytes) > MAX_NAMESPACE_PAGE_BYTES
                    {
                        break;
                    }
                    estimated_bytes = estimated_bytes.saturating_add(item_bytes);
                    res.push(namespace_info_bounded(e.key().clone(), value));
                    if res.len() >= take {
                        break;
                    }
                }
            }
            None => {
                for e in r.iter().rev() {
                    let value = e.value();
                    let item_bytes = value.info_size_hint();
                    if !res.is_empty()
                        && estimated_bytes.saturating_add(item_bytes) > MAX_NAMESPACE_PAGE_BYTES
                    {
                        break;
                    }
                    estimated_bytes = estimated_bytes.saturating_add(item_bytes);
                    res.push(namespace_info_bounded(e.key().clone(), value));
                    if res.len() >= take {
                        break;
                    }
                }
            }
        };
        res
    })
}

pub fn create_namespace(input: CreateNamespaceInput, now_ms: u64) -> Result<NamespaceInfo, String> {
    NAMESPACES_STORE.with_borrow_mut(|r| {
        if r.contains_key(&input.name) {
            Err(format!("namespace {} already exists", input.name))?;
        }
        let mut ns = Namespace {
            desc: input.desc.unwrap_or_default(),
            created_at: now_ms,
            updated_at: now_ms,
            max_payload_size: input.max_payload_size.unwrap_or(MAX_PAYLOAD_SIZE),
            visibility: input.visibility,
            managers: input.managers,
            auditors: input.auditors,
            users: input.users,
            session_expires_in_ms: input.session_expires_in_ms.unwrap_or(SESSION_EXPIRES_IN_MS),
            ..Default::default()
        };

        if ns.encoded_size_hint() > MAX_NAMESPACE_RECORD_BYTES {
            return Err(format!(
                "namespace record exceeds the limit {} bytes",
                MAX_NAMESPACE_RECORD_BYTES
            ));
        }
        ensure_acl_v1(&input.name, &mut ns);
        let info = namespace_info(input.name.clone(), ns.clone());
        r.insert(input.name, ns);
        Ok(info)
    })
}

pub fn update_namespace_info(
    caller: &Principal,
    input: UpdateNamespaceInput,
    now_ms: u64,
) -> Result<(), String> {
    let namespace = input.name.clone();
    with_mut(namespace.clone(), |ns| {
        if !ns.can_manage_namespace(&namespace, caller) {
            Err("no permission".to_string())?;
        }

        ensure_acl_v1(&namespace, ns);

        if let Some(desc) = input.desc {
            ns.desc = desc;
        }
        if let Some(max_payload_size) = input.max_payload_size {
            ns.max_payload_size = max_payload_size;
        }
        if let Some(status) = input.status {
            ns.status = status;
        }
        if let Some(visibility) = input.visibility {
            ns.visibility = visibility;
        }
        if let Some(session_expires_in_ms) = input.session_expires_in_ms {
            ns.session_expires_in_ms = session_expires_in_ms;
        }
        ns.updated_at = now_ms;
        Ok(())
    })
}

pub fn delete_namespace(caller: &Principal, namespace: String) -> Result<(), String> {
    NAMESPACES_STORE.with_borrow_mut(|r| match r.get(&namespace) {
        Some(ns) => {
            if !ns.can_manage_namespace(&namespace, caller) {
                Err("no permission".to_string())?;
            }
            let has_legacy = SETTINGS_STORE.with_borrow(|rr| {
                // the range is open-ended, so the first key it yields may already
                // belong to a later namespace: only a key still carrying this
                // namespace means the namespace is not empty.
                let mut iter = rr.keys_range(ops::RangeFrom {
                    start: &SettingPathKey(
                        namespace.clone(),
                        0,
                        Principal::management_canister(), // the smallest principal
                        ByteBuf::new(),
                        0,
                    ),
                });
                iter.next().is_some_and(|k| k.0 == namespace)
            });
            let has_modern = SETTING_META_STORE.with_borrow(|rr| {
                let mut iter = rr.keys_range(ops::RangeFrom {
                    start: &SettingPathKey(
                        namespace.clone(),
                        0,
                        Principal::management_canister(),
                        ByteBuf::new(),
                        0,
                    ),
                });
                iter.next().is_some_and(|k| k.0 == namespace)
            });
            if has_legacy || has_modern {
                return Err(format!("namespace {} is not empty", namespace));
            }
            remove_namespace_acl(&namespace);
            r.remove(&namespace);
            Ok(())
        }
        None => Err(format!("NotFound: namespace {} not found", namespace)),
    })
}

fn try_get_setting(caller: &Principal, spk: &SettingPathKey, with_data: bool) -> Option<Setting> {
    with(&spk.0, |ns| {
        let can = ns.partial_can_read_setting(caller, spk);
        if can == Some(false) {
            return Ok(None);
        }

        let key = spk.v0();
        let setting = load_setting_metadata(&key).and_then(|(mut setting, legacy)| {
            if spk.4 > setting.version || (can != Some(true) && !setting.readers.contains(caller)) {
                return None;
            }
            if with_data && !legacy {
                if let Some(data) = SETTING_DATA_STORE.with_borrow(|store| store.get(&key)) {
                    setting.payload = data.payload;
                    setting.dek = data.dek;
                }
            }
            Some(setting)
        });
        Ok(setting)
    })
    .unwrap_or(None)
}

pub fn get_setting_info(caller: Principal, spk: SettingPathKey) -> Result<SettingInfo, String> {
    let setting = try_get_setting(&caller, &spk, false)
        .ok_or_else(|| format!("NotFound: setting {} not found or no permission", spk))?;

    Ok(setting.into_info(spk.2, spk.3, false))
}

pub fn get_setting(caller: Principal, spk: SettingPathKey) -> Result<SettingInfo, String> {
    let setting = try_get_setting(&caller, &spk, true)
        .ok_or_else(|| format!("NotFound: setting {} not found or no permission", spk))?;

    if spk.4 != 0 && spk.4 != setting.version {
        Err("version mismatch".to_string())?;
    };

    Ok(setting.into_info(spk.2, spk.3, true))
}

pub fn get_setting_archived_payload(
    caller: Principal,
    spk: SettingPathKey,
) -> Result<SettingArchivedPayload, String> {
    let setting = try_get_setting(&caller, &spk, false)
        .ok_or_else(|| format!("NotFound: setting {} not found or no permission", spk))?;

    if spk.4 == 0 || spk.4 >= setting.version {
        Err("version mismatch".to_string())?;
    };

    let payload = PAYLOADS_STORE.with_borrow(|r| {
        r.get(&spk)
            .ok_or_else(|| format!("NotFound: setting {} payload not found", spk))
    })?;

    Ok(SettingArchivedPayload {
        version: spk.4,
        archived_at: payload.archived_at,
        deprecated: payload.deprecated,
        payload: payload.payload,
        dek: payload.dek,
    })
}

pub fn create_setting(
    caller: Principal,
    spk: SettingPathKey,
    input: CreateSettingInput,
    now_ms: u64,
) -> Result<CreateSettingOutput, String> {
    with_mut(spk.0.clone(), |ns| {
        if !ns.can_write_setting(&caller, &spk) {
            Err("no permission".to_string())?;
        }

        if spk.4 != 0 {
            Err("version mismatch".to_string())?;
        }

        if let Some(ref payload) = input.payload {
            if payload.len() as u64 > ns.max_payload_size {
                Err("payload size exceeds the limit".to_string())?;
            }
        }

        let size = match input.dek {
            Some(ref dek) => {
                // should be valid COSE encrypt0 dek
                try_decode_encrypt0(dek)?;
                // should be valid COSE encrypt0 payload
                if let Some(ref payload) = input.payload {
                    try_decode_encrypt0(payload)?;
                    payload.len() + dek.len()
                } else {
                    dek.len()
                }
            }
            None => input
                .payload
                .as_ref()
                .map(|payload| payload.len())
                .unwrap_or(0),
        };

        if contains_setting(&spk) {
            return Err(format!("setting {} already exists", spk));
        }
        ensure_acl_v1(&spk.0, ns);
        save_setting(
            spk,
            Setting {
                desc: input.desc.unwrap_or_default(),
                created_at: now_ms,
                updated_at: now_ms,
                status: input.status.unwrap_or(0),
                tags: input.tags.unwrap_or_default(),
                payload: input.payload,
                dek: input.dek,
                version: 1,
                ..Default::default()
            },
        );

        let output = CreateSettingOutput {
            created_at: now_ms,
            updated_at: now_ms,
            version: 1,
        };

        ns.payload_bytes_total = ns.payload_bytes_total.saturating_add(size as u64);
        Ok(output)
    })
}

pub fn with_setting_mut<R>(
    caller: &Principal,
    spk: &SettingPathKey,
    f: impl FnOnce(&mut Setting) -> Result<R, String>,
) -> Result<R, String> {
    with(&spk.0, |ns| {
        if !ns.can_write_setting(caller, spk) {
            Err("no permission".to_string())?;
        }

        let spkv0 = spk.v0();
        match load_setting_metadata(&spkv0) {
            Some((mut setting, was_legacy)) => {
                if setting.version != spk.4 {
                    Err("version mismatch".to_string())?;
                }
                match f(&mut setting) {
                    Ok(rt) => {
                        save_setting_metadata(spkv0, setting, was_legacy);
                        Ok(rt)
                    }
                    Err(err) => Err(err),
                }
            }
            None => Err(format!("NotFound: setting {} not found", spk)),
        }
    })
}

pub fn delete_setting(caller: &Principal, spk: &SettingPathKey) -> Result<(), String> {
    with_mut(spk.0.clone(), |ns| {
        if !ns.can_write_setting(caller, spk) {
            Err("no permission".to_string())?;
        }

        let spkv0 = spk.v0();
        match load_setting_metadata(&spkv0) {
            Some((setting, _)) => {
                if setting.version != spk.4 {
                    Err("version mismatch".to_string())?;
                }
                if setting.status >= 1 {
                    Err("readonly setting can not be deleted".to_string())?;
                }

                ensure_acl_v1(&spk.0, ns);
                let mut removed_bytes = remove_setting(&spkv0)
                    .expect("setting was checked before deletion")
                    .data_size();
                if spk.4 > 1 {
                    PAYLOADS_STORE.with_borrow_mut(|rr| {
                        let mut pk = spk.clone();
                        for v in 1..spk.4 {
                            pk.4 = v;
                            if let Some(archived) = rr.remove(&pk) {
                                removed_bytes = removed_bytes.saturating_add(archived.data_size());
                            }
                        }
                    });
                }
                ns.payload_bytes_total = ns.payload_bytes_total.saturating_sub(removed_bytes);

                Ok(())
            }
            None => Err(format!("NotFound: setting {} not found", spk)),
        }
    })
}

pub fn update_setting_payload(
    caller: Principal,
    spk: SettingPathKey,
    input: UpdateSettingPayloadInput,
    now_ms: u64,
) -> Result<UpdateSettingOutput, String> {
    with_mut(spk.0.clone(), |ns| {
        if !ns.can_write_setting(&caller, &spk) {
            Err("no permission".to_string())?;
        }

        let mut size = if let Some(ref payload) = input.payload {
            payload.len()
        } else {
            0
        };
        if size as u64 > ns.max_payload_size {
            Err("payload size exceeds the limit".to_string())?;
        }
        if let Some(ref dek) = input.dek {
            size += dek.len();
            // A DEK is itself a COSE_Encrypt0 envelope. Reject malformed
            // data before reading or rewriting the current setting.
            try_decode_encrypt0(dek)?;
        }

        let spkv0 = spk.v0();
        let output = match load_setting(&spkv0) {
            Some(mut setting) => {
                if setting.version != spk.4 {
                    Err("version mismatch".to_string())?;
                }
                if setting.status != 0 {
                    Err("setting is not writable".to_string())?;
                }
                if setting.version >= ic_cose_types::types::setting::MAX_SETTING_VERSIONS {
                    return Err("setting version limit reached".to_string());
                }
                let next_version = setting
                    .version
                    .checked_add(1)
                    .ok_or_else(|| "setting version exhausted".to_string())?;

                if setting.dek.is_some() || input.dek.is_some() {
                    // When only the DEK changes, validate the retained payload
                    // as well; otherwise plaintext could be relabeled as encrypted.
                    if let Some(payload) = input.payload.as_ref().or(setting.payload.as_ref()) {
                        try_decode_encrypt0(payload)?;
                    }
                }

                ensure_acl_v1(&spk.0, ns);

                let previous_payload = match input.payload {
                    Some(payload) => setting.payload.replace(payload),
                    None => setting.payload.clone(),
                };
                let previous_dek = match input.dek {
                    Some(dek) => setting.dek.replace(dek),
                    None => setting.dek.clone(),
                };
                if previous_payload.is_some() || previous_dek.is_some() {
                    PAYLOADS_STORE.with_borrow_mut(|r| {
                        r.insert(
                            spk.clone(),
                            SettingArchived {
                                archived_at: now_ms,
                                deprecated: input.deprecate_current.unwrap_or(false),
                                payload: previous_payload,
                                dek: previous_dek,
                            },
                        );
                    });
                }
                setting.version = next_version;
                setting.updated_at = now_ms;
                if let Some(status) = input.status {
                    setting.status = status;
                }

                size = setting.data_size() as usize;

                let output = UpdateSettingOutput {
                    created_at: setting.created_at,
                    updated_at: setting.updated_at,
                    version: setting.version,
                };
                save_setting(spkv0, setting);
                Ok(output)
            }
            None => Err(format!("NotFound: setting {} not found", spk)),
        }?;

        ns.payload_bytes_total = ns.payload_bytes_total.saturating_add(size as u64);
        Ok(output)
    })
}

pub fn update_setting_info(
    caller: Principal,
    spk: SettingPathKey,
    input: UpdateSettingInfoInput,
    now_ms: u64,
) -> Result<UpdateSettingOutput, String> {
    with_setting_mut(&caller, &spk, |setting| {
        if let Some(status) = input.status {
            setting.status = status;
        }
        if let Some(desc) = input.desc {
            setting.desc = desc;
        }
        if let Some(tags) = input.tags {
            setting.tags = tags;
        }
        setting.updated_at = now_ms;

        Ok(UpdateSettingOutput {
            created_at: setting.created_at,
            updated_at: setting.updated_at,
            version: setting.version,
        })
    })
}
#[cfg(test)]
mod billing_tests {
    use super::*;
    #[test]
    fn refunds_are_bounded_and_never_recreate_deleted_namespaces() {
        let name = "refunds".to_string();
        NAMESPACES_STORE.with_borrow_mut(|store| {
            store.insert(
                name.clone(),
                Namespace {
                    created_at: 1,
                    gas_balance: 50,
                    ..Default::default()
                },
            )
        });
        NamespaceCharge {
            namespace: name.clone(),
            created_at: 1,
            amount: 100,
        }
        .refund(1_000);
        assert_eq!(with(&name, |ns| Ok(ns.gas_balance)).unwrap(), 150);
        NamespaceCharge {
            namespace: name.clone(),
            created_at: 0,
            amount: 100,
        }
        .refund(100);
        assert_eq!(with(&name, |ns| Ok(ns.gas_balance)).unwrap(), 150);
        NAMESPACES_STORE.with_borrow_mut(|store| store.remove(&name));
        NamespaceCharge {
            namespace: name.clone(),
            created_at: 1,
            amount: 100,
        }
        .refund(100);
        assert!(with(&name, |_| Ok(())).is_err());
    }
}
