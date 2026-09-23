use super::*;

#[test]
fn sparse_acl_migration_pages_advance_across_empty_results() {
    for i in 0..12 {
        NAMESPACES_STORE.with_borrow_mut(|store| {
            store.insert(
                format!("scan_{i:02}"),
                Namespace {
                    acl_version: if i == 10 { 0 } else { 1 },
                    ..Default::default()
                },
            )
        });
    }
    let first = ns::migrate_legacy_namespace_acls_page(None, 4);
    assert!(first.items.is_empty());
    assert_eq!(first.next_cursor.as_deref(), Some("scan_03"));
    let second = ns::migrate_legacy_namespace_acls_page(first.next_cursor, 4);
    assert!(second.items.is_empty());
    let third = ns::migrate_legacy_namespace_acls_page(second.next_cursor, 4);
    assert_eq!(third.items, vec!["scan_10"]);
    assert!(third.next_cursor.is_none());
    assert_eq!(
        ns::with(&"scan_10".into(), |ns| Ok(ns.acl_version)).unwrap(),
        1
    );
}

#[test]
fn role_deltas_handle_duplicates_missing_members_and_limits() {
    let manager = Principal::from_slice(&[11, 9]);
    let name = "role_delta".to_string();
    ns::create_namespace(
        CreateNamespaceInput {
            name: name.clone(),
            managers: BTreeSet::from([manager]),
            ..Default::default()
        },
        1,
    )
    .unwrap();
    let users: BTreeSet<_> = (1u32..=4_000)
        .map(|i| Principal::from_slice(&i.to_be_bytes()))
        .collect();
    for chunk in users.iter().copied().collect::<Vec<_>>().chunks(1_000) {
        ns::add_users(name.clone(), &manager, chunk.iter().copied().collect(), 2).unwrap();
    }
    let existing = *users.first().unwrap();
    let missing = Principal::from_slice(&[99, 99]);
    ns::add_users(name.clone(), &manager, BTreeSet::from([existing]), 3).unwrap();
    assert!(ns::add_users(name.clone(), &manager, BTreeSet::from([missing]), 3).is_err());
    ns::remove_users(
        name.clone(),
        &manager,
        BTreeSet::from([existing, missing]),
        4,
    )
    .unwrap();
    let count = ns::with(&name, |ns| Ok(ns.user_count)).unwrap();
    assert_eq!(count, 3_999);
    assert_eq!(
        ns::list_members(&name, &manager, "user", None, 4_000)
            .unwrap()
            .len(),
        count as usize
    );
    assert!(ns::remove_managers(name, &manager, BTreeSet::from([manager]), 5).is_err());
}

#[test]
fn large_payload_updates_and_deletion_preserve_accounting() {
    for size in [256 * 1024, 1024 * 1024] {
        let manager = Principal::from_slice(&[10, 9]);
        let name = format!("payload_{size}");
        ns::create_namespace(
            CreateNamespaceInput {
                name: name.clone(),
                managers: BTreeSet::from([manager]),
                ..Default::default()
            },
            1,
        )
        .unwrap();
        let mut key = SettingPathKey(name.clone(), 0, manager, ByteBuf::from([1]), 0);
        ns::create_setting(
            manager,
            key.clone(),
            CreateSettingInput {
                payload: Some(vec![1; size].into()),
                ..Default::default()
            },
            2,
        )
        .unwrap();
        key.4 = 1;
        ns::update_setting_payload(
            manager,
            key.clone(),
            UpdateSettingPayloadInput {
                payload: Some(vec![2; size].into()),
                ..Default::default()
            },
            3,
        )
        .unwrap();
        assert_eq!(
            ns::get_setting_archived_payload(manager, key.clone())
                .unwrap()
                .payload
                .unwrap(),
            vec![1; size]
        );
        key.4 = 2;
        ns::update_setting_info(
            manager,
            key.clone(),
            UpdateSettingInfoInput {
                desc: Some("metadata only".into()),
                ..Default::default()
            },
            4,
        )
        .unwrap();
        assert_eq!(
            ns::get_setting(manager, key.clone())
                .unwrap()
                .payload
                .unwrap(),
            vec![2; size]
        );
        assert_eq!(
            ns::with(&name, |ns| Ok(ns.payload_bytes_total)).unwrap(),
            (size * 2) as u64
        );
        ns::delete_setting(&manager, &key).unwrap();
        assert_eq!(ns::with(&name, |ns| Ok(ns.payload_bytes_total)).unwrap(), 0);
    }
}

#[test]
fn kek_prefetch_requires_a_namespace_role_or_an_existing_grant() {
    let manager = Principal::from_slice(&[11, 1]);
    let user = Principal::from_slice(&[11, 2]);
    let outsider = Principal::from_slice(&[11, 3]);
    let reader = Principal::from_slice(&[11, 4]);
    let name = "kek_access".to_string();
    ns::create_namespace(
        CreateNamespaceInput {
            name: name.clone(),
            managers: BTreeSet::from([manager]),
            users: BTreeSet::from([user]),
            ..Default::default()
        },
        1,
    )
    .unwrap();
    let mut path = SettingPathKey(name.clone(), 1, outsider, ByteBuf::from([1]), 0);
    assert!(!ns::has_kek_permission(&outsider, &path));
    path.1 = 0;
    assert!(!ns::has_kek_permission(&outsider, &path));
    ns::update_namespace_info(
        &manager,
        UpdateNamespaceInput {
            name: name.clone(),
            visibility: Some(1),
            ..Default::default()
        },
        2,
    )
    .unwrap();
    assert!(!ns::has_kek_permission(&outsider, &path));
    assert!(!ns::has_vetkd_public_key_permission(&outsider, &path));
    ns::update_namespace_info(
        &manager,
        UpdateNamespaceInput {
            name: name.clone(),
            visibility: Some(0),
            ..Default::default()
        },
        2,
    )
    .unwrap();
    path.2 = user;
    assert!(ns::has_kek_permission(&user, &path));
    path.2 = outsider;
    let created =
        ns::create_setting(manager, path.clone(), CreateSettingInput::default(), 2).unwrap();
    assert!(ns::has_kek_permission(&outsider, &path));
    path.4 = created.version;
    ns::with_setting_mut(&manager, &path, |setting| {
        setting.readers.insert(reader);
        Ok(())
    })
    .unwrap();
    assert!(ns::has_kek_permission(&reader, &path));
    assert!(ns::has_vetkd_public_key_permission(&reader, &path));
    ns::with_setting_mut(&manager, &path, |setting| {
        setting.readers.remove(&reader);
        Ok(())
    })
    .unwrap();
    assert!(!ns::has_kek_permission(&reader, &path));
    assert!(!ns::has_vetkd_public_key_permission(&reader, &path));
    assert_eq!(ns::with(&name, |ns| Ok(ns.gas_balance)).unwrap(), 0);
}

#[test]
fn identity_tokens_never_mislabel_bip340_as_es256k() {
    assert_eq!(
        identity_cose_algorithm(SchnorrAlgorithm::Ed25519),
        Ok(EdDSA)
    );
    assert!(identity_cose_algorithm(SchnorrAlgorithm::Bip340secp256k1)
        .unwrap_err()
        .contains("ES256K"));
}

#[test]
fn test_stable_cbor_round_trip_handles_principals_and_payloads() {
    let principal = Principal::from_slice(&[1, 2, 3, 4]);
    let setting = Setting {
        desc: "round_trip".to_string(),
        readers: BTreeSet::from([principal]),
        payload: Some(ByteBuf::from(vec![7; 1024])),
        dek: Some(ByteBuf::from(vec![8; 32])),
        version: 3,
        ..Default::default()
    };
    let decoded = Setting::from_bytes(Cow::Owned(setting.clone().into_bytes()));
    assert_eq!(decoded.desc, setting.desc);
    assert_eq!(decoded.readers, setting.readers);
    assert_eq!(decoded.payload, setting.payload);
    assert_eq!(decoded.dek, setting.dek);
    assert_eq!(decoded.version, setting.version);

    let key = SettingPathKey(
        "round_trip".to_string(),
        1,
        principal,
        ByteBuf::from(vec![9; 64]),
        3,
    );
    assert_eq!(
        SettingPathKey::from_bytes(Cow::Owned(key.clone().into_bytes())),
        key
    );

    let namespace = Namespace {
        desc: "namespace".to_string(),
        managers: BTreeSet::from([principal]),
        fixed_id_names: BTreeMap::from([("fixed".to_string(), BTreeSet::from([principal]))]),
        ..Default::default()
    };
    let decoded = Namespace::from_bytes(Cow::Owned(namespace.clone().into_bytes()));
    assert_eq!(decoded.desc, namespace.desc);
    assert_eq!(decoded.managers, namespace.managers);
    assert_eq!(decoded.fixed_id_names, namespace.fixed_id_names);

    let state = State {
        managers: BTreeSet::from([principal]),
        ecdsa_public_key: Some(PublicKeyOutput {
            public_key: ByteBuf::from([1; 33]),
            chain_code: ByteBuf::from([2; 32]),
        }),
        init_vector: [3; 32].into(),
        ..Default::default()
    };
    let encoded = to_cbor_bytes(&state, 256, "State data");
    let decoded: State = from_cbor_bytes(&encoded, "State data");
    assert_eq!(decoded.managers, state.managers);
    assert_eq!(decoded.ecdsa_public_key, state.ecdsa_public_key);
    assert_eq!(decoded.init_vector, state.init_vector);

    let legacy_key = (principal, ByteBuf::from([4]));
    let legacy = BTreeMap::from([(
        "legacy".to_string(),
        NamespaceLegacy {
            managers: BTreeSet::from([principal]),
            settings: BTreeMap::from([(legacy_key.clone(), setting)]),
            ..Default::default()
        },
    )]);
    let encoded = to_cbor_bytes(&legacy, 1024, "legacy namespace data");
    let decoded: BTreeMap<String, NamespaceLegacy> =
        from_cbor_bytes(&encoded, "legacy namespace data");
    let decoded = decoded.get("legacy").unwrap();
    assert!(decoded.managers.contains(&principal));
    assert!(decoded.settings.contains_key(&legacy_key));
}

#[test]
fn test_derivation_path_limit_is_checked_before_storage_access() {
    let namespace = "missing_namespace".to_string();
    let err = ns::ecdsa_public_key(
        &Principal::anonymous(),
        namespace.clone(),
        vec![ByteBuf::new(); 254],
    )
    .unwrap_err();
    assert_eq!(err, "derivation path length exceeds the limit 253");

    let err = ns::ecdsa_public_key(
        &Principal::anonymous(),
        namespace,
        vec![ByteBuf::new(); 253],
    )
    .unwrap_err();
    assert!(err.starts_with("NotFound:"));
}

#[test]
fn test_list_setting_keys_includes_management_principal() {
    let namespace = "management_subject".to_string();
    let principal = Principal::management_canister();
    let key = ByteBuf::from([1]);
    let max_key = ByteBuf::from([255u8; 64].as_ref());
    SETTINGS_STORE.with_borrow_mut(|store| {
        store.insert(
            SettingPathKey(namespace.clone(), 0, principal, key.clone(), 0),
            Setting::default(),
        );
        store.insert(
            SettingPathKey(namespace.clone(), 0, principal, max_key.clone(), 0),
            Setting::default(),
        );
    });

    assert_eq!(
        ns::list_setting_keys(&namespace, false, None),
        vec![(principal, key), (principal, max_key.clone())]
    );
    assert_eq!(
        ns::list_setting_keys(&namespace, false, Some(principal)),
        vec![(principal, ByteBuf::from([1])), (principal, max_key)]
    );
}

#[test]
fn test_payload_update_preserves_current_and_archived_versions() {
    let namespace = "payload_update".to_string();
    let manager = Principal::from_slice(&[9, 9, 9]);
    let current_key = SettingPathKey(namespace.clone(), 0, manager, ByteBuf::from([1]), 0);
    let versioned_key = SettingPathKey(namespace.clone(), 0, manager, ByteBuf::from([1]), 1);
    let old_payload = ByteBuf::from(vec![1; 128]);
    let new_payload = ByteBuf::from(vec![2; 256]);

    NAMESPACES_STORE.with_borrow_mut(|store| {
        store.insert(
            namespace.clone(),
            Namespace {
                managers: BTreeSet::from([manager]),
                max_payload_size: 1024,
                payload_bytes_total: old_payload.len() as u64,
                ..Default::default()
            },
        );
    });
    SETTINGS_STORE.with_borrow_mut(|store| {
        store.insert(
            current_key.clone(),
            Setting {
                payload: Some(old_payload.clone()),
                version: 1,
                ..Default::default()
            },
        );
    });

    let output = ns::update_setting_payload(
        manager,
        versioned_key.clone(),
        UpdateSettingPayloadInput {
            payload: Some(new_payload.clone()),
            ..Default::default()
        },
        42,
    )
    .unwrap();
    assert_eq!(output.version, 2);

    let current = SETTING_META_STORE.with_borrow(|store| {
        let meta = store.get(&current_key).unwrap();
        let data = SETTING_DATA_STORE.with_borrow(|data| data.get(&current_key));
        meta.into_setting(data)
    });
    assert!(SETTINGS_STORE.with_borrow(|store| store.get(&current_key).is_none()));
    assert_eq!(current.payload, Some(new_payload));
    assert_eq!(current.version, 2);
    let archived = PAYLOADS_STORE.with_borrow(|store| store.get(&versioned_key).unwrap());
    assert_eq!(archived.payload, Some(old_payload));
    assert_eq!(
        NAMESPACES_STORE.with_borrow(|store| store.get(&namespace).unwrap().payload_bytes_total),
        384
    );

    let delete_key = SettingPathKey(
        namespace.clone(),
        0,
        manager,
        ByteBuf::from([1]),
        output.version,
    );
    ns::delete_setting(&manager, &delete_key).unwrap();
    assert_eq!(
        NAMESPACES_STORE.with_borrow(|store| store.get(&namespace).unwrap().payload_bytes_total),
        0
    );
}

#[test]
fn test_payload_update_rejects_malformed_dek_before_writing() {
    let namespace = "invalid_dek".to_string();
    let manager = Principal::from_slice(&[8, 8, 8]);
    let current_key = SettingPathKey(namespace.clone(), 0, manager, ByteBuf::from([1]), 0);
    let versioned_key = SettingPathKey(namespace.clone(), 0, manager, ByteBuf::from([1]), 1);
    let payload = ByteBuf::from(vec![1; 16]);

    NAMESPACES_STORE.with_borrow_mut(|store| {
        store.insert(
            namespace,
            Namespace {
                managers: BTreeSet::from([manager]),
                max_payload_size: 1024,
                ..Default::default()
            },
        );
    });
    SETTINGS_STORE.with_borrow_mut(|store| {
        store.insert(
            current_key.clone(),
            Setting {
                payload: Some(payload.clone()),
                version: 1,
                ..Default::default()
            },
        );
    });

    assert!(ns::update_setting_payload(
        manager,
        versioned_key.clone(),
        UpdateSettingPayloadInput {
            dek: Some(ByteBuf::from([0xff])),
            ..Default::default()
        },
        42,
    )
    .is_err());

    let current = SETTINGS_STORE.with_borrow(|store| store.get(&current_key).unwrap());
    assert_eq!(current.payload, Some(payload));
    assert_eq!(current.version, 1);
    assert!(PAYLOADS_STORE.with_borrow(|store| store.get(&versioned_key).is_none()));
}

#[test]
fn archived_settings_require_an_explicit_metadata_recovery_before_payload_writes() {
    let namespace = "archived_setting".to_string();
    let manager = Principal::from_slice(&[8, 7, 6]);
    let current_key = SettingPathKey(namespace.clone(), 0, manager, ByteBuf::from([2]), 0);
    let versioned_key = SettingPathKey(namespace.clone(), 0, manager, ByteBuf::from([2]), 1);
    NAMESPACES_STORE.with_borrow_mut(|store| {
        store.insert(
            namespace,
            Namespace {
                managers: BTreeSet::from([manager]),
                max_payload_size: 1024,
                ..Default::default()
            },
        );
    });
    SETTINGS_STORE.with_borrow_mut(|store| {
        store.insert(
            current_key,
            Setting {
                status: -1,
                version: 1,
                payload: Some(ByteBuf::from([1])),
                ..Default::default()
            },
        );
    });

    assert_eq!(
        ns::update_setting_payload(
            manager,
            versioned_key.clone(),
            UpdateSettingPayloadInput {
                payload: Some(ByteBuf::from([2])),
                ..Default::default()
            },
            2,
        )
        .unwrap_err(),
        "setting is not writable"
    );
    ns::update_setting_info(
        manager,
        versioned_key.clone(),
        UpdateSettingInfoInput {
            status: Some(0),
            ..Default::default()
        },
        3,
    )
    .unwrap();
    assert!(ns::update_setting_payload(
        manager,
        versioned_key,
        UpdateSettingPayloadInput {
            payload: Some(ByteBuf::from([2])),
            ..Default::default()
        },
        4,
    )
    .is_ok());
}

#[test]
fn test_delete_namespace_only_looks_at_its_own_settings() {
    let manager = Principal::from_slice(&[1, 1, 1, 1]);
    NAMESPACES_STORE.with_borrow_mut(|r| {
        for name in ["alpha", "beta"] {
            r.insert(
                name.to_string(),
                Namespace {
                    managers: BTreeSet::from([manager]),
                    ..Default::default()
                },
            );
        }
    });
    // only "beta" holds settings; "alpha" is empty and must stay deletable
    SETTINGS_STORE.with_borrow_mut(|r| {
        r.insert(
            SettingPathKey("beta".to_string(), 0, manager, ByteBuf::from([1]), 0),
            Setting::default(),
        );
    });

    assert_eq!(ns::delete_namespace(&manager, "alpha".to_string()), Ok(()));
    assert_eq!(
        ns::delete_namespace(&manager, "beta".to_string()),
        Err("namespace beta is not empty".to_string())
    );

    // a setting owned by the smallest possible principal still counts
    SETTINGS_STORE.with_borrow_mut(|r| {
        r.insert(
            SettingPathKey(
                "gamma".to_string(),
                0,
                Principal::management_canister(),
                ByteBuf::new(),
                0,
            ),
            Setting::default(),
        );
    });
    NAMESPACES_STORE.with_borrow_mut(|r| {
        r.insert(
            "gamma".to_string(),
            Namespace {
                managers: BTreeSet::from([manager]),
                ..Default::default()
            },
        );
    });
    assert_eq!(
        ns::delete_namespace(&manager, "gamma".to_string()),
        Err("namespace gamma is not empty".to_string())
    );
}

#[test]
fn test_list_setting_keys() {
    let n1 = "namespace1".to_string();
    let n2 = "namespace2".to_string();
    let p0 = Principal::anonymous();
    let p1 = Principal::from_slice(&[1, 1, 1, 1]);
    let p2 = Principal::from_slice(&[1, 1, 1, 1, 1]);
    let p3 = Principal::from_slice(&[1, 1, 1, 1, 2]);
    assert!(p0 > Principal::management_canister());
    assert!(p0 < p1);
    assert!(p1 < p2);
    assert!(p2 < p3);

    SETTINGS_STORE.with_borrow_mut(|r| {
        for (i, n) in [n1.clone(), n2.clone()].iter().enumerate() {
            for p in &[p0, p1, p2, p3] {
                r.insert(
                    SettingPathKey(n.clone(), 0, *p, ByteBuf::from([i as u8]), 0),
                    Setting::default(),
                );
                r.insert(
                    SettingPathKey(n.clone(), 0, *p, ByteBuf::from(p.as_slice()), 0),
                    Setting::default(),
                );
                r.insert(
                    SettingPathKey(n.clone(), 1, *p, ByteBuf::from([i as u8 + 1]), 0),
                    Setting::default(),
                );
                r.insert(
                    SettingPathKey(n.clone(), 1, *p, ByteBuf::from(p.as_slice()), 0),
                    Setting::default(),
                );
                r.insert(
                    SettingPathKey(n.clone(), 2, *p, ByteBuf::from([0]), 0),
                    Setting::default(),
                );
            }
        }
    });

    {
        let keys = ns::list_setting_keys(&n1, false, None);
        assert_eq!(
            keys,
            vec![
                (p0, ByteBuf::from([0])),
                (p0, ByteBuf::from(p0.as_slice())),
                (p1, ByteBuf::from([0])),
                (p1, ByteBuf::from(p1.as_slice())),
                (p2, ByteBuf::from([0])),
                (p2, ByteBuf::from(p2.as_slice())),
                (p3, ByteBuf::from([0])),
                (p3, ByteBuf::from(p3.as_slice())),
            ]
        );
        let keys = ns::list_setting_keys(&n1, true, None);
        assert_eq!(
            keys,
            vec![
                (p0, ByteBuf::from([1])),
                (p0, ByteBuf::from(p0.as_slice())),
                (p1, ByteBuf::from([1])),
                (p1, ByteBuf::from(p1.as_slice())),
                (p2, ByteBuf::from([1])),
                (p2, ByteBuf::from(p2.as_slice())),
                (p3, ByteBuf::from([1])),
                (p3, ByteBuf::from(p3.as_slice())),
            ]
        );
        let keys = ns::list_setting_keys(&n1, false, Some(p1));
        assert_eq!(
            keys,
            vec![(p1, ByteBuf::from([0])), (p1, ByteBuf::from(p1.as_slice())),]
        );
        let keys = ns::list_setting_keys(&n1, true, Some(p2));
        assert_eq!(
            keys,
            vec![(p2, ByteBuf::from([1])), (p2, ByteBuf::from(p2.as_slice())),]
        );
    }

    {
        let keys = ns::list_setting_keys(&n2, false, None);
        assert_eq!(
            keys,
            vec![
                (p0, ByteBuf::from([1])),
                (p0, ByteBuf::from(p0.as_slice())),
                (p1, ByteBuf::from([1])),
                (p1, ByteBuf::from(p1.as_slice())),
                (p2, ByteBuf::from([1])),
                (p2, ByteBuf::from(p2.as_slice())),
                (p3, ByteBuf::from([1])),
                (p3, ByteBuf::from(p3.as_slice())),
            ]
        );
        let keys = ns::list_setting_keys(&n2, true, None);
        assert_eq!(
            keys,
            vec![
                (p0, ByteBuf::from([2])),
                (p0, ByteBuf::from(p0.as_slice())),
                (p1, ByteBuf::from(p1.as_slice())),
                (p1, ByteBuf::from([2])),
                (p2, ByteBuf::from(p2.as_slice())),
                (p2, ByteBuf::from([2])),
                (p3, ByteBuf::from(p3.as_slice())),
                (p3, ByteBuf::from([2])),
            ]
        );
        let keys = ns::list_setting_keys(&n2, false, Some(p1));
        assert_eq!(
            keys,
            vec![(p1, ByteBuf::from([1])), (p1, ByteBuf::from(p1.as_slice())),]
        );
        let keys = ns::list_setting_keys(&n2, true, Some(p2));
        assert_eq!(
            keys,
            vec![(p2, ByteBuf::from(p2.as_slice())), (p2, ByteBuf::from([2]))]
        );
    }
}

#[test]
fn administrative_state_remains_recoverable_and_cycles_are_debited_atomically() {
    let manager = Principal::from_slice(&[7, 7, 1]);
    let namespace = "recoverable_namespace".to_string();
    let info = ns::create_namespace(
        CreateNamespaceInput {
            name: namespace.clone(),
            visibility: 0,
            managers: BTreeSet::from([manager]),
            ..Default::default()
        },
        1,
    )
    .unwrap();
    assert_eq!(info.name, namespace);
    assert!(ns::is_member(&namespace, &manager, "manager", &manager).unwrap());
    let stored = NAMESPACES_STORE.with_borrow(|store| store.get(&namespace).unwrap());
    assert_eq!(stored.acl_version, 1);
    assert!(stored.managers.is_empty());
    assert!(
        ns::remove_managers(namespace.clone(), &manager, BTreeSet::from([manager]), 2,)
            .unwrap_err()
            .contains("at least one")
    );

    let second = Principal::from_slice(&[7, 7, 2]);
    ns::add_managers(namespace.clone(), &manager, BTreeSet::from([second]), 2).unwrap();
    ns::remove_managers(namespace.clone(), &manager, BTreeSet::from([manager]), 2).unwrap();
    assert!(ns::is_member(&namespace, &second, "manager", &second).unwrap());
    assert_eq!(
        ns::list_members(&namespace, &second, "manager", None, 10).unwrap(),
        vec![second]
    );
    assert!(
        ns::list_members(&namespace, &second, "manager", Some(second), 10)
            .unwrap()
            .is_empty()
    );

    ns::mutate_delegators(
        namespace.clone(),
        "alpha".to_string(),
        &second,
        BTreeSet::from([manager]),
        true,
        2,
    )
    .unwrap();
    ns::mutate_delegators(
        namespace.clone(),
        "beta".to_string(),
        &second,
        BTreeSet::from([manager]),
        true,
        2,
    )
    .unwrap();
    assert_eq!(
        ns::list_fixed_identity_names(&namespace, &second, None, 1).unwrap(),
        vec!["alpha".to_string()]
    );
    assert_eq!(
        ns::list_fixed_identity_names(&namespace, &second, Some("alpha".to_string()), 10,).unwrap(),
        vec!["beta".to_string()]
    );

    ns::update_namespace_info(
        &second,
        UpdateNamespaceInput {
            name: namespace.clone(),
            status: Some(1),
            ..Default::default()
        },
        2,
    )
    .unwrap();
    ns::update_namespace_info(
        &second,
        UpdateNamespaceInput {
            name: namespace.clone(),
            status: Some(0),
            ..Default::default()
        },
        3,
    )
    .unwrap();

    let mut account = Namespace {
        gas_balance: 100,
        ..Default::default()
    };
    assert!(ns::debit_namespace_cycles(&mut account, 40, 1_000, 100).is_ok());
    assert_eq!(account.gas_balance, 60);
    assert!(ns::debit_namespace_cycles(&mut account, 70, 1_000, 100)
        .unwrap_err()
        .contains("namespace gas"));
    assert_eq!(account.gas_balance, 60);
    assert!(ns::debit_namespace_cycles(&mut account, 10, 50, 100)
        .unwrap_err()
        .contains("liquid cycles"));
    assert_eq!(account.gas_balance, 60);
}

#[test]
fn failed_legacy_mutations_do_not_partially_externalize_the_acl() {
    let namespace = "failed_legacy_acl".to_string();
    let manager = Principal::from_slice(&[7, 8, 9]);
    NAMESPACES_STORE.with_borrow_mut(|store| {
        store.insert(
            namespace.clone(),
            Namespace {
                managers: BTreeSet::from([manager]),
                ..Default::default()
            },
        );
    });

    assert_eq!(
        ns::with_mut(namespace.clone(), |_namespace| Err::<(), _>(
            "denied".to_string()
        )),
        Err("denied".to_string())
    );
    let stored = NAMESPACES_STORE.with_borrow(|store| store.get(&namespace).unwrap());
    assert_eq!(stored.acl_version, 0);
    assert!(stored.managers.contains(&manager));
    assert!(!ACL_STORE
        .with_borrow(|store| { store.contains_key(&AclKey(namespace, ROLE_MANAGER, manager)) }));
}

#[test]
fn namespace_summaries_keep_counts_but_never_embed_legacy_members() {
    let principal = Principal::from_slice(&[6, 6, 6]);
    let anonymous = Principal::anonymous();
    let legacy = Namespace {
        managers: BTreeSet::from([principal, anonymous]),
        auditors: BTreeSet::from([principal, anonymous]),
        users: BTreeSet::from([principal, anonymous]),
        fixed_id_names: BTreeMap::from([(
            "identity".to_string(),
            BTreeSet::from([principal, anonymous]),
        )]),
        ..Default::default()
    };
    assert!(!legacy.can_read_namespace("large_legacy", &anonymous));
    let detailed = ns::namespace_info("large_legacy".to_string(), legacy.clone());
    assert!(!detailed.managers.contains(&anonymous));
    assert!(!detailed.auditors.contains(&anonymous));
    assert!(!detailed.users.contains(&anonymous));
    assert!(!detailed.fixed_id_names["identity"].contains(&anonymous));
    let info = ns::namespace_summary("large_legacy".to_string(), legacy);
    assert_eq!(info.manager_count, 1);
    assert_eq!(info.auditor_count, 1);
    assert_eq!(info.user_count, 1);
    assert_eq!(info.fixed_delegator_count, 1);
    assert!(info.managers.is_empty());
    assert!(info.auditors.is_empty());
    assert!(info.users.is_empty());
    assert!(info.fixed_id_names.is_empty());
}

#[test]
fn legacy_data_is_never_resurrected_without_explicit_migration() {
    let name = "deleted_legacy".to_string();
    STATE_STORE.with_borrow_mut(|store| {
        store.set(to_cbor_bytes(&State::default(), 128, "test state"));
    });
    NSLEGACY_STORE.with_borrow_mut(|store| {
        store.set(to_cbor_bytes(
            &BTreeMap::from([(name.clone(), NamespaceLegacy::default())]),
            256,
            "test legacy",
        ));
    });
    SCHEMA_STORE.with_borrow_mut(|store| {
        store.set(0);
    });

    state::load(false);

    assert!(NAMESPACES_STORE.with_borrow(|store| store.get(&name).is_none()));
    assert!(NSLEGACY_STORE.with_borrow(|store| store.get().is_empty()));
    assert_eq!(
        SCHEMA_STORE.with_borrow(|store| *store.get()),
        CURRENT_SCHEMA_VERSION
    );
}

#[test]
fn explicit_legacy_migration_runs_once() {
    let name = "explicit_legacy".to_string();
    STATE_STORE.with_borrow_mut(|store| {
        store.set(to_cbor_bytes(&State::default(), 128, "test state"));
    });
    NSLEGACY_STORE.with_borrow_mut(|store| {
        store.set(to_cbor_bytes(
            &BTreeMap::from([(name.clone(), NamespaceLegacy::default())]),
            256,
            "test legacy",
        ));
    });
    SCHEMA_STORE.with_borrow_mut(|store| {
        store.set(0);
    });

    state::load(true);
    assert!(NAMESPACES_STORE.with_borrow(|store| store.get(&name).is_some()));
    NAMESPACES_STORE.with_borrow_mut(|store| {
        store.remove(&name);
    });
    state::load(false);
    assert!(NAMESPACES_STORE.with_borrow(|store| store.get(&name).is_none()));
}
