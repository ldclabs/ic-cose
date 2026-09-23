use super::*;

#[test]
fn sparse_request_scans_advance_and_archiving_preserves_id_tombstones() {
    let (_, req) = attempted_reservation("scan_requests");
    let original = REQUEST_STORE.with_borrow_mut(|store| store.remove(&req.request_id).unwrap());
    for i in 0..12u32 {
        let mut request = original.clone();
        request.stage = if i == 10 {
            ProvisionStage::Failed
        } else {
            ProvisionStage::Installed
        };
        request.expires_at = 1;
        request.updated_at = if i == 9 { 1 } else { 100 };
        REQUEST_STORE.with_borrow_mut(|store| store.insert(request_id_of(i), request));
    }
    let first = provision::list_expired_reservations_page(2, None, 4);
    assert!(first.items.is_empty());
    assert_eq!(first.next_cursor, Some(request_id_of(3).into()));
    let second = provision::list_expired_reservations_page(2, first.next_cursor, 4);
    assert!(second.items.is_empty());
    let third = provision::list_expired_reservations_page(2, second.next_cursor, 4);
    assert_eq!(third.items.len(), 1);
    assert_eq!(
        third.items[0].request_id,
        ByteArray::from(request_id_of(10))
    );
    assert!(third.next_cursor.is_none());
    let first = provision::archive_completed_requests_page(2, None, 4);
    assert!(first.items.is_empty());
    let second = provision::archive_completed_requests_page(2, first.next_cursor, 4);
    let third = provision::archive_completed_requests_page(2, second.next_cursor, 4);
    assert_eq!(third.items, vec![ByteArray::from(request_id_of(9))]);
    assert!(third.next_cursor.is_none());
    assert!(provision::get_receipt(&request_id_of(9).into()).is_none());
    assert!(COMPLETED_REQUEST_STORE.with_borrow(|store| store.contains_key(&request_id_of(9))));
    assert!(provision::get_receipt(&request_id_of(10).into()).is_some());
}

#[test]
fn direct_cbor_decode_handles_principals_without_an_intermediate_value_tree() {
    let principal = Principal::from_slice(&[1, 2, 3]);
    let state = State {
        name: "round_trip".to_string(),
        managers: BTreeSet::from([principal]),
        ..Default::default()
    };
    let decoded = State::from_bytes(Cow::Owned(state.into_bytes()));
    assert_eq!(decoded.name, "round_trip");
    assert_eq!(decoded.managers, BTreeSet::from([principal]));

    let wasm = Wasm {
        name: "round_trip".to_string(),
        created_at: 1,
        created_by: principal,
        description: String::new(),
        wasm: ByteBuf::from([0, 97, 115, 109, 1, 0, 0, 0]),
        encoding: WasmEncoding::Raw,
        module_hash: Some(ByteArray::from([3; 32])),
    };
    let decoded = Wasm::from_bytes(Cow::Owned(wasm.into_bytes()));
    assert_eq!(decoded.created_by, principal);
    assert_eq!(decoded.wasm.as_slice(), &[0, 97, 115, 109, 1, 0, 0, 0]);
}

fn log(name: &str) -> DeployLog {
    DeployLog {
        name: name.to_string(),
        deploy_at: 1,
        canister: Principal::management_canister(),
        prev_hash: Default::default(),
        wasm_hash: Default::default(),
        module_hash: None,
        args: ByteBuf::new(),
        args_hash: None,
        args_size: 0,
        error: None,
    }
}

// ----- provisioning -----

use ic_cose_types::types::wasm::{
    InstallRequest, ProvisionSettings, ReserveRequest, MAX_PROVISION_ARGS_BYTES,
};
use serde_bytes::ByteBuf as TestByteBuf;

const GOV: Principal = Principal::management_canister();

fn rid(n: u8) -> ByteArray<32> {
    ByteArray::from([n; 32])
}

fn request_id_of(n: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&n.to_be_bytes());
    id
}

fn seed_template(id: &str) -> TemplateEntry {
    let wasm_bytes = vec![0, 97, 115, 109, 1, 0, 0, 0, 0, 2, 0, id.len() as u8];
    let artifact_hash: ByteArray<32> = sha256(&wasm_bytes).into();
    let module_hash = artifact_hash;
    wasm::add_wasm(
        GOV,
        1,
        AddWasmInput {
            name: "project".to_string(),
            description: "d".to_string(),
            wasm: TestByteBuf::from(wasm_bytes),
            encoding: None,
        },
        None,
        None,
    )
    .unwrap();

    let template = ProvisionTemplate {
        id: id.to_string(),
        wasm_name: "project".to_string(),
        artifact_hash,
        expected_module_hash: module_hash,
        encoding: WasmEncoding::Raw,
        settings: ProvisionSettings {
            controllers: vec![
                Principal::from_slice(&[1, 1]),
                Principal::from_slice(&[2, 2]),
            ],
            ..Default::default()
        },
        subnet: None,
        initial_cycles: 2_000_000_000_000,
        max_init_args_bytes: MAX_PROVISION_ARGS_BYTES,
        pool_size: 2,
    };
    provision::add_template(
        GOV,
        1,
        template,
        &BTreeSet::from([
            Principal::from_slice(&[1, 1]),
            Principal::from_slice(&[2, 2]),
        ]),
    )
    .unwrap();
    TEMPLATE_STORE.with_borrow(|r| r.get(&id.to_string()).unwrap())
}

fn reserve_req(id: &str, entry: &TemplateEntry, n: u8) -> ReserveRequest {
    ReserveRequest {
        request_id: rid(n),
        provision_template_id: id.to_string(),
        provision_template_hash: entry.hash,
        expires_at: 60_000,
    }
}

fn add_pool_canister(id: &str, canister: Principal, now_ms: u64) {
    provision::begin_pool_create(id).unwrap();
    provision::finish_pool_create(id, canister, now_ms).unwrap();
}

#[test]
fn reserve_is_idempotent_and_never_creates_a_canister() {
    let id = "tpl_a";
    let entry = seed_template(id);
    let pooled = Principal::from_slice(&[7, 7, 7]);
    add_pool_canister(id, pooled, 1);

    let req = reserve_req(id, &entry, 1);
    let first = provision::reserve(GOV, 10, &req).unwrap();
    assert_eq!(first.canister, pooled);
    assert_eq!(first.controllers, entry.template.settings.controllers);
    assert_eq!(first.initial_cycles, entry.template.initial_cycles);
    assert_eq!(
        POOL_STORE
            .with_borrow(|store| store.get(&PoolKey(id.to_string(), pooled)).unwrap())
            .created_at,
        1
    );

    // replaying the same request id must always return the same canister
    for _ in 0..100 {
        let again = provision::reserve(GOV, 11, &req).unwrap();
        assert_eq!(again, first);
    }
    // and must not consume more of the pool
    assert_eq!(provision::get_template(id).unwrap().available, 0);
    assert_eq!(provision::get_template(id).unwrap().reserved, 1);

    // a second request finds the pool empty rather than creating anything
    let err = provision::reserve(GOV, 12, &reserve_req(id, &entry, 2)).unwrap_err();
    assert!(err.contains("no available canister"), "{err}");

    // the receipt survives a lost response
    let receipt = provision::get_receipt(&rid(1)).unwrap();
    assert_eq!(receipt.canister, pooled);
    assert_eq!(receipt.stage, ProvisionStage::Reserved);
}

#[test]
fn available_pool_index_rebuilds_old_state_once() {
    let id = "tpl_index";
    let entry = seed_template(id);
    let first = Principal::from_slice(&[7, 8, 1]);
    let second = Principal::from_slice(&[7, 8, 2]);
    add_pool_canister(id, first, 1);
    add_pool_canister(id, second, 2);

    // Simulate state written by a version that only had the stable pool.
    state::with_mut(|s| {
        s.available_pool.remove(id);
    });

    let reserved = provision::reserve(GOV, 10, &reserve_req(id, &entry, 31)).unwrap();
    assert!(reserved.canister == first || reserved.canister == second);
    state::with(|s| {
        let remaining = s.available_pool.get(id).unwrap();
        assert_eq!(remaining.len(), 1);
        assert!(!remaining.contains(&reserved.canister));
    });
}

#[test]
fn reserve_rejects_a_tampered_template_binding() {
    let id = "tpl_b";
    let entry = seed_template(id);
    add_pool_canister(id, Principal::from_slice(&[8, 8]), 1);

    let mut req = reserve_req(id, &entry, 3);
    req.provision_template_hash = ByteArray::from([0u8; 32]);
    assert!(provision::reserve(GOV, 10, &req)
        .unwrap_err()
        .contains("hash mismatch"));

    // binding a used request id to another template is refused
    let ok = reserve_req(id, &entry, 3);
    provision::reserve(GOV, 10, &ok).unwrap();
    let other = seed_template("tpl_b2");
    let mut cross = reserve_req("tpl_b2", &other, 3);
    cross.request_id = rid(3);
    assert!(provision::reserve(GOV, 10, &cross)
        .unwrap_err()
        .contains("different template"));
}

#[test]
fn install_binds_every_parameter_it_was_reserved_with() {
    let id = "tpl_c";
    let entry = seed_template(id);
    add_pool_canister(id, Principal::from_slice(&[9, 9]), 1);
    let reservation = provision::reserve(GOV, 10, &reserve_req(id, &entry, 4)).unwrap();

    let args = TestByteBuf::from(vec![1u8, 2, 3]);
    let base = InstallRequest {
        request_id: rid(4),
        canister: reservation.canister,
        provision_template_id: id.to_string(),
        provision_template_hash: entry.hash,
        expected_module_hash: entry.template.expected_module_hash,
        init_args: args.clone(),
        init_args_hash: sha256(&args).into(),
        provision_spec_hash: ByteArray::from([5u8; 32]),
        expires_at: 60_000,
    };
    assert!(provision::begin_install(GOV, 20, &base).is_ok());

    // paying for one module hash must not deliver another
    let mut wrong_module = base.clone();
    wrong_module.expected_module_hash = ByteArray::from([1u8; 32]);
    assert!(provision::begin_install(GOV, 20, &wrong_module)
        .unwrap_err()
        .contains("expected_module_hash mismatch"));

    let mut wrong_args = base.clone();
    wrong_args.init_args = TestByteBuf::from(vec![9u8]);
    wrong_args.init_args_hash = sha256(&[9u8]).into();
    assert!(provision::begin_install(GOV, 20, &wrong_args)
        .unwrap_err()
        .contains("different init_args"));

    let mut wrong_spec = base.clone();
    wrong_spec.provision_spec_hash = ByteArray::from([6u8; 32]);
    assert!(provision::begin_install(GOV, 20, &wrong_spec)
        .unwrap_err()
        .contains("different provision_spec_hash"));

    let mut wrong_hash = base.clone();
    wrong_hash.init_args_hash = ByteArray::from([0u8; 32]);
    assert!(provision::begin_install(GOV, 20, &wrong_hash)
        .unwrap_err()
        .contains("init_args_hash does not match"));

    let mut wrong_canister = base.clone();
    wrong_canister.canister = Principal::from_slice(&[3, 3]);
    assert!(provision::begin_install(GOV, 20, &wrong_canister)
        .unwrap_err()
        .contains("bound to canister"));

    // an install for a request that was never reserved is refused
    let mut unknown = base.clone();
    unknown.request_id = rid(99);
    assert!(provision::begin_install(GOV, 20, &unknown)
        .unwrap_err()
        .contains("reserve_canister must be called first"));

    // once installed, a replay returns the same receipt instead of reinstalling
    let receipt =
        provision::finish_install(&rid(4), 1, entry.template.expected_module_hash, 30).unwrap();
    assert_eq!(receipt.stage, ProvisionStage::Installed);
    assert_eq!(
        receipt.module_hash,
        Some(entry.template.expected_module_hash)
    );
    match provision::begin_install(GOV, 40, &base).unwrap() {
        provision::InstallPlan::AlreadyInstalled(r) => assert_eq!(*r, receipt),
        _ => panic!("expected an already-installed plan"),
    }
    assert_eq!(provision::get_template(id).unwrap().installed, 1);
}

#[test]
fn release_returns_the_canister_and_retires_the_request_id() {
    let id = "tpl_d";
    let entry = seed_template(id);
    let pooled = Principal::from_slice(&[4, 4]);
    add_pool_canister(id, pooled, 1);
    provision::reserve(GOV, 10, &reserve_req(id, &entry, 5)).unwrap();

    assert_eq!(
        provision::expected_controllers(GOV, &rid(5)).unwrap(),
        entry.template.settings.controllers
    );

    let receipt = provision::release(GOV, 20, &rid(5), pooled).unwrap();
    assert_eq!(receipt.canister, pooled);
    let info = provision::get_template(id).unwrap();
    assert_eq!(info.available, 1);
    assert_eq!(info.reserved, 0);
    assert_eq!(info.tombstones, 1);

    // releasing twice is idempotent, and the id can never be reused
    assert_eq!(
        provision::release(GOV, 21, &rid(5), pooled).unwrap(),
        receipt
    );
    assert!(provision::reserve(GOV, 22, &reserve_req(id, &entry, 5))
        .unwrap_err()
        .contains("released"));

    // an installed request may not be released
    provision::reserve(GOV, 23, &reserve_req(id, &entry, 6)).unwrap();
    let install = InstallRequest {
        request_id: rid(6),
        canister: pooled,
        provision_template_id: id.to_string(),
        provision_template_hash: entry.hash,
        expected_module_hash: entry.template.expected_module_hash,
        init_args: TestByteBuf::from([1]),
        init_args_hash: sha256(&[1]).into(),
        provision_spec_hash: rid(61),
        expires_at: 60_000,
    };
    provision::begin_install(GOV, 24, &install).unwrap();
    provision::finish_install(&rid(6), 1, entry.template.expected_module_hash, 24).unwrap();
    assert!(provision::release(GOV, 25, &rid(6), pooled)
        .unwrap_err()
        .contains("installed request cannot be released"));
}

#[test]
fn release_tombstones_expire_after_the_ttl() {
    let id = "tpl_e";
    let entry = seed_template(id);
    let pooled = Principal::from_slice(&[5, 5]);
    add_pool_canister(id, pooled, 1);
    provision::reserve(GOV, 10, &reserve_req(id, &entry, 7)).unwrap();
    provision::release(GOV, 20, &rid(7), pooled).unwrap();
    assert!(provision::get_receipt(&rid(7)).is_some());

    // a later release past the TTL prunes the older tombstone and its record
    provision::reserve(GOV, 30, &reserve_req(id, &entry, 8)).unwrap();
    let late = 20 + provision::RELEASE_TOMBSTONE_TTL_MS + 1;
    provision::release(GOV, late, &rid(8), pooled).unwrap();
    assert!(provision::get_receipt(&rid(7)).is_none());
    assert_eq!(provision::get_template(id).unwrap().tombstones, 1);
}

#[test]
fn release_refuses_a_request_whose_install_is_in_flight() {
    let id = "tpl_i";
    let entry = seed_template(id);
    let pooled = Principal::from_slice(&[3, 1]);
    add_pool_canister(id, pooled, 1);
    provision::reserve(GOV, 10, &reserve_req(id, &entry, 30)).unwrap();

    let args = TestByteBuf::from(vec![1u8]);
    let install = InstallRequest {
        request_id: rid(30),
        canister: pooled,
        provision_template_id: id.to_string(),
        provision_template_hash: entry.hash,
        expected_module_hash: entry.template.expected_module_hash,
        init_args: args.clone(),
        init_args_hash: sha256(&args).into(),
        provision_spec_hash: ByteArray::from([1u8; 32]),
        expires_at: 60_000,
    };
    provision::begin_install(GOV, 20, &install).unwrap();

    // the canister may already be receiving code, so it must not go back
    // into the pool as Available
    assert!(provision::release(GOV, 30, &rid(30), pooled)
        .unwrap_err()
        .contains("install is in flight"));
    assert_eq!(provision::get_template(id).unwrap().available, 0);
}

#[test]
fn tombstone_pruning_evicts_only_what_is_over_the_limit() {
    let id = "tpl_j";
    let entry = seed_template(id);
    let pooled = Principal::from_slice(&[3, 2]);
    add_pool_canister(id, pooled, 1);

    // fill the ring past its bound, reusing the single pooled canister
    let total = provision::MAX_RELEASE_TOMBSTONES + 3;
    for n in 0..total {
        let mut req = reserve_req(id, &entry, 0);
        req.request_id = ByteArray::from(request_id_of(n + 1));
        provision::reserve(GOV, 10, &req).unwrap();
        provision::release(GOV, 10 + n as u64, &req.request_id, pooled).unwrap();
    }

    // one release over the bound must evict one tombstone, not a whole batch
    let info = provision::get_template(id).unwrap();
    assert_eq!(info.tombstones, provision::MAX_RELEASE_TOMBSTONES);
    // the newest ids are still rejectable
    assert!(provision::get_receipt(&ByteArray::from(request_id_of(total))).is_some());
    // and the three oldest were the ones dropped
    for n in 0..3 {
        assert!(provision::get_receipt(&ByteArray::from(request_id_of(n + 1))).is_none());
    }
}

#[test]
fn upgrades_are_limited_to_canisters_this_canister_deployed() {
    let stranger = Principal::from_slice(&[4, 1]);
    assert!(
        provision::assert_upgradable(stranger, "project", Default::default())
            .unwrap_err()
            .contains("was not deployed by this canister")
    );

    let mine = Principal::from_slice(&[4, 2]);
    let module_hash = ByteArray::from([4u8; 32]);
    let log_id = wasm::add_log(DeployLog {
        name: "project".to_string(),
        deploy_at: 1,
        canister: mine,
        prev_hash: Default::default(),
        wasm_hash: Default::default(),
        module_hash: Some(module_hash),
        args: TestByteBuf::new(),
        args_hash: Some(ByteArray::from(sha256(&[]))),
        args_size: 0,
        error: None,
    })
    .unwrap();
    state::record_deployment(
        mine,
        DeploymentIndex {
            log_id,
            artifact_hash: Default::default(),
            module_hash,
            wasm_name: "project".to_string(),
        },
    );

    assert!(provision::assert_upgradable(mine, "project", module_hash).is_ok());
    // and never across wasm families
    assert!(provision::assert_upgradable(mine, "other", module_hash)
        .unwrap_err()
        .contains("runs wasm project"));
}

#[test]
fn completed_deployment_replays_before_rechecking_the_old_module_index() {
    let request_id = rid(91);
    let canister = Principal::from_slice(&[4, 3]);
    let previous = rid(92);
    let installed = rid(93);
    let artifact = rid(94);
    let args_hash = rid(95);
    REQUEST_STORE.with_borrow_mut(|store| {
        store.insert(
            *request_id,
            ProvisionRequest {
                stage: ProvisionStage::Installed,
                owner: GOV,
                expires_at: 1_000,
                attempt: 1,
                canister,
                wasm_name: "project".to_string(),
                template_id: None,
                template_hash: None,
                artifact_hash: artifact,
                expected_module_hash: installed,
                module_hash: Some(installed),
                prev_module_hash: Some(previous),
                args_hash: Some(args_hash),
                args_size: 0,
                provision_spec_hash: None,
                error: None,
                created_at: 1,
                updated_at: 2,
            },
        );
    });
    state::record_deployment(
        canister,
        DeploymentIndex {
            log_id: 0,
            artifact_hash: artifact,
            module_hash: installed,
            wasm_name: "project".to_string(),
        },
    );

    assert!(matches!(
        provision::begin_deployment(
            GOV,
            3,
            &request_id,
            canister,
            "project",
            artifact,
            installed,
            previous,
            args_hash,
            0,
            1_000,
        )
        .unwrap(),
        provision::DeploymentPlan::AlreadyInstalled(_)
    ));
    assert!(provision::begin_deployment(
        GOV,
        3,
        &request_id,
        canister,
        "other",
        artifact,
        installed,
        previous,
        args_hash,
        0,
        1_000,
    )
    .unwrap_err()
    .contains("different parameters"));
}

#[test]
fn staged_chunks_are_bounded_per_uploader() {
    let uploader = Principal::from_slice(&[5, 1]);
    for n in 0..provision::MAX_STAGED_CHUNKS {
        provision::add_chunk(uploader, vec![n as u8; 4]).unwrap();
    }
    assert_eq!(
        provision::staged_chunks(uploader),
        provision::MAX_STAGED_CHUNKS
    );
    assert!(provision::add_chunk(uploader, vec![255u8; 4])
        .unwrap_err()
        .contains("chunks may be staged"));
    // re-staging a chunk already held is not a new allocation
    assert!(provision::add_chunk(uploader, vec![0u8; 4]).is_ok());
    // and the bound is per uploader
    assert!(provision::add_chunk(Principal::from_slice(&[5, 2]), vec![1u8; 4]).is_ok());

    provision::clear_chunks(uploader);
    assert_eq!(provision::staged_chunks(uploader), 0);
}

#[test]
fn pool_create_unknown_circuit_breaks_until_reconciled() {
    let id = "tpl_f";
    seed_template(id);

    provision::begin_pool_create(id).unwrap();
    // only one create may be in flight per template
    assert!(provision::begin_pool_create(id)
        .unwrap_err()
        .contains("already in flight"));

    provision::fail_pool_create(id, true);
    assert_eq!(
        provision::get_template(id).unwrap().pool_status,
        PoolStatus::CreateUnknown
    );
    // an unknown outcome must not be retried into one leaked canister per attempt
    assert!(provision::begin_pool_create(id)
        .unwrap_err()
        .contains("circuit-broken"));

    // governance adopts the canister it located out of band
    let found = Principal::from_slice(&[6, 6]);
    provision::reconcile_pool(id, Some(found), 40).unwrap();
    let info = provision::get_template(id).unwrap();
    assert_eq!(info.pool_status, PoolStatus::Idle);
    assert_eq!(info.available, 1);
    assert!(provision::reconcile_pool(id, None, 41)
        .unwrap_err()
        .contains("nothing to reconcile"));

    // and refill stops at the template's pool size
    provision::begin_pool_create(id).unwrap();
    provision::finish_pool_create(id, Principal::from_slice(&[6, 7]), 42).unwrap();
    assert!(provision::begin_pool_create(id)
        .unwrap_err()
        .contains("already holds"));
}

#[test]
fn request_epochs_bound_replay() {
    assert!(provision::validate_epoch(0, 10)
        .unwrap_err()
        .contains("expired"));
    assert!(provision::validate_epoch(10, 10)
        .unwrap_err()
        .contains("expired"));
    assert!(provision::validate_epoch(11, 10).is_ok());
    let far = 10 + ic_cose_types::types::wasm::MAX_REQUEST_TTL_MS + 1;
    assert!(provision::validate_epoch(far, 10)
        .unwrap_err()
        .contains("in the future"));
}

#[test]
fn templates_pin_an_existing_artifact_and_resist_removal_while_in_use() {
    let id = "tpl_g";
    let entry = seed_template(id);
    assert_eq!(entry.template.hash().unwrap(), entry.hash);
    assert_eq!(entry.template.settings.hash().unwrap(), entry.settings_hash);

    let missing_controller = BTreeSet::from([Principal::from_slice(&[9, 9])]);
    assert!(
        provision::validate_template(&entry.template, &missing_controller)
            .unwrap_err()
            .contains("controllers")
    );

    let mut wrong_module = entry.template.clone();
    wrong_module.id = "tpl_wrong_module".to_string();
    wrong_module.expected_module_hash = rid(77);
    assert!(provision::validate_template(
        &wrong_module,
        &entry
            .template
            .settings
            .controllers
            .iter()
            .copied()
            .collect()
    )
    .unwrap_err()
    .contains("module hash"));

    // a template may not point at bytes this canister does not hold
    let mut missing = entry.template.clone();
    missing.id = "tpl_g2".to_string();
    missing.artifact_hash = ByteArray::from([0u8; 32]);
    assert!(provision::add_template(
        GOV,
        1,
        missing,
        &entry
            .template
            .settings
            .controllers
            .iter()
            .copied()
            .collect()
    )
    .unwrap_err()
    .contains("artifact not found"));

    // nor claim a different wasm name than the artifact it pins
    let mut renamed = entry.template.clone();
    renamed.id = "tpl_g3".to_string();
    renamed.wasm_name = "other".to_string();
    assert!(provision::add_template(
        GOV,
        1,
        renamed,
        &entry
            .template
            .settings
            .controllers
            .iter()
            .copied()
            .collect()
    )
    .unwrap_err()
    .contains("belongs to wasm"));

    assert!(provision::add_template(
        GOV,
        1,
        entry.template.clone(),
        &entry
            .template
            .settings
            .controllers
            .iter()
            .copied()
            .collect()
    )
    .unwrap_err()
    .contains("already exists"));

    add_pool_canister(id, Principal::from_slice(&[1, 9]), 1);
    assert!(provision::remove_template(id)
        .unwrap_err()
        .contains("still owns"));
}

#[test]
fn publishing_a_newer_wasm_does_not_move_an_approved_template() {
    let id = "tpl_h";
    let entry = seed_template(id);
    let pinned = entry.template.artifact_hash;
    add_pool_canister(id, Principal::from_slice(&[1, 4]), 1);
    provision::reserve(GOV, 10, &reserve_req(id, &entry, 20)).unwrap();

    // governance publishes a newer version of the same wasm name
    let newer = vec![0, 97, 115, 109, 1, 0, 0, 0, 0, 2, 0, 7];
    wasm::add_wasm(
        GOV,
        2,
        AddWasmInput {
            name: "project".to_string(),
            description: "newer".to_string(),
            wasm: TestByteBuf::from(newer.clone()),
            encoding: None,
        },
        None,
        None,
    )
    .unwrap();
    let latest = wasm::get_latest("project").unwrap().0;
    assert_ne!(latest, pinned, "latest should have moved");

    // the approved template still resolves the artifact it was approved with
    let info = provision::get_template(id).unwrap();
    assert_eq!(info.template.artifact_hash, pinned);
    assert_eq!(info.hash, entry.hash);

    let args = TestByteBuf::from(vec![1u8]);
    let req = InstallRequest {
        request_id: rid(20),
        canister: Principal::from_slice(&[1, 4]),
        provision_template_id: id.to_string(),
        provision_template_hash: entry.hash,
        expected_module_hash: entry.template.expected_module_hash,
        init_args: args.clone(),
        init_args_hash: sha256(&args).into(),
        provision_spec_hash: ByteArray::from([1u8; 32]),
        expires_at: 60_000,
    };
    match provision::begin_install(GOV, 20, &req).unwrap() {
        provision::InstallPlan::Install { artifact_hash, .. } => {
            assert_eq!(
                artifact_hash, pinned,
                "install must use the pinned artifact"
            );
        }
        other => panic!("unexpected plan: {other:?}"),
    }
}

#[test]
fn chunked_upload_assembles_the_declared_artifact() {
    let uploader = Principal::from_slice(&[2, 9]);
    let a = provision::add_chunk(uploader, vec![1u8; 10]).unwrap();
    let b = provision::add_chunk(uploader, vec![2u8; 10]).unwrap();

    let joined = provision::take_chunks(uploader, &[a, b]).unwrap();
    assert_eq!(joined.len(), 20);
    assert_eq!(&joined[..10], &[1u8; 10]);
    assert_eq!(&joined[10..], &[2u8; 10]);

    // another uploader cannot pick up these chunks
    assert!(provision::take_chunks(Principal::from_slice(&[3, 9]), &[a])
        .unwrap_err()
        .contains("not staged"));
    assert!(provision::add_chunk(uploader, vec![]).is_err());
    assert!(provision::take_chunks(uploader, &[]).is_err());

    assert_eq!(provision::clear_chunks(uploader), 2);
    assert!(provision::take_chunks(uploader, &[a]).is_err());
}

#[test]
fn artifacts_bind_raw_and_gzip_module_hashes_and_support_chunk_reads() {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    let raw = vec![0, 97, 115, 109, 1, 0, 0, 0, 0, 2, 0, 42];
    let raw_hash = wasm::add_wasm(
        GOV,
        1,
        AddWasmInput {
            name: "artifact_raw".to_string(),
            description: "raw".to_string(),
            wasm: TestByteBuf::from(raw.clone()),
            encoding: Some(WasmEncoding::Raw),
        },
        None,
        None,
    )
    .unwrap();
    let metadata = wasm::get_metadata(&raw_hash).unwrap();
    assert_eq!(metadata.module_hash, raw_hash);
    assert_eq!(wasm::get_chunk(&raw_hash, 2, 5).unwrap(), raw[2..7]);
    assert_eq!(wasm::get_wasm(&raw_hash).unwrap().wasm.as_slice(), raw);

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&raw).unwrap();
    let gzip = encoder.finish().unwrap();
    let artifact_hash = wasm::add_wasm(
        GOV,
        2,
        AddWasmInput {
            name: "artifact_gzip".to_string(),
            description: "gzip".to_string(),
            wasm: TestByteBuf::from(gzip.clone()),
            encoding: Some(WasmEncoding::Gzip),
        },
        None,
        None,
    )
    .unwrap();
    let metadata = wasm::get_metadata(&artifact_hash).unwrap();
    assert_eq!(metadata.module_hash, ByteArray::from(sha256(&raw)));
    assert_ne!(artifact_hash, metadata.module_hash);
    assert_eq!(
        wasm::get_chunk(&artifact_hash, 0, gzip.len()).unwrap(),
        gzip
    );
    assert_eq!(
        wasm::next_version_metadata("artifact_raw", Default::default())
            .unwrap()
            .0,
        raw_hash
    );
    assert_eq!(
        wasm::next_version_metadata("artifact_gzip", Default::default())
            .unwrap()
            .0,
        artifact_hash
    );

    assert!(wasm::validate_wasm(
        &AddWasmInput {
            name: "invalid_artifact".to_string(),
            description: String::new(),
            wasm: TestByteBuf::from([1, 2, 3]),
            encoding: Some(WasmEncoding::Raw),
        },
        None,
    )
    .is_err());

    let mut malformed = WASM_HEADER.to_vec();
    malformed.extend_from_slice(&[1, 1, 0xff]);
    assert!(wasm::validate_wasm(
        &AddWasmInput {
            name: "malformed_artifact".to_string(),
            description: String::new(),
            wasm: TestByteBuf::from(malformed),
            encoding: Some(WasmEncoding::Raw),
        },
        None,
    )
    .unwrap_err()
    .contains("invalid WebAssembly"));

    let mut alternate_encoder = GzEncoder::new(Vec::new(), Compression::fast());
    alternate_encoder.write_all(&raw).unwrap();
    let alternate_gzip = alternate_encoder.finish().unwrap();
    assert!(wasm::add_wasm(
        GOV,
        3,
        AddWasmInput {
            name: "artifact_raw".to_string(),
            description: "same module".to_string(),
            wasm: TestByteBuf::from(alternate_gzip),
            encoding: Some(WasmEncoding::Gzip),
        },
        Some(raw_hash),
        None,
    )
    .unwrap_err()
    .contains("same module"));
}

#[test]
fn legacy_artifact_migration_is_incremental_and_lossless() {
    let bytes = vec![0, 97, 115, 109, 1, 0, 0, 0];
    let hash = ByteArray::from(sha256(&bytes));
    WASM_STORE.with_borrow_mut(|store| {
        store.insert(
            *hash,
            Wasm {
                name: "legacy_artifact".to_string(),
                created_at: 1,
                created_by: GOV,
                description: String::new(),
                wasm: ByteBuf::from(bytes.clone()),
                encoding: WasmEncoding::Raw,
                module_hash: None,
            },
        );
    });
    assert_eq!(wasm::list_legacy_artifacts(None, 10), vec![hash]);
    assert!(wasm::migrate_legacy_artifact(&hash).unwrap());
    assert!(wasm::list_legacy_artifacts(None, 10).is_empty());
    assert_eq!(wasm::get_wasm(&hash).unwrap().wasm.as_slice(), bytes);
    assert!(!wasm::migrate_legacy_artifact(&hash).unwrap());
}

#[test]
fn install_attempts_bind_owner_expiration_and_serialize_per_target() {
    let id = "tpl_attempt";
    let entry = seed_template(id);
    let pooled = Principal::from_slice(&[4, 8]);
    add_pool_canister(id, pooled, 1);
    let reserve = reserve_req(id, &entry, 88);
    provision::reserve(GOV, 10, &reserve).unwrap();

    let mut changed_expiration = reserve.clone();
    changed_expiration.expires_at += 1;
    assert!(provision::reserve(GOV, 11, &changed_expiration)
        .unwrap_err()
        .contains("expiration"));
    assert!(
        provision::reserve(Principal::from_slice(&[9, 8]), 11, &reserve)
            .unwrap_err()
            .contains("another provisioner")
    );

    let args = TestByteBuf::from([1]);
    let install = InstallRequest {
        request_id: reserve.request_id,
        canister: pooled,
        provision_template_id: id.to_string(),
        provision_template_hash: entry.hash,
        expected_module_hash: entry.template.expected_module_hash,
        init_args: args.clone(),
        init_args_hash: sha256(&args).into(),
        provision_spec_hash: rid(89),
        expires_at: reserve.expires_at,
    };
    let first = provision::begin_install(GOV, 20, &install).unwrap();
    assert!(matches!(
        first,
        provision::InstallPlan::Install { attempt: 1, .. }
    ));
    assert!(provision::begin_install(GOV, 21, &install)
        .unwrap_err()
        .contains("already in flight"));
    assert!(state::acquire_operation(pooled, rid(90), 99, u64::MAX)
        .unwrap_err()
        .contains("already in flight"));

    let receipt = provision::finish_install(
        &install.request_id,
        1,
        entry.template.expected_module_hash,
        22,
    )
    .unwrap();
    provision::fail_install(&install.request_id, 1, "late failure".to_string(), 23);
    let current = provision::get_receipt(&install.request_id).unwrap();
    assert_eq!(current.stage, ProvisionStage::Installed);
    assert_eq!(current.error, None);
    assert_eq!(current, receipt);
    assert_eq!(provision::archive_completed_requests(23, 10), 1);
    assert!(provision::get_receipt(&install.request_id).is_none());
    assert!(provision::reserve(GOV, 24, &reserve)
        .unwrap_err()
        .contains("archived completed"));
}

#[test]
fn historical_module_republication_is_rejected_without_changing_latest() {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    let module = |marker| vec![0, 97, 115, 109, 1, 0, 0, 0, 0, 2, 0, marker];
    let publish = |bytes: Vec<u8>, encoding| {
        wasm::add_wasm(
            GOV,
            1,
            AddWasmInput {
                name: "history".to_string(),
                description: String::new(),
                wasm: bytes.into(),
                encoding: Some(encoding),
            },
            None,
            None,
        )
    };
    publish(module(1), WasmEncoding::Raw).unwrap();
    let latest = publish(module(2), WasmEncoding::Raw).unwrap();
    // Different gzip artifacts can decode to the same old module.
    for compression in [Compression::fast(), Compression::best()] {
        let mut encoder = GzEncoder::new(Vec::new(), compression);
        encoder.write_all(&module(1)).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(publish(compressed, WasmEncoding::Gzip)
            .unwrap_err()
            .contains("release history"));
        assert_eq!(wasm::get_latest_metadata("history").unwrap().0, latest);
    }
    let next = publish(module(3), WasmEncoding::Raw).unwrap();
    assert_eq!(
        wasm::next_version_metadata("history", latest).unwrap().0,
        next
    );
}

#[test]
fn legacy_gzip_without_encoding_survives_upgrade_and_chunk_migration() {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    #[derive(Serialize)]
    struct LegacyWasm {
        name: String,
        created_at: u64,
        created_by: Principal,
        description: String,
        wasm: ByteBuf,
    }
    #[derive(Serialize)]
    struct LegacyState {
        #[serde(flatten)]
        state: State,
        latest_version: BTreeMap<String, ByteArray<32>>,
        upgrade_path: BTreeMap<ByteArray<32>, ByteArray<32>>,
        deployed_list: BTreeMap<Principal, (u64, ByteArray<32>)>,
    }
    let raw = vec![0, 97, 115, 109, 1, 0, 0, 0];
    let raw_hash = ByteArray::from(sha256(&raw));
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&raw).unwrap();
    let compressed = encoder.finish().unwrap();
    let hash = ByteArray::from(sha256(&compressed));
    let bytes = cbor2::to_vec(&LegacyWasm {
        name: "legacy_gzip".to_string(),
        created_at: 1,
        created_by: GOV,
        description: String::new(),
        wasm: compressed.clone().into(),
    })
    .unwrap();
    let legacy = Wasm::from_bytes(Cow::Owned(bytes));
    assert_eq!(legacy.encoding, WasmEncoding::Raw);
    WASM_STORE.with_borrow_mut(|store| store.insert(*hash, legacy));
    let target = Principal::from_slice(&[4, 4]);
    let log_id = wasm::add_log(log("legacy_gzip")).unwrap();
    let legacy_state = cbor2::to_vec(&LegacyState {
        state: State::default(),
        latest_version: BTreeMap::from([("legacy_gzip".to_string(), hash)]),
        upgrade_path: BTreeMap::from([(ByteArray::from([0; 32]), hash)]),
        deployed_list: BTreeMap::from([(target, (log_id, hash))]),
    })
    .unwrap();
    let memory = MEMORY_MANAGER.with_borrow(|m| m.get(STATE_MEMORY_ID));
    StableCell::init(memory, Vec::<u8>::new()).set(legacy_state);
    state::load();
    assert_eq!(state::deployed(&target).unwrap().module_hash, raw_hash);
    assert_eq!(
        wasm::get_metadata(&hash).unwrap().encoding,
        WasmEncoding::Gzip
    );
    assert_eq!(wasm::get_metadata(&hash).unwrap().module_hash, raw_hash);
    assert_eq!(wasm::get_wasm(&hash).unwrap().encoding, WasmEncoding::Gzip);
    assert!(wasm::migrate_legacy_artifact(&hash).unwrap());
    assert_eq!(wasm::get_metadata(&hash).unwrap().module_hash, raw_hash);
    assert_eq!(
        wasm::get_metadata(&hash).unwrap().encoding,
        WasmEncoding::Gzip
    );
    assert_eq!(
        wasm::get_chunk(&hash, 0, compressed.len()).unwrap(),
        compressed
    );
    state::save();
    state::load();
    assert_eq!(state::deployed(&target).unwrap().module_hash, raw_hash);
}

fn attempted_reservation(id: &str) -> (TemplateEntry, InstallRequest) {
    let entry = seed_template(id);
    let target = Principal::from_slice(&[8, 4]);
    add_pool_canister(id, target, 1);
    let reserve = reserve_req(id, &entry, 80);
    provision::reserve(GOV, 2, &reserve).unwrap();
    let args = ByteBuf::from(b"DIDL\0\0".as_slice());
    let install = InstallRequest {
        request_id: reserve.request_id,
        canister: target,
        provision_template_id: id.to_string(),
        provision_template_hash: entry.hash,
        expected_module_hash: entry.template.expected_module_hash,
        init_args_hash: sha256(&args).into(),
        init_args: args,
        provision_spec_hash: rid(81),
        expires_at: reserve.expires_at,
    };
    provision::begin_install(GOV, 3, &install).unwrap();
    (entry, install)
}

#[test]
fn expired_interrupted_install_can_be_reconciled_and_released_without_reinstalling() {
    let (entry, req) = attempted_reservation("recover_empty");
    let now = req.expires_at + 1;
    assert!(provision::begin_reconcile(GOV, false, &req.request_id, now)
        .unwrap_err()
        .contains("already in flight"));
    // A real state save/load clears heap locks but keeps the request attempt.
    state::initialize_schema();
    state::save();
    state::load();
    assert!(provision::validate_epoch(req.expires_at, now).is_err());
    let mut changed = req.clone();
    changed.expires_at = now + 1_000;
    assert!(provision::begin_install(GOV, now, &changed)
        .unwrap_err()
        .contains("expiration"));
    let stranger = Principal::from_slice(&[9, 9]);
    assert!(provision::begin_reconcile(stranger, false, &req.request_id, now).is_err());
    let (target, attempt) =
        provision::begin_reconcile(stranger, true, &req.request_id, now).unwrap();
    assert_eq!(attempt, 2);
    assert!(provision::finish_reconcile(
        &req.request_id,
        1,
        None,
        &entry.template.settings.controllers,
        now
    )
    .is_err());
    let receipt = provision::finish_reconcile(
        &req.request_id,
        attempt,
        None,
        &entry.template.settings.controllers,
        now,
    )
    .unwrap();
    assert_eq!(receipt.stage, ProvisionStage::Failed);
    assert_eq!(receipt.expires_at, req.expires_at);
    assert_eq!(receipt.args_hash, Some(req.init_args_hash));
    provision::release(GOV, now, &req.request_id, target).unwrap();
    assert_eq!(
        provision::get_template("recover_empty").unwrap().available,
        1
    );
}

#[test]
fn reconciliation_commits_installed_module_and_preserves_parameter_commitments() {
    let (entry, req) = attempted_reservation("recover_landed");
    provision::fail_install(&req.request_id, 1, "status query timed out".to_string(), 4);
    let now = req.expires_at + 1;
    let (_, attempt) = provision::begin_reconcile(GOV, false, &req.request_id, now).unwrap();
    assert!(provision::finish_reconcile(
        &req.request_id,
        attempt,
        Some(req.expected_module_hash),
        &[],
        now
    )
    .is_err());
    let receipt = provision::finish_reconcile(
        &req.request_id,
        attempt,
        Some(req.expected_module_hash),
        &entry.template.settings.controllers,
        now,
    )
    .unwrap();
    assert_eq!(receipt.stage, ProvisionStage::Installed);
    assert_eq!(receipt.expires_at, req.expires_at);
    assert_eq!(receipt.provision_spec_hash, Some(req.provision_spec_hash));
    let deployed = state::deployed(&req.canister).unwrap();
    let log = INSTALL_LOGS.with_borrow(|logs| logs.get(deployed.log_id).unwrap());
    assert_eq!(log.args_hash, Some(req.init_args_hash));
    assert_eq!(log.args_size, req.init_args.len() as u64);
    assert!(log.args.is_empty());
    assert!(!state::operation_active(&req.canister));
    provision::fail_install(&req.request_id, 1, "stale callback".to_string(), now);
    assert_eq!(provision::get_receipt(&req.request_id).unwrap(), receipt);
    assert_eq!(
        provision::get_template("recover_landed").unwrap().reserved,
        0
    );
}

#[test]
fn reconciliation_resolves_upgrade_outcomes_without_executing_another_upgrade() {
    let id = "upgrade_recovery";
    let entry = seed_template(id);
    let canister = Principal::from_slice(&[9, 3]);
    let previous = rid(70);
    let args = b"DIDL\0\0";
    state::record_deployment(
        canister,
        DeploymentIndex {
            log_id: 0,
            artifact_hash: previous,
            module_hash: previous,
            wasm_name: "project".to_string(),
        },
    );
    let request_id = rid(71);
    provision::begin_deployment(
        GOV,
        1,
        &request_id,
        canister,
        "project",
        entry.template.artifact_hash,
        entry.template.expected_module_hash,
        previous,
        sha256(args).into(),
        args.len() as u64,
        60_000,
    )
    .unwrap();
    provision::fail_install(&request_id, 1, "probe failed".into(), 2);
    let (_, attempt) = provision::begin_reconcile(GOV, false, &request_id, 60_001).unwrap();
    let receipt =
        provision::finish_reconcile(&request_id, attempt, Some(previous), &[], 60_002).unwrap();
    assert_eq!(receipt.stage, ProvisionStage::Failed);
    assert_eq!(state::deployed(&canister).unwrap().module_hash, previous);
    let (_, attempt) = provision::begin_reconcile(GOV, false, &request_id, 60_003).unwrap();
    provision::fail_install(&request_id, 1, "late failure".into(), 60_004);
    assert!(state::operation_active(&canister));
    assert!(provision::finish_reconcile(&request_id, attempt, Some(rid(72)), &[], 60_005).is_err());
    let receipt = provision::finish_reconcile(
        &request_id,
        attempt,
        Some(entry.template.expected_module_hash),
        &[],
        60_006,
    )
    .unwrap();
    assert_eq!(receipt.stage, ProvisionStage::Installed);
    assert_eq!(receipt.expires_at, 60_000);
    assert_eq!(
        state::deployed(&canister).unwrap().module_hash,
        entry.template.expected_module_hash
    );
}

#[test]
fn explicit_forget_blocks_receipt_repair_across_upgrades_until_controller_adoption() {
    let (_, req) = attempted_reservation("forget_receipt");
    let receipt = provision::commit_install_success(
        &req.request_id,
        1,
        req.expected_module_hash,
        4,
        &req.init_args,
    )
    .unwrap();
    assert!(state::forget_deployment(&req.canister));
    state::initialize_schema();
    state::save();
    state::load();
    assert!(
        provision::repair_installed_receipt(&receipt, &req.init_args, 5)
            .unwrap_err()
            .contains("handed off or forgotten")
    );
    assert!(provision::begin_install(GOV, 5, &req).is_err());
    assert!(state::deployed(&req.canister).is_none());
    // Explicit controller adoption is the only way to lift the barrier.
    state::resume_management(&req.canister);
    provision::repair_installed_receipt(&receipt, &req.init_args, 6).unwrap();
    assert_eq!(
        state::deployed(&req.canister).unwrap().module_hash,
        req.expected_module_hash
    );
}

#[test]
fn deployment_logs_skips_other_names_without_hanging() {
    // interleaved names: the scan must step over "bar" entries instead of
    // spinning on them forever
    for name in ["foo", "bar", "foo", "bar", "bar", "foo"] {
        wasm::add_log(log(name)).unwrap();
    }

    let foo = wasm::deployment_logs("foo", None, 10);
    assert_eq!(foo.len(), 3);
    assert!(foo.iter().all(|d| d.name == "foo"));

    let bar = wasm::deployment_logs("bar", None, 10);
    assert_eq!(bar.len(), 3);

    // the newest "bar" is at index 4, so a cursor of 4 sees only the older two
    assert_eq!(wasm::deployment_logs("bar", Some(4), 10).len(), 2);
    assert_eq!(wasm::deployment_logs("foo", None, 2).len(), 2);
    assert_eq!(wasm::deployment_logs("foo", None, 0).len(), 0);
    assert_eq!(wasm::deployment_logs("none", None, 10).len(), 0);
    assert_eq!(wasm::deployment_logs("foo", Some(0), 10).len(), 0);
    assert_eq!(wasm::deployment_logs("foo", Some(99), 10).len(), 0);
}
