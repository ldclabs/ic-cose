//! Run explicitly after building both canisters:
//! POCKET_IC_BIN=/path/to/pocket-ic-16 cargo test -p ic_wasm_canister
//!   --test canister_runtime -- --ignored
//! CANISTER_WASM_DIR selects a wasm64 release directory for the same tests.
use candid::{utils::ArgumentEncoder, CandidType, Principal};
use ed25519_dalek::{Signer, SigningKey};
use ic_auth_types::{SignInResponse, SignedDelegation};
use ic_canister_sig_creation::{delegation_signature_msg, DELEGATION_SIG_DOMAIN};
use ic_cose_types::{
    cose::sha256,
    types::{namespace::*, wasm::*, SignDelegationInput},
};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde::de::DeserializeOwned;
use serde_bytes::{ByteArray, ByteBuf};
use std::{collections::BTreeSet, path::PathBuf, time::Duration};

fn wasm(name: &str) -> Vec<u8> {
    let directory = std::env::var_os("CANISTER_WASM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/wasm32-unknown-unknown/release")
        });
    std::fs::read(directory.join(format!("{name}.wasm"))).expect("build canisters first")
}

fn replica() -> PocketIc {
    assert!(
        std::env::var_os("POCKET_IC_BIN").is_some(),
        "set POCKET_IC_BIN to a PocketIC 16 server; tests do not download servers"
    );
    PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build()
}

fn update<T: CandidType + DeserializeOwned>(
    pic: &PocketIc,
    id: Principal,
    caller: Principal,
    method: &str,
    args: impl ArgumentEncoder,
) -> Result<T, String> {
    let reply = pic
        .update_call(id, caller, method, candid::encode_args(args).unwrap())
        .unwrap();
    candid::decode_one(&reply).unwrap()
}

fn query<T: CandidType + DeserializeOwned>(
    pic: &PocketIc,
    id: Principal,
    caller: Principal,
    method: &str,
    args: impl ArgumentEncoder,
) -> Result<T, String> {
    let reply = pic
        .query_call(id, caller, method, candid::encode_args(args).unwrap())
        .unwrap();
    candid::decode_one(&reply).unwrap()
}

#[derive(CandidType)]
enum Init<T: CandidType> {
    Init(T),
}

#[derive(CandidType)]
struct CoseInit {
    name: String,
    ecdsa_key_name: String,
    schnorr_key_name: String,
    vetkd_key_name: String,
    allowed_apis: BTreeSet<String>,
    subnet_size: u64,
    freezing_threshold: u64,
    governance_canister: Option<Principal>,
}

#[derive(CandidType)]
struct WasmInit {
    name: String,
    topup_threshold: u128,
    topup_amount: u128,
    governance_canister: Option<Principal>,
}

#[test]
#[ignore = "requires built Wasm files and a local PocketIC 16 server"]
fn delegation_certification_and_stable_state_survive_upgrade() {
    let pic = replica();
    let caller = Principal::from_slice(&[1, 2, 3]);
    let id = pic.create_canister_with_settings(Some(caller), None);
    pic.add_cycles(id, 100_000_000_000_000);
    let module = wasm("ic_cose_canister");
    pic.install_canister(
        id,
        module.clone(),
        candid::encode_one(Some(Init::Init(CoseInit {
            name: "runtime".into(),
            ecdsa_key_name: "test_key_1".into(),
            schnorr_key_name: "test_key_1".into(),
            vetkd_key_name: "test_key_1".into(),
            allowed_apis: BTreeSet::new(),
            subnet_size: 0,
            freezing_threshold: 0,
            governance_canister: Some(caller),
        })))
        .unwrap(),
        Some(caller),
    );
    let input = CreateNamespaceInput {
        name: "runtime".into(),
        managers: BTreeSet::from([caller]),
        ..Default::default()
    };
    let _: NamespaceInfo = update(&pic, id, caller, "admin_create_namespace", (input,)).unwrap();
    let _: BTreeSet<Principal> = update(
        &pic,
        id,
        caller,
        "namespace_add_delegator",
        (NamespaceDelegatorsInput {
            ns: "runtime".into(),
            name: "session".into(),
            delegators: BTreeSet::from([caller]),
        },),
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(key.verifying_key().as_bytes());
    let challenge = cbor2::to_vec(&("runtime", "session", caller)).unwrap();
    let sign_in: SignInResponse = update(
        &pic,
        id,
        caller,
        "namespace_sign_delegation",
        (SignDelegationInput {
            ns: "runtime".into(),
            name: "session".into(),
            pubkey: der.clone().into(),
            sig: key.sign(&challenge).to_bytes().to_vec().into(),
        },),
    )
    .unwrap();
    let verify = || {
        let signed: SignedDelegation = query(
            &pic,
            id,
            caller,
            "get_delegation",
            (
                ByteBuf::from(sign_in.seed.to_vec()),
                ByteBuf::from(der.clone()),
                sign_in.expiration,
            ),
        )
        .unwrap();
        let mut message = vec![DELEGATION_SIG_DOMAIN.len() as u8];
        message.extend_from_slice(DELEGATION_SIG_DOMAIN);
        message.extend_from_slice(&delegation_signature_msg(&der, sign_in.expiration, None));
        ic_auth_verifier::verify_canister_sig(
            &message,
            &signed.signature,
            &sign_in.user_key,
            &pic.root_key().unwrap(),
            &u128::from(pic.get_time().as_nanos_since_unix_epoch()),
            Some(300_000_000_000),
        )
        .unwrap();
    };
    pic.tick();
    verify();
    pic.upgrade_canister(
        id,
        module.clone(),
        candid::encode_one(None::<()>).unwrap(),
        Some(caller),
    )
    .unwrap();
    pic.tick();
    verify();
    let ns: NamespaceInfo = query(&pic, id, caller, "namespace_get_info", ("runtime",)).unwrap();
    assert_eq!(ns.managers, BTreeSet::from([caller]));
    pic.advance_time(Duration::from_secs(61));
    pic.upgrade_canister(
        id,
        module,
        candid::encode_one(None::<()>).unwrap(),
        Some(caller),
    )
    .unwrap();
    let expired: Result<SignedDelegation, _> = query(
        &pic,
        id,
        caller,
        "get_delegation",
        (
            ByteBuf::from(sign_in.seed.to_vec()),
            ByteBuf::from(der),
            sign_in.expiration,
        ),
    );
    assert!(
        expired.is_err(),
        "expired signature intent must not be restored"
    );
}

#[test]
#[ignore = "requires built Wasm files and a local PocketIC 16 server"]
fn provisioning_handoff_stays_forgotten_after_upgrade_and_owner_retry() {
    let pic = replica();
    let controller = Principal::from_slice(&[1, 2, 3]);
    let owner = Principal::from_slice(&[2, 3, 4]);
    let id = pic.create_canister_with_settings(Some(controller), None);
    pic.add_cycles(id, 100_000_000_000_000);
    let module = wasm("ic_wasm_canister");
    pic.install_canister(
        id,
        module.clone(),
        candid::encode_one(Some(Init::Init(WasmInit {
            name: "runtime".into(),
            topup_threshold: 0,
            topup_amount: 0,
            governance_canister: Some(controller),
        })))
        .unwrap(),
        Some(controller),
    );
    let bytes = b"\0asm\x01\0\0\0".to_vec();
    let hash = ByteArray::from(sha256(&bytes));
    let _: () = update(
        &pic,
        id,
        controller,
        "admin_add_wasm",
        (
            AddWasmInput {
                name: "runtime".into(),
                description: String::new(),
                wasm: bytes.into(),
                encoding: Some(WasmEncoding::Raw),
            },
            None::<ByteArray<32>>,
        ),
    )
    .unwrap();
    let _: () = update(
        &pic,
        id,
        controller,
        "admin_add_provisioners",
        (BTreeSet::from([owner]),),
    )
    .unwrap();
    let controllers: Vec<_> = BTreeSet::from([id, controller]).into_iter().collect();
    let template: ProvisionTemplateInfo = update(
        &pic,
        id,
        controller,
        "admin_add_provision_template",
        (ProvisionTemplate {
            id: "runtime".into(),
            wasm_name: "runtime".into(),
            artifact_hash: hash,
            expected_module_hash: hash,
            encoding: WasmEncoding::Raw,
            settings: ProvisionSettings {
                controllers,
                ..Default::default()
            },
            subnet: None,
            initial_cycles: 2_000_000_000_000,
            max_init_args_bytes: 1024,
            pool_size: 1,
        },),
    )
    .unwrap();
    let target: Principal =
        update(&pic, id, controller, "admin_refill_pool", ("runtime",)).unwrap();
    let expires_at = pic.get_time().as_nanos_since_unix_epoch() / 1_000_000 + 3_600_000;
    let request_id = ByteArray::from([9; 32]);
    let _: ReservationReceipt = update(
        &pic,
        id,
        owner,
        "reserve_canister",
        (ReserveRequest {
            request_id,
            provision_template_id: "runtime".into(),
            provision_template_hash: template.hash,
            expires_at,
        },),
    )
    .unwrap();
    let args = ByteBuf::from(b"DIDL\0\0".as_slice());
    let req = InstallRequest {
        request_id,
        canister: target,
        provision_template_id: "runtime".into(),
        provision_template_hash: template.hash,
        expected_module_hash: hash,
        init_args_hash: sha256(&args).into(),
        init_args: args,
        provision_spec_hash: [8; 32].into(),
        expires_at,
    };
    let installed: ProvisionReceipt = update(&pic, id, owner, "ensure_install", (&req,)).unwrap();
    assert_eq!(installed.stage, ProvisionStage::Installed);
    let _: () = update(
        &pic,
        id,
        controller,
        "admin_handoff_canister",
        (ic_cdk_management_canister::UpdateSettingsArgs {
            canister_id: target,
            settings: ic_cdk_management_canister::CanisterSettings {
                controllers: Some(vec![controller]),
                ..Default::default()
            },
        },),
    )
    .unwrap();
    pic.upgrade_canister(
        id,
        module,
        candid::encode_one(None::<()>).unwrap(),
        Some(controller),
    )
    .unwrap();
    let replay: Result<ProvisionReceipt, _> = update(&pic, id, owner, "ensure_install", (&req,));
    assert!(replay.unwrap_err().contains("handed off or forgotten"));
    let deployed: Vec<Principal> =
        query(&pic, id, controller, "get_deployed_canisters", ()).unwrap();
    assert!(deployed.is_empty());
    let metadata: WasmMetadata = query(&pic, id, controller, "get_wasm_metadata", (hash,)).unwrap();
    assert_eq!(metadata.module_hash, hash);
}

#[test]
#[ignore = "requires built Wasm files and a local PocketIC 16 server"]
fn large_artifacts_install_through_concurrently_uploaded_chunks() {
    let pic = replica();
    let controller = Principal::from_slice(&[1, 2, 3]);
    let owner = Principal::from_slice(&[2, 3, 4]);
    let id = pic.create_canister_with_settings(Some(controller), None);
    pic.add_cycles(id, 100_000_000_000_000);
    pic.install_canister(
        id,
        wasm("ic_wasm_canister"),
        candid::encode_one(Some(Init::Init(WasmInit {
            name: "runtime".into(),
            topup_threshold: 0,
            topup_amount: 0,
            governance_canister: Some(controller),
        })))
        .unwrap(),
        Some(controller),
    );

    // Five 1 MiB storage chunks: more than one concurrent upload group and far
    // above the direct-install limit.
    let payload = "a".repeat(4_500_000);
    let module = wat::parse_str(format!(
        r#"(module (memory 80) (data (i32.const 0) "{payload}"))"#
    ))
    .unwrap();
    let hash = ByteArray::from(sha256(&module));
    let chunk_hashes: Vec<ByteArray<32>> = module
        .chunks(1024 * 1024)
        .map(|chunk| {
            update(
                &pic,
                id,
                controller,
                "admin_add_wasm_chunk",
                (ByteBuf::from(chunk),),
            )
            .unwrap()
        })
        .collect();
    let committed: ByteArray<32> = update(
        &pic,
        id,
        controller,
        "admin_commit_wasm_chunks",
        (
            CommitWasmChunksInput {
                name: "large".into(),
                description: String::new(),
                chunk_hashes,
                artifact_hash: hash,
                encoding: Some(WasmEncoding::Raw),
            },
            None::<ByteArray<32>>,
        ),
    )
    .unwrap();
    assert_eq!(committed, hash);

    let _: () = update(
        &pic,
        id,
        controller,
        "admin_add_provisioners",
        (BTreeSet::from([owner]),),
    )
    .unwrap();
    let controllers: Vec<_> = BTreeSet::from([id, controller]).into_iter().collect();
    let template: ProvisionTemplateInfo = update(
        &pic,
        id,
        controller,
        "admin_add_provision_template",
        (ProvisionTemplate {
            id: "large".into(),
            wasm_name: "large".into(),
            artifact_hash: hash,
            expected_module_hash: hash,
            encoding: WasmEncoding::Raw,
            settings: ProvisionSettings {
                controllers,
                ..Default::default()
            },
            subnet: None,
            initial_cycles: 5_000_000_000_000,
            max_init_args_bytes: 1024,
            pool_size: 1,
        },),
    )
    .unwrap();
    let target: Principal = update(&pic, id, controller, "admin_refill_pool", ("large",)).unwrap();
    let expires_at = pic.get_time().as_nanos_since_unix_epoch() / 1_000_000 + 3_600_000;
    let request_id = ByteArray::from([7; 32]);
    let _: ReservationReceipt = update(
        &pic,
        id,
        owner,
        "reserve_canister",
        (ReserveRequest {
            request_id,
            provision_template_id: "large".into(),
            provision_template_hash: template.hash,
            expires_at,
        },),
    )
    .unwrap();
    let args = ByteBuf::from(b"DIDL\0\0".as_slice());
    let installed: ProvisionReceipt = update(
        &pic,
        id,
        owner,
        "ensure_install",
        (InstallRequest {
            request_id,
            canister: target,
            provision_template_id: "large".into(),
            provision_template_hash: template.hash,
            expected_module_hash: hash,
            init_args_hash: sha256(&args).into(),
            init_args: args,
            provision_spec_hash: [6; 32].into(),
            expires_at,
        },),
    )
    .unwrap();
    assert_eq!(installed.stage, ProvisionStage::Installed);
    assert_eq!(installed.module_hash, Some(hash));
    assert_eq!(
        pic.canister_status(target, Some(id))
            .unwrap()
            .module_hash
            .as_deref(),
        Some(hash.as_slice())
    );
}

// Minimal local wallet fixture: forwards the top-up arguments with attached cycles.
fn fund_namespace(pic: &PocketIc, target: Principal, caller: Principal, namespace: &str) {
    let target_bytes = target
        .as_slice()
        .iter()
        .map(|b| format!("\\{b:02x}"))
        .collect::<String>();
    let module = wat::parse_str(format!(
        r#"(module
      (import "ic0" "msg_arg_data_size" (func $size (result i32)))
      (import "ic0" "msg_arg_data_copy" (func $copy (param i32 i32 i32)))
      (import "ic0" "msg_reply_data_append" (func $append (param i32 i32)))
      (import "ic0" "msg_reply" (func $reply))
      (import "ic0" "call_new" (func $new (param i32 i32 i32 i32 i32 i32 i32 i32)))
      (import "ic0" "call_data_append" (func $args (param i32 i32)))
      (import "ic0" "call_cycles_add128" (func $cycles (param i64 i64)))
      (import "ic0" "call_perform" (func $perform (result i32)))
      (memory (export "memory") 1)
      (table 2 funcref)
      (elem (i32.const 0) $done $failed)
      (data (i32.const 0) "{target_bytes}")
      (data (i32.const 64) "namespace_top_up")
      (func $done (param i32)
        (call $copy (i32.const 128) (i32.const 0) (call $size))
        (call $append (i32.const 128) (call $size)) (call $reply))
      (func $failed (param i32) unreachable)
      (func (export "canister_update fund")
        (call $copy (i32.const 128) (i32.const 0) (call $size))
        (call $new (i32.const 0) (i32.const {target_len}) (i32.const 64) (i32.const 16)
          (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 0))
        (call $args (i32.const 128) (call $size))
        (call $cycles (i64.const 0) (i64.const 10000000000000))
        (if (call $perform) (then unreachable))))"#,
        target_len = target.as_slice().len()
    ))
    .unwrap();
    let wallet = pic.create_canister_with_settings(Some(caller), None);
    pic.add_cycles(wallet, 100_000_000_000_000);
    pic.install_canister(wallet, module, vec![], Some(caller));
    let received: u128 = update(
        pic,
        wallet,
        caller,
        "fund",
        (namespace, 10_000_000_000_000u128),
    )
    .unwrap();
    assert_eq!(received, 10_000_000_000_000);
}

#[test]
#[ignore = "requires built Wasm files and a local PocketIC 16 server"]
fn key_permissions_and_billing_work_for_external_setting_readers() {
    use ic_cose_types::types::{setting::*, ECDHInput};
    use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey};
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_test_threshold_keys_subnet()
        .build();
    let manager = Principal::from_slice(&[9, 1]);
    let outsider = Principal::from_slice(&[9, 2]);
    let reader = Principal::from_slice(&[9, 3]);
    let id = pic.create_canister_with_settings(Some(manager), None);
    pic.add_cycles(id, 100_000_000_000_000);
    pic.install_canister(
        id,
        wasm("ic_cose_canister"),
        candid::encode_one(Some(Init::Init(CoseInit {
            name: "keys".into(),
            ecdsa_key_name: "test_key_1".into(),
            schnorr_key_name: "test_key_1".into(),
            vetkd_key_name: "test_key_1".into(),
            allowed_apis: BTreeSet::new(),
            subnet_size: 0,
            freezing_threshold: 0,
            governance_canister: Some(manager),
        })))
        .unwrap(),
        Some(manager),
    );
    let _: NamespaceInfo = update(
        &pic,
        id,
        manager,
        "admin_create_namespace",
        (CreateNamespaceInput {
            name: "keys".into(),
            managers: BTreeSet::from([manager]),
            ..Default::default()
        },),
    )
    .unwrap();
    fund_namespace(&pic, id, manager, "keys");
    let balance = || -> u128 {
        let info: NamespaceInfo =
            query(&pic, id, manager, "namespace_get_info", ("keys",)).unwrap();
        info.gas_balance
    };
    let before = balance();
    let mut path = SettingPath {
        ns: "keys".into(),
        subject: Some(outsider),
        key: vec![1].into(),
        ..Default::default()
    };
    let transport = TransportSecretKey::from_seed([7u8; 32].into()).unwrap();
    let transport_public: ByteBuf = transport.public_key().into();
    for owned in [false, true] {
        path.user_owned = owned;
        let denied: Result<ByteBuf, _> = update(
            &pic,
            id,
            outsider,
            "vetkd_encrypted_key",
            (&path, &transport_public),
        );
        assert!(denied.unwrap_err().contains("no permission"));
        let denied: Result<ic_cose_types::types::ECDHOutput<ByteBuf>, _> = update(
            &pic,
            id,
            outsider,
            "ecdh_cose_encrypted_key",
            (
                &path,
                ECDHInput {
                    public_key: [1; 32].into(),
                    nonce: [2; 12].into(),
                },
            ),
        );
        assert!(denied.unwrap_err().contains("no permission"));
        assert_eq!(balance(), before);
    }
    path.user_owned = false;
    let created: CreateSettingOutput = update(
        &pic,
        id,
        manager,
        "setting_create",
        (&path, CreateSettingInput::default()),
    )
    .unwrap();
    path.version = created.version;
    let _: () = update(
        &pic,
        id,
        manager,
        "setting_add_readers",
        (&path, BTreeSet::from([reader])),
    )
    .unwrap();
    let public: ByteBuf = update(&pic, id, reader, "vetkd_public_key", (&path,)).unwrap();
    let before_key = balance();
    let encrypted: ByteBuf = update(
        &pic,
        id,
        reader,
        "vetkd_encrypted_key",
        (&path, &transport_public),
    )
    .unwrap();
    let successful_charge = before_key - balance();
    let public = DerivedPublicKey::deserialize(&public).unwrap();
    let encrypted = EncryptedVetKey::deserialize(&encrypted).unwrap();
    encrypted
        .decrypt_and_verify(&transport, &public, &path.key)
        .unwrap();
    assert!(balance() < before);
    // A management rejection must remain a normal Result, including the refund callback.
    let before_rejection = balance();
    let invalid: Result<ByteBuf, _> = update(
        &pic,
        id,
        reader,
        "vetkd_encrypted_key",
        (&path, ByteArray::from([0; 48])),
    );
    assert!(invalid.is_err());
    assert!(
        before_rejection - balance() < successful_charge,
        "refunded request cycles must be credited back to the namespace"
    );
    let _: () = update(
        &pic,
        id,
        manager,
        "setting_remove_readers",
        (&path, BTreeSet::from([reader])),
    )
    .unwrap();
    let before = balance();
    let denied: Result<ByteBuf, _> = update(&pic, id, reader, "vetkd_public_key", (&path,));
    assert!(denied.unwrap_err().contains("no permission"));
    assert_eq!(balance(), before);
}

#[test]
#[ignore = "requires built Wasm files and a local PocketIC 16 server"]
fn storage_operations_report_cycle_costs() {
    use ic_cose_types::types::setting::*;
    let pic = replica();
    let manager = Principal::from_slice(&[8, 9]);
    let id = pic.create_canister_with_settings(Some(manager), None);
    pic.add_cycles(id, 100_000_000_000_000);
    pic.install_canister(
        id,
        wasm("ic_cose_canister"),
        candid::encode_one(Some(Init::Init(CoseInit {
            name: "storage_benchmark".into(),
            ecdsa_key_name: "test_key_1".into(),
            schnorr_key_name: "test_key_1".into(),
            vetkd_key_name: "test_key_1".into(),
            allowed_apis: BTreeSet::new(),
            subnet_size: 0,
            freezing_threshold: 0,
            governance_canister: Some(manager),
        })))
        .unwrap(),
        Some(manager),
    );
    for _ in 0..20 {
        pic.tick();
    }
    for size in [256 * 1024, 1024 * 1024] {
        let namespace = format!("payload_{size}");
        let _: NamespaceInfo = update(
            &pic,
            id,
            manager,
            "admin_create_namespace",
            (CreateNamespaceInput {
                name: namespace.clone(),
                managers: BTreeSet::from([manager]),
                ..Default::default()
            },),
        )
        .unwrap();
        let mut path = SettingPath {
            ns: namespace.clone(),
            subject: Some(manager),
            key: vec![1].into(),
            ..Default::default()
        };
        let before = pic.cycle_balance(id);
        let created: CreateSettingOutput = update(
            &pic,
            id,
            manager,
            "setting_create",
            (
                &path,
                CreateSettingInput {
                    payload: Some(vec![1; size].into()),
                    ..Default::default()
                },
            ),
        )
        .unwrap();
        println!("CYCLES create_{size} {}", before - pic.cycle_balance(id));
        path.version = created.version;
        let before = pic.cycle_balance(id);
        let updated: UpdateSettingOutput = update(
            &pic,
            id,
            manager,
            "setting_update_payload",
            (
                &path,
                UpdateSettingPayloadInput {
                    payload: Some(vec![2; size].into()),
                    ..Default::default()
                },
            ),
        )
        .unwrap();
        println!("CYCLES update_{size} {}", before - pic.cycle_balance(id));
        path.version = updated.version;
        let before = pic.cycle_balance(id);
        let _: () = update(&pic, id, manager, "setting_delete", (&path,)).unwrap();
        println!("CYCLES delete_{size} {}", before - pic.cycle_balance(id));
        let info: NamespaceInfo =
            query(&pic, id, manager, "namespace_get_info", (&namespace,)).unwrap();
        assert_eq!(info.payload_bytes_total, 0);
    }
    for count in [100u32, 3_999] {
        let namespace = format!("members_{count}");
        let _: NamespaceInfo = update(
            &pic,
            id,
            manager,
            "admin_create_namespace",
            (CreateNamespaceInput {
                name: namespace.clone(),
                managers: BTreeSet::from([manager]),
                ..Default::default()
            },),
        )
        .unwrap();
        let members: Vec<_> = (0..count)
            .map(|i| Principal::from_slice(&i.to_be_bytes()))
            .collect();
        for chunk in members.chunks(1_000) {
            let _: () = update(
                &pic,
                id,
                manager,
                "namespace_add_users",
                (&namespace, chunk.iter().copied().collect::<BTreeSet<_>>()),
            )
            .unwrap();
        }
        let extra = Principal::from_slice(&[77, 99]);
        let before = pic.cycle_balance(id);
        let _: () = update(
            &pic,
            id,
            manager,
            "namespace_add_users",
            (&namespace, BTreeSet::from([extra])),
        )
        .unwrap();
        println!("CYCLES acl_add_{count} {}", before - pic.cycle_balance(id));
        let before = pic.cycle_balance(id);
        let _: () = update(
            &pic,
            id,
            manager,
            "namespace_remove_users",
            (&namespace, BTreeSet::from([extra])),
        )
        .unwrap();
        println!(
            "CYCLES acl_remove_{count} {}",
            before - pic.cycle_balance(id)
        );
        let info: NamespaceInfo = query(
            &pic,
            id,
            manager,
            "namespace_get_info_v2",
            (&namespace, false),
        )
        .unwrap();
        assert_eq!(info.user_count, count);
    }
}
