//! Run explicitly after building both canisters:
//! POCKET_IC_BIN=/path/to/pocket-ic-13 cargo test -p ic_wasm_canister
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
        "set POCKET_IC_BIN to a PocketIC 13 server; tests do not download servers"
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
#[ignore = "requires built Wasm files and a local PocketIC 13 server"]
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
#[ignore = "requires built Wasm files and a local PocketIC 13 server"]
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
