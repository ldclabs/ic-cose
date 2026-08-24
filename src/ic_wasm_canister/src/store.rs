use candid::Principal;
use cbor2::{from_reader, to_writer, Value};
use ic_cose_types::{
    cose::sha256,
    format_error,
    types::wasm::{
        AddWasmInput, DeploymentInfo, PoolCanisterInfo, PoolCanisterState, PoolStatus,
        ProvisionReceipt, ProvisionStage, ProvisionTemplate, ProvisionTemplateInfo, ReleaseReceipt,
        ReservationReceipt, StateInfo, WasmEncoding,
    },
};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    DefaultMemoryImpl, StableBTreeMap, StableCell, StableLog, Storable,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap},
    ops,
};

type Memory = VirtualMemory<DefaultMemoryImpl>;

fn from_cbor_bytes<T>(bytes: &[u8], context: &str) -> T
where
    T: DeserializeOwned,
{
    // Decode through Value so candid::Principal sees CBOR byte strings via visit_bytes.
    let value: Value =
        from_reader(bytes).unwrap_or_else(|err| panic!("failed to decode {context}: {err:?}"));
    value
        .deserialized()
        .unwrap_or_else(|err| panic!("failed to deserialize {context}: {err:?}"))
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct State {
    pub name: String,
    pub managers: BTreeSet<Principal>,
    pub latest_version: BTreeMap<String, ByteArray<32>>,
    pub upgrade_path: HashMap<ByteArray<32>, ByteArray<32>>,
    pub deployed_list: BTreeMap<Principal, (u64, ByteArray<32>)>,
    pub topup_threshold: u128,
    pub topup_amount: u128,
    pub governance_canister: Option<Principal>,
    pub committers: BTreeSet<Principal>,
    /// Least-privilege role for the provisioning API: may reserve, install and
    /// release canisters from approved templates, nothing else.
    #[serde(default)]
    pub provisioners: BTreeSet<Principal>,
}

impl Storable for State {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        let mut buf = vec![];
        to_writer(&self, &mut buf).expect("failed to encode State data");
        buf
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        to_writer(self, &mut buf).expect("failed to encode State data");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "State data")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Wasm {
    #[serde(rename = "n", alias = "name")]
    pub name: String,
    #[serde(rename = "a", alias = "created_at")]
    pub created_at: u64, // in milliseconds
    #[serde(rename = "b", alias = "created_by")]
    pub created_by: Principal,
    #[serde(rename = "d", alias = "description")]
    pub description: String,
    #[serde(rename = "w", alias = "wasm")]
    pub wasm: ByteBuf,
    #[serde(default, rename = "e", alias = "encoding")]
    pub encoding: WasmEncoding,
}

impl Storable for Wasm {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        let mut buf = vec![];
        to_writer(&self, &mut buf).expect("failed to encode Wasm data");
        buf
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        to_writer(self, &mut buf).expect("failed to encode Wasm data");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "Wasm data")
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct DeployLog {
    #[serde(rename = "n", alias = "name")]
    pub name: String,
    #[serde(rename = "d", alias = "deploy_at")]
    pub deploy_at: u64, // in milliseconds
    #[serde(rename = "c", alias = "canister")]
    pub canister: Principal,
    #[serde(rename = "p", alias = "prev_hash")]
    pub prev_hash: ByteArray<32>,
    #[serde(rename = "w", alias = "wasm_hash")]
    pub wasm_hash: ByteArray<32>,
    #[serde(rename = "a", alias = "args")]
    pub args: ByteBuf,
    #[serde(rename = "e", alias = "error")]
    pub error: Option<String>,
}

impl Storable for DeployLog {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        let mut buf = vec![];
        to_writer(&self, &mut buf).expect("failed to encode DeployLog data");
        buf
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        to_writer(self, &mut buf).expect("failed to encode DeployLog data");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "DeployLog data")
    }
}

/// One pre-created canister in a template's pool.
#[derive(Clone, Deserialize, Serialize)]
pub struct PoolCanister {
    #[serde(rename = "s")]
    pub state: PoolCanisterState,
    #[serde(rename = "c")]
    pub created_at: u64,
    /// Set while the canister is claimed by a request.
    #[serde(default, rename = "r")]
    pub request_id: Option<ByteArray<32>>,
}

/// A governance-approved template plus its derived hashes and pool counters.
#[derive(Clone, Deserialize, Serialize)]
pub struct TemplateEntry {
    #[serde(rename = "t")]
    pub template: ProvisionTemplate,
    #[serde(rename = "h")]
    pub hash: ByteArray<32>,
    #[serde(rename = "sh")]
    pub settings_hash: ByteArray<32>,
    #[serde(rename = "nh")]
    pub subnet_policy_hash: ByteArray<32>,
    #[serde(rename = "ca")]
    pub created_at: u64,
    #[serde(rename = "cb")]
    pub created_by: Principal,
    #[serde(rename = "ps")]
    pub pool_status: PoolStatus,
    #[serde(rename = "av")]
    pub available: u32,
    #[serde(rename = "rv")]
    pub reserved: u32,
    #[serde(rename = "in")]
    pub installed: u32,
    #[serde(rename = "tb")]
    pub tombstones: u32,
}

impl TemplateEntry {
    pub fn into_info(self) -> ProvisionTemplateInfo {
        ProvisionTemplateInfo {
            template: self.template,
            hash: self.hash,
            settings_hash: self.settings_hash,
            subnet_policy_hash: self.subnet_policy_hash,
            created_at: self.created_at,
            created_by: self.created_by,
            pool_status: self.pool_status,
            available: self.available,
            reserved: self.reserved,
            installed: self.installed,
            tombstones: self.tombstones,
        }
    }
}

/// The durable record behind one `request_id`.
///
/// Written before the reply to `reserve_canister`, so a lost response can be
/// recovered by querying the same request id instead of creating a second
/// canister.
#[derive(Clone, Deserialize, Serialize)]
pub struct ProvisionRequest {
    #[serde(rename = "s")]
    pub stage: ProvisionStage,
    #[serde(rename = "c")]
    pub canister: Principal,
    #[serde(rename = "n")]
    pub wasm_name: String,
    #[serde(default, rename = "ti")]
    pub template_id: Option<String>,
    #[serde(default, rename = "th")]
    pub template_hash: Option<ByteArray<32>>,
    #[serde(rename = "ah")]
    pub artifact_hash: ByteArray<32>,
    #[serde(default, rename = "eh")]
    pub expected_module_hash: ByteArray<32>,
    #[serde(default, rename = "mh")]
    pub module_hash: Option<ByteArray<32>>,
    #[serde(default, rename = "ph")]
    pub prev_module_hash: Option<ByteArray<32>>,
    #[serde(default, rename = "gh")]
    pub args_hash: Option<ByteArray<32>>,
    #[serde(default, rename = "sh")]
    pub provision_spec_hash: Option<ByteArray<32>>,
    #[serde(default, rename = "e")]
    pub error: Option<String>,
    #[serde(rename = "ca")]
    pub created_at: u64,
    #[serde(rename = "ua")]
    pub updated_at: u64,
}

impl ProvisionRequest {
    pub fn into_receipt(self, request_id: ByteArray<32>) -> ProvisionReceipt {
        ProvisionReceipt {
            request_id,
            stage: self.stage,
            canister: self.canister,
            wasm_name: self.wasm_name,
            provision_template_id: self.template_id,
            provision_template_hash: self.template_hash,
            artifact_hash: self.artifact_hash,
            module_hash: self.module_hash,
            prev_module_hash: self.prev_module_hash,
            args_hash: self.args_hash,
            provision_spec_hash: self.provision_spec_hash,
            error: self.error,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

macro_rules! impl_cbor_storable {
    ($ty:ty, $ctx:literal) => {
        impl Storable for $ty {
            const BOUND: Bound = Bound::Unbounded;

            fn into_bytes(self) -> Vec<u8> {
                let mut buf = vec![];
                to_writer(&self, &mut buf).expect(concat!("failed to encode ", $ctx));
                buf
            }

            fn to_bytes(&self) -> Cow<'_, [u8]> {
                let mut buf = vec![];
                to_writer(self, &mut buf).expect(concat!("failed to encode ", $ctx));
                Cow::Owned(buf)
            }

            fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
                from_cbor_bytes(&bytes, $ctx)
            }
        }
    };
}

impl_cbor_storable!(TemplateEntry, "TemplateEntry data");
impl_cbor_storable!(PoolCanister, "PoolCanister data");
impl_cbor_storable!(ProvisionRequest, "ProvisionRequest data");

/// `(template_id, canister)`
#[derive(Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct PoolKey(pub String, pub Principal);
impl_cbor_storable!(PoolKey, "PoolKey data");

/// `(template_id, released_at_ms, request_id)`, ordered so the oldest
/// tombstone of a template is the first key in its range.
#[derive(Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct TombstoneKey(pub String, pub u64, pub ByteArray<32>);
impl_cbor_storable!(TombstoneKey, "TombstoneKey data");

/// `(uploader, chunk_hash)`, so concurrent uploaders never mix chunks.
#[derive(Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct ChunkKey(pub Principal, pub ByteArray<32>);
impl_cbor_storable!(ChunkKey, "ChunkKey data");

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const WASM_MEMORY_ID: MemoryId = MemoryId::new(1);
const INSTALL_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(2);
const INSTALL_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(3);
const TEMPLATE_MEMORY_ID: MemoryId = MemoryId::new(4);
const POOL_MEMORY_ID: MemoryId = MemoryId::new(5);
const REQUEST_MEMORY_ID: MemoryId = MemoryId::new(6);
const TOMBSTONE_MEMORY_ID: MemoryId = MemoryId::new(7);
const CHUNK_MEMORY_ID: MemoryId = MemoryId::new(8);

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static STATE_STORE: RefCell<StableCell<State, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(STATE_MEMORY_ID)),
            State::default()
        )
    );

    static WASM_STORE: RefCell<StableBTreeMap<[u8; 32], Wasm, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(WASM_MEMORY_ID)),
        )
    );

    static INSTALL_LOGS: RefCell<StableLog<DeployLog, Memory, Memory>> = RefCell::new(
        StableLog::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(INSTALL_LOG_INDEX_MEMORY_ID)),
            MEMORY_MANAGER.with_borrow(|m| m.get(INSTALL_LOG_DATA_MEMORY_ID)),
        )
    );

    static TEMPLATE_STORE: RefCell<StableBTreeMap<String, TemplateEntry, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(TEMPLATE_MEMORY_ID)))
    );

    static POOL_STORE: RefCell<StableBTreeMap<PoolKey, PoolCanister, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(POOL_MEMORY_ID)))
    );

    static REQUEST_STORE: RefCell<StableBTreeMap<[u8; 32], ProvisionRequest, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(REQUEST_MEMORY_ID)))
    );

    static TOMBSTONE_STORE: RefCell<StableBTreeMap<TombstoneKey, u64, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(TOMBSTONE_MEMORY_ID)))
    );

    static CHUNK_STORE: RefCell<StableBTreeMap<ChunkKey, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(CHUNK_MEMORY_ID)))
    );
}

pub mod state {
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
        with(|s| StateInfo {
            name: s.name.clone(),
            managers: s.managers.clone(),
            committers: s.committers.clone(),
            latest_version: s.latest_version.clone(),
            wasm_total: WASM_STORE.with(|r| r.borrow().len()),
            deployed_total: s.deployed_list.len() as u64,
            deployment_logs: INSTALL_LOGS.with(|r| r.borrow().len()),
            governance_canister: s.governance_canister,
        })
    }

    pub fn with<R>(f: impl FnOnce(&State) -> R) -> R {
        STATE.with_borrow(|r| f(r))
    }

    pub fn with_mut<R>(f: impl FnOnce(&mut State) -> R) -> R {
        STATE.with_borrow_mut(|r| f(r))
    }

    pub fn load() {
        STATE_STORE.with_borrow(|r| {
            STATE.with_borrow_mut(|h| {
                let s = r.get().to_owned();
                *h = s;
            });
        });
    }

    pub fn save() {
        STATE.with_borrow(|h| {
            STATE_STORE.with_borrow_mut(|r| {
                r.set(h.clone());
            });
        });
    }
}

pub mod wasm {
    use super::*;

    pub fn add_wasm(
        caller: Principal,
        now_ms: u64,
        args: AddWasmInput,
        force_prev_hash: Option<ByteArray<32>>,
        dry_run: bool,
    ) -> Result<(), String> {
        WASM_STORE.with_borrow_mut(|m| {
            let hash: ByteArray<32> = sha256(&args.wasm).into();
            if m.contains_key(&hash) {
                return Err("wasm already exists".to_string());
            }

            if dry_run {
                return state::with(|s| {
                    if let Some(force_prev_hash) = force_prev_hash {
                        if !s.upgrade_path.contains_key(&force_prev_hash) {
                            Err("force_prev_hash not exists".to_string())?
                        }
                    };

                    Ok::<(), String>(())
                });
            }

            state::with_mut(|s| {
                let prev_hash = if let Some(force_prev_hash) = force_prev_hash {
                    if !s.upgrade_path.contains_key(&force_prev_hash) {
                        Err("force_prev_hash not exists".to_string())?
                    }
                    force_prev_hash
                } else {
                    s.latest_version
                        .get(&args.name)
                        .copied()
                        .unwrap_or_else(|| [0u8; 32].into())
                };
                s.upgrade_path.insert(prev_hash, hash);
                s.latest_version.insert(args.name.clone(), hash);
                Ok::<(), String>(())
            })?;

            m.insert(
                *hash,
                Wasm {
                    name: args.name,
                    created_at: now_ms,
                    created_by: caller,
                    description: args.description,
                    wasm: args.wasm,
                    encoding: args.encoding.unwrap_or_default(),
                },
            );
            Ok(())
        })
    }

    pub fn get_latest(name: &str) -> Result<(ByteArray<32>, Wasm), String> {
        state::with(|s| {
            let hash = s
                .latest_version
                .get(name)
                .ok_or_else(|| format!("NotFound: {} not found", name))?;
            WASM_STORE.with_borrow(|r| {
                r.get(hash)
                    .map(|w| (*hash, w))
                    .ok_or_else(|| "NotFound: latest wasm not found".to_string())
            })
        })
    }

    pub fn get_wasm(hash: &ByteArray<32>) -> Option<Wasm> {
        WASM_STORE.with_borrow(|r| r.get(hash))
    }

    /// Resolves the wasm that follows `prev_hash` on the upgrade path.
    ///
    /// `upgrade_path` is keyed by `prev_hash` alone and is shared by every wasm
    /// name, so the all-zero key used by the first version of each name is
    /// claimed by whichever name was added last. Checking the name here turns
    /// that collision into an error instead of installing another wasm's module.
    pub fn next_version(
        name: &str,
        prev_hash: ByteArray<32>,
    ) -> Result<(ByteArray<32>, Wasm), String> {
        state::with(|s| {
            let hash = s
                .upgrade_path
                .get(&prev_hash)
                .ok_or_else(|| "no next version".to_string())?;
            WASM_STORE.with_borrow(|r| {
                let w = r
                    .get(hash)
                    .ok_or_else(|| "NotFound: next version not found".to_string())?;
                if w.name != name {
                    return Err(format!(
                        "next version {} of {} belongs to wasm {}, not {}",
                        hex::encode(hash.as_ref()),
                        hex::encode(prev_hash.as_ref()),
                        w.name,
                        name
                    ));
                }
                Ok((*hash, w))
            })
        })
    }

    pub fn add_log(log: DeployLog) -> Result<u64, String> {
        INSTALL_LOGS.with(|r| r.borrow_mut().append(&log).map_err(format_error))
    }

    pub fn get_deployed() -> Vec<DeploymentInfo> {
        state::with(|s| {
            INSTALL_LOGS.with_borrow(|logs| {
                s.deployed_list
                    .iter()
                    .filter_map(|(_, (id, _))| {
                        logs.get(*id).map(|log| DeploymentInfo {
                            name: log.name.clone(),
                            deploy_at: log.deploy_at,
                            canister: log.canister,
                            prev_hash: log.prev_hash,
                            wasm_hash: log.wasm_hash,
                            args: None,
                            error: log.error,
                        })
                    })
                    .collect()
            })
        })
    }

    pub fn deployment_logs(name: &str, prev: Option<u64>, take: usize) -> Vec<DeploymentInfo> {
        INSTALL_LOGS.with(|r| {
            let logs = r.borrow();
            let latest = logs.len();
            if latest == 0 || take == 0 {
                return vec![];
            }

            let prev = prev.unwrap_or(latest);
            if prev > latest || prev == 0 {
                return vec![];
            }

            let mut idx = prev.saturating_sub(1);
            let mut res: Vec<DeploymentInfo> = Vec::with_capacity(take);
            while let Some(log) = logs.get(idx) {
                // entries for other wasm names are skipped, but the cursor must
                // still move or the loop never terminates
                if log.name == name {
                    res.push(DeploymentInfo {
                        name: log.name.clone(),
                        deploy_at: log.deploy_at,
                        canister: log.canister,
                        prev_hash: log.prev_hash,
                        wasm_hash: log.wasm_hash,
                        args: Some(log.args),
                        error: log.error,
                    });

                    if res.len() >= take {
                        break;
                    }
                }

                if idx == 0 {
                    break;
                }
                idx -= 1;
            }
            res
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn log(name: &str) -> DeployLog {
        DeployLog {
            name: name.to_string(),
            deploy_at: 1,
            canister: Principal::management_canister(),
            prev_hash: Default::default(),
            wasm_hash: Default::default(),
            args: ByteBuf::new(),
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

    fn seed_template(id: &str) -> TemplateEntry {
        let wasm_bytes = vec![0u8, 1, 2, 3, id.len() as u8];
        let artifact_hash: ByteArray<32> = sha256(&wasm_bytes).into();
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
            false,
        )
        .unwrap();

        let template = ProvisionTemplate {
            id: id.to_string(),
            wasm_name: "project".to_string(),
            artifact_hash,
            expected_module_hash: ByteArray::from([9u8; 32]),
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
        provision::add_template(GOV, 1, template).unwrap();
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

    #[test]
    fn reserve_is_idempotent_and_never_creates_a_canister() {
        let id = "tpl_a";
        let entry = seed_template(id);
        let pooled = Principal::from_slice(&[7, 7, 7]);
        provision::finish_pool_create(id, pooled, 1).unwrap();

        let req = reserve_req(id, &entry, 1);
        let first = provision::reserve(10, &req).unwrap();
        assert_eq!(first.canister, pooled);
        assert_eq!(first.controllers, entry.template.settings.controllers);
        assert_eq!(first.initial_cycles, entry.template.initial_cycles);

        // replaying the same request id must always return the same canister
        for _ in 0..100 {
            let again = provision::reserve(11, &req).unwrap();
            assert_eq!(again, first);
        }
        // and must not consume more of the pool
        assert_eq!(provision::get_template(id).unwrap().available, 0);
        assert_eq!(provision::get_template(id).unwrap().reserved, 1);

        // a second request finds the pool empty rather than creating anything
        let err = provision::reserve(12, &reserve_req(id, &entry, 2)).unwrap_err();
        assert!(err.contains("no available canister"), "{err}");

        // the receipt survives a lost response
        let receipt = provision::get_receipt(&rid(1)).unwrap();
        assert_eq!(receipt.canister, pooled);
        assert_eq!(receipt.stage, ProvisionStage::Reserved);
    }

    #[test]
    fn reserve_rejects_a_tampered_template_binding() {
        let id = "tpl_b";
        let entry = seed_template(id);
        provision::finish_pool_create(id, Principal::from_slice(&[8, 8]), 1).unwrap();

        let mut req = reserve_req(id, &entry, 3);
        req.provision_template_hash = ByteArray::from([0u8; 32]);
        assert!(provision::reserve(10, &req)
            .unwrap_err()
            .contains("hash mismatch"));

        // binding a used request id to another template is refused
        let ok = reserve_req(id, &entry, 3);
        provision::reserve(10, &ok).unwrap();
        let other = seed_template("tpl_b2");
        let mut cross = reserve_req("tpl_b2", &other, 3);
        cross.request_id = rid(3);
        assert!(provision::reserve(10, &cross)
            .unwrap_err()
            .contains("different template"));
    }

    #[test]
    fn install_binds_every_parameter_it_was_reserved_with() {
        let id = "tpl_c";
        let entry = seed_template(id);
        provision::finish_pool_create(id, Principal::from_slice(&[9, 9]), 1).unwrap();
        let reservation = provision::reserve(10, &reserve_req(id, &entry, 4)).unwrap();

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
        assert!(provision::begin_install(20, &base).is_ok());

        // paying for one module hash must not deliver another
        let mut wrong_module = base.clone();
        wrong_module.expected_module_hash = ByteArray::from([1u8; 32]);
        assert!(provision::begin_install(20, &wrong_module)
            .unwrap_err()
            .contains("expected_module_hash mismatch"));

        let mut wrong_args = base.clone();
        wrong_args.init_args = TestByteBuf::from(vec![9u8]);
        wrong_args.init_args_hash = sha256(&[9u8]).into();
        assert!(provision::begin_install(20, &wrong_args)
            .unwrap_err()
            .contains("different init_args"));

        let mut wrong_spec = base.clone();
        wrong_spec.provision_spec_hash = ByteArray::from([6u8; 32]);
        assert!(provision::begin_install(20, &wrong_spec)
            .unwrap_err()
            .contains("different provision_spec_hash"));

        let mut wrong_hash = base.clone();
        wrong_hash.init_args_hash = ByteArray::from([0u8; 32]);
        assert!(provision::begin_install(20, &wrong_hash)
            .unwrap_err()
            .contains("init_args_hash does not match"));

        let mut wrong_canister = base.clone();
        wrong_canister.canister = Principal::from_slice(&[3, 3]);
        assert!(provision::begin_install(20, &wrong_canister)
            .unwrap_err()
            .contains("bound to canister"));

        // an install for a request that was never reserved is refused
        let mut unknown = base.clone();
        unknown.request_id = rid(99);
        assert!(provision::begin_install(20, &unknown)
            .unwrap_err()
            .contains("reserve_canister must be called first"));

        // once installed, a replay returns the same receipt instead of reinstalling
        let receipt = provision::finish_install(&rid(4), ByteArray::from([9u8; 32]), 30).unwrap();
        assert_eq!(receipt.stage, ProvisionStage::Installed);
        assert_eq!(receipt.module_hash, Some(ByteArray::from([9u8; 32])));
        match provision::begin_install(40, &base).unwrap() {
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
        provision::finish_pool_create(id, pooled, 1).unwrap();
        provision::reserve(10, &reserve_req(id, &entry, 5)).unwrap();

        assert_eq!(
            provision::expected_controllers(&rid(5)).unwrap(),
            entry.template.settings.controllers
        );

        let receipt = provision::release(20, &rid(5), pooled).unwrap();
        assert_eq!(receipt.canister, pooled);
        let info = provision::get_template(id).unwrap();
        assert_eq!(info.available, 1);
        assert_eq!(info.reserved, 0);
        assert_eq!(info.tombstones, 1);

        // releasing twice is idempotent, and the id can never be reused
        assert_eq!(provision::release(21, &rid(5), pooled).unwrap(), receipt);
        assert!(provision::reserve(22, &reserve_req(id, &entry, 5))
            .unwrap_err()
            .contains("released"));

        // an installed request may not be released
        provision::reserve(23, &reserve_req(id, &entry, 6)).unwrap();
        provision::finish_install(&rid(6), ByteArray::from([9u8; 32]), 24).unwrap();
        assert!(provision::release(25, &rid(6), pooled)
            .unwrap_err()
            .contains("installed request cannot be released"));
    }

    #[test]
    fn release_tombstones_expire_after_the_ttl() {
        let id = "tpl_e";
        let entry = seed_template(id);
        let pooled = Principal::from_slice(&[5, 5]);
        provision::finish_pool_create(id, pooled, 1).unwrap();
        provision::reserve(10, &reserve_req(id, &entry, 7)).unwrap();
        provision::release(20, &rid(7), pooled).unwrap();
        assert!(provision::get_receipt(&rid(7)).is_some());

        // a later release past the TTL prunes the older tombstone and its record
        provision::reserve(30, &reserve_req(id, &entry, 8)).unwrap();
        let late = 20 + provision::RELEASE_TOMBSTONE_TTL_MS + 1;
        provision::release(late, &rid(8), pooled).unwrap();
        assert!(provision::get_receipt(&rid(7)).is_none());
        assert_eq!(provision::get_template(id).unwrap().tombstones, 1);
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

        // a template may not point at bytes this canister does not hold
        let mut missing = entry.template.clone();
        missing.id = "tpl_g2".to_string();
        missing.artifact_hash = ByteArray::from([0u8; 32]);
        assert!(provision::add_template(GOV, 1, missing)
            .unwrap_err()
            .contains("artifact not found"));

        // nor claim a different wasm name than the artifact it pins
        let mut renamed = entry.template.clone();
        renamed.id = "tpl_g3".to_string();
        renamed.wasm_name = "other".to_string();
        assert!(provision::add_template(GOV, 1, renamed)
            .unwrap_err()
            .contains("belongs to wasm"));

        assert!(provision::add_template(GOV, 1, entry.template.clone())
            .unwrap_err()
            .contains("already exists"));

        provision::finish_pool_create(id, Principal::from_slice(&[1, 9]), 1).unwrap();
        assert!(provision::remove_template(id)
            .unwrap_err()
            .contains("still owns"));
    }

    #[test]
    fn publishing_a_newer_wasm_does_not_move_an_approved_template() {
        let id = "tpl_h";
        let entry = seed_template(id);
        let pinned = entry.template.artifact_hash;
        provision::finish_pool_create(id, Principal::from_slice(&[1, 4]), 1).unwrap();
        provision::reserve(10, &reserve_req(id, &entry, 20)).unwrap();

        // governance publishes a newer version of the same wasm name
        let newer = vec![7u8; 32];
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
            false,
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
        match provision::begin_install(20, &req).unwrap() {
            provision::InstallPlan::Install { wasm, .. } => {
                let resolved: ByteArray<32> = sha256(&wasm.wasm).into();
                assert_eq!(resolved, pinned, "install must use the pinned artifact");
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
}

/// Provisioning: governance-approved templates, a pre-created canister pool and
/// request-id-keyed idempotent reservation, installation and release.
///
/// The pool exists because the management canister cannot be asked "which
/// canister did you create for my request id?". A create whose response is lost
/// may leave a canister nobody knows about, so creation is kept out of any paid
/// flow: a caller reserves an already-recorded canister, and every later retry
/// installs onto that same principal.
pub mod provision {
    use super::*;
    use ic_cose_types::types::wasm::{
        InstallRequest, ReserveRequest, MAX_REQUEST_TTL_MS, PROVISION_CONTROLLERS,
    };

    /// How long a released request id stays rejectable after its canister went
    /// back to the pool. Covers the longest cross-canister call plus margin.
    pub const RELEASE_TOMBSTONE_TTL_MS: u64 = 24 * 3600 * 1000;
    /// Bounded ring of release tombstones kept per template.
    pub const MAX_RELEASE_TOMBSTONES: u32 = 4096;

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
    ) -> Result<ProvisionTemplateInfo, String> {
        template.validate()?;
        let wasm = wasm::get_wasm(&template.artifact_hash)
            .ok_or_else(|| "NotFound: artifact not found, add the wasm first".to_string())?;
        if wasm.name != template.wasm_name {
            return Err(format!(
                "artifact belongs to wasm {}, not {}",
                wasm.name, template.wasm_name
            ));
        }
        if wasm.encoding != template.encoding {
            return Err("encoding does not match the stored artifact".to_string());
        }

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
            if r.contains_key(&id) {
                return Err(format!("provision template {} already exists", id));
            }
            let info = entry.clone().into_info();
            r.insert(id, entry);
            Ok(info)
        })
    }

    /// Removing a template is only safe while nothing depends on it: any pooled
    /// canister would otherwise lose the settings it must be validated against.
    pub fn remove_template(id: &str) -> Result<(), String> {
        TEMPLATE_STORE.with_borrow_mut(|r| {
            let entry = r
                .get(&id.to_string())
                .ok_or_else(|| format!("NotFound: provision template {} not found", id))?;
            if entry.available + entry.reserved + entry.installed > 0 {
                return Err(format!(
                    "provision template {} still owns {} canisters",
                    id,
                    entry.available + entry.reserved + entry.installed
                ));
            }
            if entry.pool_status != PoolStatus::Idle {
                return Err(format!(
                    "provision template {} pool is {:?}",
                    id, entry.pool_status
                ));
            }
            r.remove(&id.to_string());
            Ok(())
        })
    }

    pub fn get_template(id: &str) -> Option<ProvisionTemplateInfo> {
        TEMPLATE_STORE.with_borrow(|r| r.get(&id.to_string()).map(|e| e.into_info()))
    }

    pub fn list_templates() -> Vec<ProvisionTemplateInfo> {
        TEMPLATE_STORE.with_borrow(|r| r.iter().map(|e| e.value().into_info()).collect())
    }

    fn load_template(id: &str, hash: &ByteArray<32>) -> Result<TemplateEntry, String> {
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
        with_template_mut(id, |entry| {
            entry.pool_status = PoolStatus::Idle;
            entry.available = entry.available.saturating_add(1);
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
        with_template_mut(id, |entry| {
            if entry.pool_status != PoolStatus::CreateUnknown {
                return Err(format!(
                    "provision template {} pool is {:?}, nothing to reconcile",
                    id, entry.pool_status
                ));
            }
            entry.pool_status = PoolStatus::Idle;
            if found.is_some() {
                entry.available = entry.available.saturating_add(1);
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

    pub fn list_pool(id: &str) -> Vec<PoolCanisterInfo> {
        POOL_STORE.with_borrow(|r| {
            r.range(ops::RangeFrom {
                start: PoolKey(id.to_string(), Principal::management_canister()),
            })
            .take_while(|e| e.key().0 == id)
            .map(|e| PoolCanisterInfo {
                canister: e.key().1,
                state: e.value().state,
                created_at: e.value().created_at,
                request_id: e.value().request_id,
            })
            .collect()
        })
    }

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

    fn reservation_receipt(
        request_id: ByteArray<32>,
        canister: Principal,
        entry: &TemplateEntry,
        reserved_at: u64,
    ) -> ReservationReceipt {
        ReservationReceipt {
            request_id,
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
    pub fn reserve(now_ms: u64, req: &ReserveRequest) -> Result<ReservationReceipt, String> {
        let entry = load_template(&req.provision_template_id, &req.provision_template_hash)?;

        if let Some(existing) = REQUEST_STORE.with_borrow(|r| r.get(&req.request_id)) {
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
            return Ok(reservation_receipt(
                req.request_id,
                existing.canister,
                &entry,
                existing.created_at,
            ));
        }

        let canister = take_available(&req.provision_template_id).ok_or_else(|| {
            format!(
                "no available canister in the pool of provision template {}",
                req.provision_template_id
            )
        })?;

        POOL_STORE.with_borrow_mut(|r| {
            r.insert(
                PoolKey(req.provision_template_id.clone(), canister),
                PoolCanister {
                    state: PoolCanisterState::Reserved,
                    created_at: now_ms,
                    request_id: Some(req.request_id),
                },
            )
        });
        with_template_mut(&req.provision_template_id, |e| {
            e.available = e.available.saturating_sub(1);
            e.reserved = e.reserved.saturating_add(1);
            Ok(())
        })?;
        REQUEST_STORE.with_borrow_mut(|r| {
            r.insert(
                *req.request_id,
                ProvisionRequest {
                    stage: ProvisionStage::Reserved,
                    canister,
                    wasm_name: entry.template.wasm_name.clone(),
                    template_id: Some(entry.template.id.clone()),
                    template_hash: Some(entry.hash),
                    artifact_hash: entry.template.artifact_hash,
                    expected_module_hash: entry.template.expected_module_hash,
                    module_hash: None,
                    prev_module_hash: None,
                    args_hash: None,
                    provision_spec_hash: None,
                    error: None,
                    created_at: now_ms,
                    updated_at: now_ms,
                },
            )
        });

        Ok(reservation_receipt(
            req.request_id,
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
            canister: Principal,
            wasm: Wasm,
            expected_module_hash: ByteArray<32>,
            controllers: Vec<Principal>,
        },
    }

    /// Validates an install request against its reservation and marks it
    /// `InstallPending` before any outcall.
    pub fn begin_install(now_ms: u64, req: &InstallRequest) -> Result<InstallPlan, String> {
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
        if sha256(&req.init_args) != *req.init_args_hash {
            return Err("init_args_hash does not match init_args".to_string());
        }

        let existing = REQUEST_STORE
            .with_borrow(|r| r.get(&req.request_id))
            .ok_or_else(|| "NotFound: reserve_canister must be called first".to_string())?;
        if existing.stage == ProvisionStage::Released {
            return Err("request has been released and cannot be reused".to_string());
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
        // a retry must carry the same arguments, or it is a different request
        if let Some(prev) = existing.args_hash {
            if prev != req.init_args_hash {
                return Err("request id already bound to different init_args".to_string());
            }
        }
        if let Some(prev) = existing.provision_spec_hash {
            if prev != req.provision_spec_hash {
                return Err(
                    "request id already bound to a different provision_spec_hash".to_string(),
                );
            }
        }
        if existing.stage == ProvisionStage::Installed {
            return Ok(InstallPlan::AlreadyInstalled(Box::new(
                existing.into_receipt(req.request_id),
            )));
        }

        let wasm = wasm::get_wasm(&entry.template.artifact_hash).ok_or_else(|| {
            format!(
                "NotFound: artifact {} not found",
                hex::encode(entry.template.artifact_hash.as_ref())
            )
        })?;

        REQUEST_STORE.with_borrow_mut(|r| {
            let mut cur = existing;
            cur.stage = ProvisionStage::InstallPending;
            cur.args_hash = Some(req.init_args_hash);
            cur.provision_spec_hash = Some(req.provision_spec_hash);
            cur.error = None;
            cur.updated_at = now_ms;
            r.insert(*req.request_id, cur)
        });

        Ok(InstallPlan::Install {
            canister: req.canister,
            wasm,
            expected_module_hash: entry.template.expected_module_hash,
            controllers: entry.template.settings.controllers.clone(),
        })
    }

    pub fn finish_install(
        request_id: &ByteArray<32>,
        module_hash: ByteArray<32>,
        now_ms: u64,
    ) -> Result<ProvisionReceipt, String> {
        let (receipt, template_id, was_reserved) = REQUEST_STORE.with_borrow_mut(|r| {
            let mut cur = r
                .get(request_id)
                .ok_or_else(|| "NotFound: request not found".to_string())?;
            let was_reserved = cur.stage != ProvisionStage::Installed;
            cur.stage = ProvisionStage::Installed;
            cur.module_hash = Some(module_hash);
            cur.error = None;
            cur.updated_at = now_ms;
            let template_id = cur.template_id.clone();
            let canister = cur.canister;
            r.insert(**request_id, cur.clone());
            Ok::<_, String>((
                cur.into_receipt(*request_id),
                template_id.map(|t| (t, canister)),
                was_reserved,
            ))
        })?;

        if let (Some((id, canister)), true) = (template_id, was_reserved) {
            POOL_STORE.with_borrow_mut(|r| {
                let key = PoolKey(id.clone(), canister);
                if let Some(mut pc) = r.get(&key) {
                    pc.state = PoolCanisterState::Installed;
                    r.insert(key, pc);
                }
            });
            let _ = with_template_mut(&id, |e| {
                e.reserved = e.reserved.saturating_sub(1);
                e.installed = e.installed.saturating_add(1);
                Ok(())
            });
        }
        Ok(receipt)
    }

    pub fn fail_install(request_id: &ByteArray<32>, error: String, now_ms: u64) {
        REQUEST_STORE.with_borrow_mut(|r| {
            if let Some(mut cur) = r.get(request_id) {
                // an installed request stays installed: a later probe failing
                // does not undo the module already running
                if cur.stage != ProvisionStage::Installed {
                    cur.stage = ProvisionStage::Failed;
                }
                cur.error = Some(error);
                cur.updated_at = now_ms;
                r.insert(**request_id, cur);
            }
        });
    }

    /// Records an upgrade request keyed by `request_id`, or returns the receipt
    /// of an identical one that already completed.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_deployment(
        now_ms: u64,
        request_id: &ByteArray<32>,
        canister: Principal,
        wasm_name: &str,
        artifact_hash: ByteArray<32>,
        expected_module_hash: ByteArray<32>,
        expected_prev_module_hash: ByteArray<32>,
        args_hash: ByteArray<32>,
    ) -> Result<Option<ProvisionReceipt>, String> {
        if let Some(existing) = REQUEST_STORE.with_borrow(|r| r.get(request_id)) {
            if existing.canister != canister
                || existing.artifact_hash != artifact_hash
                || existing.expected_module_hash != expected_module_hash
                || existing.args_hash != Some(args_hash)
                || existing.prev_module_hash != Some(expected_prev_module_hash)
            {
                return Err("request id already bound to different parameters".to_string());
            }
            if existing.stage == ProvisionStage::Installed {
                return Ok(Some(existing.into_receipt(*request_id)));
            }
        }

        REQUEST_STORE.with_borrow_mut(|r| {
            let created_at = r.get(request_id).map(|c| c.created_at).unwrap_or(now_ms);
            r.insert(
                **request_id,
                ProvisionRequest {
                    stage: ProvisionStage::InstallPending,
                    canister,
                    wasm_name: wasm_name.to_string(),
                    template_id: None,
                    template_hash: None,
                    artifact_hash,
                    expected_module_hash,
                    module_hash: None,
                    prev_module_hash: Some(expected_prev_module_hash),
                    args_hash: Some(args_hash),
                    provision_spec_hash: None,
                    error: None,
                    created_at,
                    updated_at: now_ms,
                },
            )
        });
        Ok(None)
    }

    /// Returns a reserved canister to the pool.
    ///
    /// Only valid while the request never installed anything; the caller must
    /// have verified the canister is still empty and still carries the
    /// template's controllers.
    pub fn release(
        now_ms: u64,
        request_id: &ByteArray<32>,
        canister: Principal,
    ) -> Result<ReleaseReceipt, String> {
        let existing = REQUEST_STORE
            .with_borrow(|r| r.get(request_id))
            .ok_or_else(|| "NotFound: request not found".to_string())?;
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

        POOL_STORE.with_borrow_mut(|r| {
            let key = PoolKey(template_id.clone(), canister);
            if let Some(mut pc) = r.get(&key) {
                pc.state = PoolCanisterState::Available;
                pc.request_id = None;
                r.insert(key, pc);
            }
        });
        with_template_mut(&template_id, |e| {
            e.reserved = e.reserved.saturating_sub(1);
            e.available = e.available.saturating_add(1);
            Ok(())
        })?;
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
        with_template_mut(&template_id, |e| {
            e.tombstones = e.tombstones.saturating_add(1);
            Ok(())
        })?;
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
        let mut pruned = 0u32;
        loop {
            let count = TEMPLATE_STORE
                .with_borrow(|r| r.get(&template_id.to_string()).map(|e| e.tombstones))
                .unwrap_or(0);
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

    /// Controllers the template fixes for a reserved canister, so a release can
    /// verify the canister was not re-parented before returning it to the pool.
    pub fn expected_controllers(request_id: &ByteArray<32>) -> Result<Vec<Principal>, String> {
        let req = REQUEST_STORE
            .with_borrow(|r| r.get(request_id))
            .ok_or_else(|| "NotFound: request not found".to_string())?;
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
        CHUNK_STORE.with_borrow_mut(|r| r.insert(ChunkKey(caller, hash), chunk));
        Ok(hash)
    }

    pub fn take_chunks(caller: Principal, hashes: &[ByteArray<32>]) -> Result<Vec<u8>, String> {
        if hashes.is_empty() {
            return Err("chunk_hashes should not be empty".to_string());
        }
        CHUNK_STORE.with_borrow(|r| {
            let mut out: Vec<u8> = Vec::new();
            for h in hashes {
                let chunk = r.get(&ChunkKey(caller, *h)).ok_or_else(|| {
                    format!("NotFound: chunk {} not staged", hex::encode(h.as_ref()))
                })?;
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
                .range(ops::RangeFrom {
                    start: ChunkKey(caller, ByteArray::from([0u8; 32])),
                })
                .take_while(|e| e.key().0 == caller)
                .map(|e| e.key().clone())
                .collect();
            let n = keys.len() as u64;
            for k in keys {
                r.remove(&k);
            }
            n
        })
    }
}
