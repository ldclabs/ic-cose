use candid::Principal;
use cbor2::{from_reader, to_writer, Value};
use ic_cose_types::{
    cose::sha256,
    format_error,
    types::wasm::{AddWasmInput, DeploymentInfo, StateInfo},
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

#[derive(Clone, Deserialize, Serialize)]
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

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const WASM_MEMORY_ID: MemoryId = MemoryId::new(1);
const INSTALL_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(2);
const INSTALL_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(3);

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
