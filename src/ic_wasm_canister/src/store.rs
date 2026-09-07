use candid::Principal;
use cbor2::{from_slice, to_writer};
use ic_cose_types::{
    cose::sha256,
    format_error,
    types::wasm::{
        AddWasmInput, DeploymentInfo, PoolCanisterInfo, PoolCanisterState, PoolStatus,
        ProvisionReceipt, ProvisionStage, ProvisionTemplate, ProvisionTemplateInfo, ReleaseReceipt,
        ReservationReceipt, StateInfo, WasmEncoding, WasmMetadata,
    },
};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    StableBTreeMap, StableCell, StableLog, Storable,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Read,
    ops,
};

use crate::canister_memory::DefaultMemoryImpl;
use flate2::read::MultiGzDecoder;

type Memory = VirtualMemory<DefaultMemoryImpl>;
const CURRENT_SCHEMA_VERSION: u32 = 2;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_MODULE_BYTES: usize = 100 * 1024 * 1024;
const ARTIFACT_STORAGE_CHUNK_BYTES: usize = 1024 * 1024;
const WASM_HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";

fn from_cbor_bytes<T>(bytes: &[u8], context: &str) -> T
where
    T: DeserializeOwned,
{
    from_slice(bytes).unwrap_or_else(|err| panic!("failed to decode {context}: {err:?}"))
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct State {
    pub name: String,
    pub managers: BTreeSet<Principal>,
    /// Legacy heap indexes, consumed into stable indexes on the first upgrade
    /// to schema v2 and omitted from all subsequent snapshots.
    #[serde(default, skip_serializing)]
    pub latest_version: BTreeMap<String, ByteArray<32>>,
    #[serde(default, skip_serializing)]
    pub upgrade_path: HashMap<ByteArray<32>, ByteArray<32>>,
    #[serde(default, skip_serializing)]
    pub deployed_list: BTreeMap<Principal, (u64, ByteArray<32>)>,
    pub topup_threshold: u128,
    pub topup_amount: u128,
    pub governance_canister: Option<Principal>,
    #[serde(default)]
    pub canister_id: Option<Principal>,
    pub committers: BTreeSet<Principal>,
    /// Least-privilege role for the provisioning API: may reserve, install and
    /// release canisters from approved templates, nothing else.
    #[serde(default)]
    pub provisioners: BTreeSet<Principal>,
    /// Heap index over the stable pool inventory.
    ///
    /// A template retains installed canisters for auditability, so scanning the
    /// stable pool for every reservation would become linear in all historical
    /// installs. This bounded index contains only currently available entries.
    /// It is derived and can be rebuilt lazily after upgrading old state.
    #[serde(default, skip)]
    pub available_pool: BTreeMap<String, BTreeSet<Principal>>,
    /// Transient per-target serialization. Durable request attempts provide the
    /// recovery record; locks deliberately reset on upgrade.
    #[serde(default, skip)]
    pub active_operations: BTreeMap<Principal, OperationLock>,
    #[serde(default, skip)]
    pub topup_in_progress: bool,
    #[serde(default, skip)]
    pub low_wasm_memory: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OperationLock {
    pub request_id: ByteArray<32>,
    pub attempt: u64,
    pub started_at: u64,
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
    #[serde(default, rename = "mh", alias = "module_hash")]
    pub module_hash: Option<ByteArray<32>>,
}

impl Wasm {
    fn effective_encoding(&self) -> WasmEncoding {
        // Before encoding was recorded, gzip artifacts were stored with the
        // default Raw value. Match the management canister's magic-byte dispatch.
        if self.module_hash.is_none() {
            if self.wasm.starts_with(&[0x1f, 0x8b, 0x08]) {
                return WasmEncoding::Gzip;
            }
            if self.wasm.starts_with(WASM_HEADER) {
                return WasmEncoding::Raw;
            }
        }
        self.encoding
    }

    fn effective_module_hash(
        &self,
        artifact_hash: &ByteArray<32>,
    ) -> Result<ByteArray<32>, String> {
        self.module_hash
            .map(Ok)
            .unwrap_or_else(|| module_hash_from_artifact(&self.wasm, self.effective_encoding()))
            .or_else(|error| {
                // Old raw artifacts were keyed by exactly the bytes whose hash
                // the management canister reports. Preserve their deploy index
                // even if a newer parser rejects a once-supported feature.
                (self.effective_encoding() == WasmEncoding::Raw
                    && self.wasm.starts_with(WASM_HEADER))
                .then_some(*artifact_hash)
                .ok_or(error)
            })
    }

    pub fn metadata(&self, artifact_hash: ByteArray<32>) -> Result<WasmMetadata, String> {
        Ok(WasmMetadata {
            name: self.name.clone(),
            created_at: self.created_at,
            created_by: self.created_by,
            description: self.description.clone(),
            hash: artifact_hash,
            module_hash: self.effective_module_hash(&artifact_hash)?,
            wasm_size: self.wasm.len() as u64,
            encoding: self.effective_encoding(),
        })
    }
}

fn module_hash_from_artifact(
    artifact: &[u8],
    encoding: WasmEncoding,
) -> Result<ByteArray<32>, String> {
    if artifact.len() > MAX_ARTIFACT_BYTES {
        return Err(format!(
            "artifact of {} bytes exceeds the limit {}",
            artifact.len(),
            MAX_ARTIFACT_BYTES
        ));
    }
    match encoding {
        WasmEncoding::Raw => {
            validate_wasm_module(artifact, "raw artifact")?;
            Ok(ByteArray::from(sha256(artifact)))
        }
        WasmEncoding::Gzip => {
            let mut decoder = MultiGzDecoder::new(artifact);
            let mut module = Vec::new();
            decoder
                .by_ref()
                .take((MAX_MODULE_BYTES + 1) as u64)
                .read_to_end(&mut module)
                .map_err(|err| format!("invalid gzip artifact: {err}"))?;
            if module.len() > MAX_MODULE_BYTES {
                return Err(format!(
                    "decoded module exceeds the limit {}",
                    MAX_MODULE_BYTES
                ));
            }
            validate_wasm_module(&module, "gzip artifact")?;
            Ok(ByteArray::from(sha256(&module)))
        }
    }
}

fn validate_wasm_module(module: &[u8], context: &str) -> Result<(), String> {
    if !module.starts_with(WASM_HEADER) {
        return Err(format!("{context} is not a WebAssembly module"));
    }
    wasmparser::Validator::new()
        .validate_all(module)
        .map_err(|err| format!("{context} contains invalid WebAssembly: {err}"))?;
    Ok(())
}

impl Storable for Wasm {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            self.wasm
                .len()
                .saturating_add(self.name.len())
                .saturating_add(self.description.len())
                .saturating_add(192),
        );
        to_writer(&self, &mut buf).expect("failed to encode Wasm data");
        buf
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = Vec::with_capacity(
            self.wasm
                .len()
                .saturating_add(self.name.len())
                .saturating_add(self.description.len())
                .saturating_add(192),
        );
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
    #[serde(default, rename = "m", alias = "module_hash")]
    pub module_hash: Option<ByteArray<32>>,
    #[serde(rename = "a", alias = "args")]
    pub args: ByteBuf,
    #[serde(default, rename = "ah", alias = "args_hash")]
    pub args_hash: Option<ByteArray<32>>,
    #[serde(default, rename = "as", alias = "args_size")]
    pub args_size: u64,
    #[serde(rename = "e", alias = "error")]
    pub error: Option<String>,
}

impl DeployLog {
    pub fn new(input: DeployLogInput<'_>) -> Self {
        Self {
            name: input.name,
            deploy_at: input.deploy_at,
            canister: input.canister,
            prev_hash: input.prev_hash,
            wasm_hash: input.artifact_hash,
            module_hash: input.module_hash,
            // Deployment arguments frequently contain secrets. New records
            // retain only a commitment and size; old records remain readable.
            args: ByteBuf::new(),
            args_hash: Some(ByteArray::from(sha256(input.args))),
            args_size: input.args.len() as u64,
            error: input.error,
        }
    }
}

pub struct DeployLogInput<'a> {
    pub name: String,
    pub deploy_at: u64,
    pub canister: Principal,
    pub prev_hash: ByteArray<32>,
    pub artifact_hash: ByteArray<32>,
    pub module_hash: Option<ByteArray<32>>,
    pub args: &'a [u8],
    pub error: Option<String>,
}

impl Storable for DeployLog {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            self.args
                .len()
                .saturating_add(self.name.len())
                .saturating_add(self.error.as_ref().map_or(0, String::len))
                .saturating_add(256),
        );
        to_writer(&self, &mut buf).expect("failed to encode DeployLog data");
        buf
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = Vec::with_capacity(
            self.args
                .len()
                .saturating_add(self.name.len())
                .saturating_add(self.error.as_ref().map_or(0, String::len))
                .saturating_add(256),
        );
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
    #[serde(default = "anonymous_principal", rename = "o")]
    pub owner: Principal,
    #[serde(default, rename = "x")]
    pub expires_at: u64,
    #[serde(default, rename = "at")]
    pub attempt: u64,
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
    #[serde(default, rename = "gs")]
    pub args_size: u64,
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
            owner: self.owner,
            expires_at: self.expires_at,
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

fn anonymous_principal() -> Principal {
    Principal::anonymous()
}

#[derive(Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct ReleaseKey(pub String, pub ByteArray<32>);

#[derive(Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct LogKey(pub String, pub u64);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentIndex {
    pub log_id: u64,
    pub artifact_hash: ByteArray<32>,
    pub module_hash: ByteArray<32>,
    pub wasm_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArtifactMetadata {
    pub name: String,
    pub created_at: u64,
    pub created_by: Principal,
    pub description: String,
    pub encoding: WasmEncoding,
    pub module_hash: ByteArray<32>,
    pub wasm_size: u64,
    pub chunks: u32,
}

impl ArtifactMetadata {
    fn public(&self, hash: ByteArray<32>) -> WasmMetadata {
        WasmMetadata {
            name: self.name.clone(),
            created_at: self.created_at,
            created_by: self.created_by,
            description: self.description.clone(),
            hash,
            module_hash: self.module_hash,
            wasm_size: self.wasm_size,
            encoding: self.encoding,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct ArtifactChunkKey(pub [u8; 32], pub u32);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompletedRequest {
    pub owner: Principal,
    pub completed_at: u64,
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
impl_cbor_storable!(ReleaseKey, "ReleaseKey data");
impl_cbor_storable!(LogKey, "LogKey data");
impl_cbor_storable!(DeploymentIndex, "DeploymentIndex data");
impl_cbor_storable!(ArtifactMetadata, "ArtifactMetadata data");
impl_cbor_storable!(ArtifactChunkKey, "ArtifactChunkKey data");
impl_cbor_storable!(CompletedRequest, "CompletedRequest data");

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
const RELEASE_PATH_MEMORY_ID: MemoryId = MemoryId::new(9);
const LATEST_MEMORY_ID: MemoryId = MemoryId::new(10);
const DEPLOYED_MEMORY_ID: MemoryId = MemoryId::new(11);
const SCHEMA_MEMORY_ID: MemoryId = MemoryId::new(12);
const LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(13);
const ARTIFACT_META_MEMORY_ID: MemoryId = MemoryId::new(14);
const ARTIFACT_CHUNK_MEMORY_ID: MemoryId = MemoryId::new(15);
const COMPLETED_REQUEST_MEMORY_ID: MemoryId = MemoryId::new(16);
const FORGOTTEN_DEPLOYMENT_MEMORY_ID: MemoryId = MemoryId::new(17);

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

    static RELEASE_PATH_STORE: RefCell<StableBTreeMap<ReleaseKey, [u8; 32], Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(RELEASE_PATH_MEMORY_ID)))
    );

    static LATEST_STORE: RefCell<StableBTreeMap<String, [u8; 32], Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(LATEST_MEMORY_ID)))
    );

    static DEPLOYED_STORE: RefCell<StableBTreeMap<Principal, DeploymentIndex, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(DEPLOYED_MEMORY_ID)))
    );

    static SCHEMA_STORE: RefCell<StableCell<u32, Memory>> = RefCell::new(
        StableCell::init(MEMORY_MANAGER.with_borrow(|m| m.get(SCHEMA_MEMORY_ID)), 0)
    );

    static LOG_INDEX_STORE: RefCell<StableBTreeMap<LogKey, u64, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(LOG_INDEX_MEMORY_ID)))
    );

    static ARTIFACT_META_STORE: RefCell<StableBTreeMap<[u8; 32], ArtifactMetadata, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(ARTIFACT_META_MEMORY_ID)))
    );

    static ARTIFACT_CHUNK_STORE: RefCell<StableBTreeMap<ArtifactChunkKey, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(ARTIFACT_CHUNK_MEMORY_ID)))
    );

    static COMPLETED_REQUEST_STORE: RefCell<StableBTreeMap<[u8; 32], CompletedRequest, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(COMPLETED_REQUEST_MEMORY_ID)))
    );

    // Explicit handoff/forget is not a missing-index failure. Only a controller's
    // successful adoption/deployment may lift this durable barrier.
    static FORGOTTEN_DEPLOYMENT_STORE: RefCell<StableBTreeMap<Principal, u8, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(FORGOTTEN_DEPLOYMENT_MEMORY_ID)))
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
                ic_cdk::api::debug_print(
                    "removed unsafe anonymous governance_canister during upgrade",
                );
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
                paths.sort_unstable_by(|left, right| {
                    left.0.cmp(&right.0).then(left.1.cmp(&right.1))
                });
                for (previous_artifact, next_artifact) in paths {
                    let Some(next) = WASM_STORE.with_borrow(|store| store.get(&*next_artifact))
                    else {
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
}

pub mod wasm {
    use super::*;

    /// Performs all synchronous checks for publishing an artifact and returns
    /// the hash under which it would be stored.
    pub fn validate_wasm(
        args: &AddWasmInput,
        force_prev_hash: Option<ByteArray<32>>,
    ) -> Result<ByteArray<32>, String> {
        validate_new_wasm(args, force_prev_hash, None).map(|validated| validated.artifact_hash)
    }

    struct ValidatedWasm {
        artifact_hash: ByteArray<32>,
        module_hash: ByteArray<32>,
        previous_module_hash: ByteArray<32>,
    }

    pub fn add_wasm(
        caller: Principal,
        now_ms: u64,
        args: AddWasmInput,
        force_prev_hash: Option<ByteArray<32>>,
        expected_hash: Option<ByteArray<32>>,
    ) -> Result<ByteArray<32>, String> {
        let validated = validate_new_wasm(&args, force_prev_hash, expected_hash)?;
        let hash = validated.artifact_hash;
        let encoding = args.encoding.unwrap_or_default();
        let name = args.name.clone();
        let wasm = args.wasm.into_vec();
        let chunks = wasm.len().div_ceil(ARTIFACT_STORAGE_CHUNK_BYTES) as u32;
        ARTIFACT_CHUNK_STORE.with_borrow_mut(|store| {
            for (index, chunk) in wasm.chunks(ARTIFACT_STORAGE_CHUNK_BYTES).enumerate() {
                store.insert(ArtifactChunkKey(*hash, index as u32), chunk.to_vec());
            }
        });
        ARTIFACT_META_STORE.with_borrow_mut(|store| {
            store.insert(
                *hash,
                ArtifactMetadata {
                    name: args.name,
                    created_at: now_ms,
                    created_by: caller,
                    description: args.description,
                    encoding,
                    module_hash: validated.module_hash,
                    wasm_size: wasm.len() as u64,
                    chunks,
                },
            );
        });
        RELEASE_PATH_STORE.with_borrow_mut(|r| {
            r.insert(
                ReleaseKey(name.clone(), validated.previous_module_hash),
                *hash,
            );
        });
        LATEST_STORE.with_borrow_mut(|r| {
            r.insert(name, *hash);
        });
        Ok(hash)
    }

    fn validate_new_wasm(
        args: &AddWasmInput,
        force_prev_hash: Option<ByteArray<32>>,
        expected_hash: Option<ByteArray<32>>,
    ) -> Result<ValidatedWasm, String> {
        ic_cose_types::validate_str(&args.name)?;
        if args.description.len() > ic_cose_types::types::MAX_DESC_SIZE {
            return Err(format!(
                "description length exceeds the limit {}",
                ic_cose_types::types::MAX_DESC_SIZE
            ));
        }
        let encoding = args.encoding.unwrap_or_default();
        let hash: ByteArray<32> = sha256(&args.wasm).into();
        let current_module_hash = module_hash_from_artifact(&args.wasm, encoding)?;
        if let Some(expected_hash) = expected_hash {
            if hash != expected_hash {
                return Err(format!(
                    "artifact hash {} does not match the declared {}",
                    hex::encode(hash.as_ref()),
                    hex::encode(expected_hash.as_ref())
                ));
            }
        }
        if WASM_STORE.with_borrow(|m| m.contains_key(&hash))
            || ARTIFACT_META_STORE.with_borrow(|m| m.contains_key(&*hash))
        {
            return Err("wasm already exists".to_string());
        }
        let latest = LATEST_STORE.with_borrow(|r| r.get(&args.name).map(ByteArray::from));
        if let Some(force_prev_hash) = force_prev_hash {
            let expected = latest.unwrap_or_else(|| ByteArray::from([0u8; 32]));
            if force_prev_hash != expected {
                return Err(format!(
                    "force_prev_hash is stale: latest is {}",
                    hex::encode(expected.as_ref())
                ));
            }
        }
        let previous_artifact = force_prev_hash
            .or(latest)
            .unwrap_or_else(|| ByteArray::from([0u8; 32]));
        let previous_module_hash = if *previous_artifact == [0u8; 32] {
            ByteArray::from([0u8; 32])
        } else {
            module_hash(&previous_artifact)?
        };
        if *previous_artifact != [0u8; 32] && current_module_hash == previous_module_hash {
            return Err(
                "new artifact installs the same module as the current latest version".to_string(),
            );
        }
        if RELEASE_PATH_STORE
            .with_borrow(|r| r.contains_key(&ReleaseKey(args.name.clone(), current_module_hash)))
        {
            return Err("module hash already appears in this wasm's release history".to_string());
        }
        if RELEASE_PATH_STORE
            .with_borrow(|r| r.contains_key(&ReleaseKey(args.name.clone(), previous_module_hash)))
        {
            return Err("the previous module already has a successor".to_string());
        }
        Ok(ValidatedWasm {
            artifact_hash: hash,
            module_hash: current_module_hash,
            previous_module_hash,
        })
    }

    #[cfg(test)]
    pub fn get_latest(name: &str) -> Result<(ByteArray<32>, Wasm), String> {
        let hash = LATEST_STORE
            .with_borrow(|r| r.get(&name.to_string()).map(ByteArray::from))
            .ok_or_else(|| format!("NotFound: {} not found", name))?;
        get_wasm(&hash)
            .map(|wasm| (hash, wasm))
            .ok_or_else(|| "NotFound: latest wasm not found".to_string())
    }

    pub fn get_latest_metadata(name: &str) -> Result<(ByteArray<32>, WasmMetadata), String> {
        let hash = LATEST_STORE
            .with_borrow(|r| r.get(&name.to_string()).map(ByteArray::from))
            .ok_or_else(|| format!("NotFound: {} not found", name))?;
        Ok((hash, get_metadata(&hash)?))
    }

    pub fn get_wasm(hash: &ByteArray<32>) -> Option<Wasm> {
        if let Some(metadata) = ARTIFACT_META_STORE.with_borrow(|r| r.get(&**hash)) {
            let mut bytes = Vec::with_capacity(metadata.wasm_size as usize);
            for index in 0..metadata.chunks {
                let chunk = ARTIFACT_CHUNK_STORE
                    .with_borrow(|r| r.get(&ArtifactChunkKey(**hash, index)))?;
                bytes.extend_from_slice(&chunk);
            }
            if bytes.len() as u64 != metadata.wasm_size {
                return None;
            }
            return Some(Wasm {
                name: metadata.name,
                created_at: metadata.created_at,
                created_by: metadata.created_by,
                description: metadata.description,
                wasm: ByteBuf::from(bytes),
                encoding: metadata.encoding,
                module_hash: Some(metadata.module_hash),
            });
        }
        WASM_STORE.with_borrow(|r| r.get(hash)).map(|mut wasm| {
            wasm.encoding = wasm.effective_encoding();
            wasm
        })
    }

    pub fn get_metadata(hash: &ByteArray<32>) -> Result<WasmMetadata, String> {
        if let Some(metadata) = ARTIFACT_META_STORE.with_borrow(|r| r.get(&**hash)) {
            return Ok(metadata.public(*hash));
        }
        WASM_STORE
            .with_borrow(|r| r.get(hash))
            .ok_or_else(|| "NotFound: wasm not found".to_string())?
            .metadata(*hash)
    }

    pub fn is_legacy_artifact(hash: &ByteArray<32>) -> bool {
        !ARTIFACT_META_STORE.with_borrow(|store| store.contains_key(&**hash))
            && WASM_STORE.with_borrow(|store| store.contains_key(hash))
    }

    pub fn module_hash(hash: &ByteArray<32>) -> Result<ByteArray<32>, String> {
        if let Some(metadata) = ARTIFACT_META_STORE.with_borrow(|r| r.get(&**hash)) {
            return Ok(metadata.module_hash);
        }
        let wasm = WASM_STORE
            .with_borrow(|r| r.get(hash))
            .ok_or_else(|| "NotFound: wasm not found".to_string())?;
        wasm.effective_module_hash(hash)
    }

    pub fn get_chunk(hash: &ByteArray<32>, offset: usize, take: usize) -> Result<Vec<u8>, String> {
        if let Some(metadata) = ARTIFACT_META_STORE.with_borrow(|r| r.get(&**hash)) {
            let size = usize::try_from(metadata.wasm_size)
                .map_err(|_| "artifact size exceeds usize".to_string())?;
            if offset > size {
                return Err("offset exceeds artifact size".to_string());
            }
            let end = offset.saturating_add(take).min(size);
            let mut out = Vec::with_capacity(end.saturating_sub(offset));
            let mut cursor = offset;
            while cursor < end {
                let index = cursor / ARTIFACT_STORAGE_CHUNK_BYTES;
                let within = cursor % ARTIFACT_STORAGE_CHUNK_BYTES;
                let chunk = ARTIFACT_CHUNK_STORE
                    .with_borrow(|r| r.get(&ArtifactChunkKey(**hash, index as u32)))
                    .ok_or_else(|| "artifact chunk is missing".to_string())?;
                if within >= chunk.len() {
                    return Err("artifact chunk is truncated".to_string());
                }
                let available = chunk.len().saturating_sub(within);
                let count = available.min(end - cursor);
                out.extend_from_slice(&chunk[within..within + count]);
                cursor += count;
            }
            return Ok(out);
        }
        let wasm = WASM_STORE
            .with_borrow(|r| r.get(hash))
            .ok_or_else(|| "NotFound: wasm not found".to_string())?;
        if offset > wasm.wasm.len() {
            return Err("offset exceeds artifact size".to_string());
        }
        let end = offset.saturating_add(take).min(wasm.wasm.len());
        Ok(wasm.wasm[offset..end].to_vec())
    }

    pub fn storage_chunk_count(hash: &ByteArray<32>) -> Result<u32, String> {
        let metadata = get_metadata(hash)?;
        Ok((metadata.wasm_size as usize).div_ceil(ARTIFACT_STORAGE_CHUNK_BYTES) as u32)
    }

    pub fn storage_chunk(hash: &ByteArray<32>, index: u32) -> Result<Vec<u8>, String> {
        let offset = (index as usize)
            .checked_mul(ARTIFACT_STORAGE_CHUNK_BYTES)
            .ok_or_else(|| "artifact chunk offset overflowed".to_string())?;
        get_chunk(hash, offset, ARTIFACT_STORAGE_CHUNK_BYTES)
    }

    pub fn list_legacy_artifacts(prev: Option<ByteArray<32>>, take: usize) -> Vec<ByteArray<32>> {
        WASM_STORE.with_borrow(|r| {
            let lower = prev
                .map(|hash| std::ops::Bound::Excluded(*hash))
                .unwrap_or(std::ops::Bound::Unbounded);
            r.keys_range((lower, std::ops::Bound::Unbounded))
                .take(take)
                .map(ByteArray::from)
                .collect()
        })
    }

    pub fn migrate_legacy_artifact(hash: &ByteArray<32>) -> Result<bool, String> {
        if ARTIFACT_META_STORE.with_borrow(|r| r.contains_key(&**hash)) {
            return Ok(false);
        }
        let legacy = WASM_STORE
            .with_borrow(|r| r.get(hash))
            .ok_or_else(|| "NotFound: legacy artifact not found".to_string())?;
        let module_hash = legacy.effective_module_hash(hash)?;
        let encoding = legacy.effective_encoding();
        let wasm = legacy.wasm.into_vec();
        let chunks = wasm.len().div_ceil(ARTIFACT_STORAGE_CHUNK_BYTES) as u32;
        ARTIFACT_CHUNK_STORE.with_borrow_mut(|store| {
            for (index, chunk) in wasm.chunks(ARTIFACT_STORAGE_CHUNK_BYTES).enumerate() {
                store.insert(ArtifactChunkKey(**hash, index as u32), chunk.to_vec());
            }
        });
        ARTIFACT_META_STORE.with_borrow_mut(|store| {
            store.insert(
                **hash,
                ArtifactMetadata {
                    name: legacy.name,
                    created_at: legacy.created_at,
                    created_by: legacy.created_by,
                    description: legacy.description,
                    encoding,
                    module_hash,
                    wasm_size: wasm.len() as u64,
                    chunks,
                },
            );
        });
        WASM_STORE.with_borrow_mut(|store| {
            store.remove(hash);
        });
        Ok(true)
    }

    pub fn validate_remove_wasm(hash: &ByteArray<32>) -> Result<(), String> {
        if get_metadata(hash).is_err() {
            return Err("NotFound: wasm not found".to_string());
        }
        if LATEST_STORE.with_borrow(|r| r.iter().any(|entry| entry.value() == **hash)) {
            return Err("cannot remove a latest artifact".to_string());
        }
        if RELEASE_PATH_STORE.with_borrow(|r| r.iter().any(|entry| entry.value() == **hash)) {
            return Err("cannot remove an artifact referenced by a release path".to_string());
        }
        if TEMPLATE_STORE.with_borrow(|r| {
            r.iter()
                .any(|entry| entry.value().template.artifact_hash == *hash)
        }) {
            return Err("cannot remove an artifact referenced by a template".to_string());
        }
        if DEPLOYED_STORE
            .with_borrow(|r| r.iter().any(|entry| entry.value().artifact_hash == *hash))
        {
            return Err("cannot remove an artifact referenced by a deployment".to_string());
        }
        if REQUEST_STORE.with_borrow(|r| r.iter().any(|entry| entry.value().artifact_hash == *hash))
        {
            return Err("cannot remove an artifact referenced by a request".to_string());
        }
        Ok(())
    }

    pub fn remove_wasm(hash: &ByteArray<32>) -> Result<(), String> {
        validate_remove_wasm(hash)?;
        if let Some(metadata) = ARTIFACT_META_STORE.with_borrow_mut(|r| r.remove(&**hash)) {
            ARTIFACT_CHUNK_STORE.with_borrow_mut(|r| {
                for index in 0..metadata.chunks {
                    r.remove(&ArtifactChunkKey(**hash, index));
                }
            });
        } else {
            WASM_STORE.with_borrow_mut(|r| {
                r.remove(hash);
            });
        }
        Ok(())
    }

    /// Resolves the wasm that follows `prev_hash` on the upgrade path.
    ///
    pub fn next_version_metadata(
        name: &str,
        prev_hash: ByteArray<32>,
    ) -> Result<(ByteArray<32>, WasmMetadata), String> {
        let hash = next_version_hash(name, prev_hash)?;
        Ok((hash, get_metadata(&hash)?))
    }

    fn next_version_hash(name: &str, prev_hash: ByteArray<32>) -> Result<ByteArray<32>, String> {
        ic_cose_types::validate_str(name)?;
        let key = ReleaseKey(name.to_string(), prev_hash);
        let hash = RELEASE_PATH_STORE
            .with_borrow(|r| r.get(&key).map(ByteArray::from))
            .or_else(|| {
                if *prev_hash != [0u8; 32] {
                    return None;
                }
                // The legacy global zero edge lost all but one wasm family.
                // Recover the first release deterministically from artifact
                // metadata and keep future publications on the v2 path.
                WASM_STORE.with_borrow(|r| {
                    r.iter()
                        .filter(|entry| entry.value().name == name)
                        .min_by_key(|entry| (entry.value().created_at, *entry.key()))
                        .map(|entry| ByteArray::from(*entry.key()))
                })
            })
            .ok_or_else(|| "no next version".to_string())?;
        let metadata = get_metadata(&hash)?;
        if metadata.name != name {
            return Err(format!(
                "next version {} of {} belongs to wasm {}, not {}",
                hex::encode(hash.as_ref()),
                hex::encode(prev_hash.as_ref()),
                metadata.name,
                name
            ));
        }
        Ok(hash)
    }

    pub fn add_log(log: DeployLog) -> Result<u64, String> {
        let name = log.name.clone();
        let id = INSTALL_LOGS.with(|r| r.borrow_mut().append(&log).map_err(format_error))?;
        LOG_INDEX_STORE.with_borrow_mut(|r| {
            r.insert(LogKey(name, id), id);
        });
        Ok(id)
    }

    pub fn rebuild_log_index(start: u64, take: usize) -> Result<u64, String> {
        let len = INSTALL_LOGS.with_borrow(|logs| logs.len());
        if start > len {
            return Err("log rebuild cursor exceeds log length".to_string());
        }
        let end = start.saturating_add(take as u64).min(len);
        for id in start..end {
            if let Some(log) = INSTALL_LOGS.with_borrow(|logs| logs.get(id)) {
                LOG_INDEX_STORE.with_borrow_mut(|index| {
                    index.insert(LogKey(log.name, id), id);
                });
            }
        }
        Ok(end)
    }

    pub fn commit_deployment(log: DeployLog) -> Result<u64, String> {
        let module_hash = log
            .module_hash
            .ok_or_else(|| "successful deployment log is missing module_hash".to_string())?;
        let canister = log.canister;
        let artifact_hash = log.wasm_hash;
        let wasm_name = log.name.clone();
        let log_id = add_log(log)?;
        state::record_deployment(
            canister,
            DeploymentIndex {
                log_id,
                artifact_hash,
                module_hash,
                wasm_name,
            },
        );
        Ok(log_id)
    }

    pub fn get_deployed_page(prev: Option<Principal>, take: usize) -> Vec<DeploymentInfo> {
        DEPLOYED_STORE.with_borrow(|deployed| {
            INSTALL_LOGS.with_borrow(|logs| {
                let lower = prev
                    .map(std::ops::Bound::Excluded)
                    .unwrap_or(std::ops::Bound::Unbounded);
                deployed
                    .range((lower, std::ops::Bound::Unbounded))
                    .filter_map(|entry| {
                        let deployment = entry.value();
                        logs.get(deployment.log_id).map(|log| {
                            let mut info = deployment_info_with_args(deployment.log_id, log);
                            info.args = None;
                            info.args_hash = None;
                            info
                        })
                    })
                    .take(take)
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

            if LOG_INDEX_STORE.with_borrow(|index| index.len()) == latest {
                return LOG_INDEX_STORE.with_borrow(|index| {
                    index
                        .range((
                            std::ops::Bound::Included(LogKey(name.to_string(), 0)),
                            std::ops::Bound::Excluded(LogKey(name.to_string(), prev)),
                        ))
                        .rev()
                        .take(take)
                        .filter_map(|entry| {
                            let id = entry.value();
                            logs.get(id).map(|log| deployment_info_with_args(id, log))
                        })
                        .collect()
                });
            }

            let mut idx = prev.saturating_sub(1);
            let mut res: Vec<DeploymentInfo> = Vec::with_capacity(take);
            while let Some(log) = logs.get(idx) {
                // entries for other wasm names are skipped, but the cursor must
                // still move or the loop never terminates
                if log.name == name {
                    res.push(deployment_info_with_args(idx, log));

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

    fn deployment_info_with_args(log_id: u64, log: DeployLog) -> DeploymentInfo {
        let legacy_args_hash = (!log.args.is_empty()).then(|| ByteArray::from(sha256(&log.args)));
        let args_size = if log.args_size == 0 {
            log.args.len() as u64
        } else {
            log.args_size
        };
        let args = (!log.args.is_empty() && log.args.len() <= 8 * 1024).then_some(log.args);
        DeploymentInfo {
            log_id,
            name: log.name,
            deploy_at: log.deploy_at,
            canister: log.canister,
            prev_hash: log.prev_hash,
            wasm_hash: log.wasm_hash,
            module_hash: log.module_hash,
            args,
            args_hash: log.args_hash.or(legacy_args_hash),
            args_size,
            error: log.error,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
        assert!(
            provision::finish_reconcile(&request_id, attempt, Some(rid(72)), &[], 60_005).is_err()
        );
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
        let controllers: BTreeSet<Principal> =
            template.settings.controllers.iter().copied().collect();
        if !required_controllers.is_subset(&controllers) {
            return Err(
                "template controllers must include this canister and governance".to_string(),
            );
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
            if state.canister_id.is_some_and(|canister_id| {
                !entry.template.settings.controllers.contains(&canister_id)
            }) {
                return Err(
                    "provision template does not include this canister as controller".to_string(),
                );
            }
            if state.governance_canister.is_some_and(|governance| {
                !entry.template.settings.controllers.contains(&governance)
            }) {
                return Err(
                    "provision template does not include governance as controller".to_string(),
                );
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
        add_available(id, canister);
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
            add_available(id, canister);
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
                    std::ops::Bound::Included(PoolKey(
                        id.to_string(),
                        Principal::management_canister(),
                    ))
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

    fn take_available(id: &str) -> Option<Principal> {
        if let Some(canister) = state::with(|s| {
            s.available_pool
                .get(id)
                .and_then(|canisters| canisters.first().copied())
        }) {
            return Some(canister);
        }

        // State written before this index was introduced has no heap index.
        // Rebuild the whole template once, then future reservations stay O(log n)
        // even though the stable audit inventory keeps every installed canister.
        let expected = TEMPLATE_STORE
            .with_borrow(|r| r.get(&id.to_string()).map(|entry| entry.available))
            .unwrap_or(0);
        if expected == 0 {
            return None;
        }
        let available: BTreeSet<Principal> = POOL_STORE.with_borrow(|r| {
            r.range(ops::RangeFrom {
                start: PoolKey(id.to_string(), Principal::management_canister()),
            })
            .take_while(|e| e.key().0 == id)
            .filter_map(|e| (e.value().state == PoolCanisterState::Available).then_some(e.key().1))
            .collect()
        });
        let canister = available.first().copied()?;
        state::with_mut(|s| {
            s.available_pool.insert(id.to_string(), available);
        });
        Some(canister)
    }

    fn add_available(id: &str, canister: Principal) {
        state::with_mut(|s| {
            s.available_pool
                .entry(id.to_string())
                .or_default()
                .insert(canister);
        });
    }

    fn remove_available(id: &str, canister: &Principal) {
        state::with_mut(|s| {
            let remove_entry = s
                .available_pool
                .get_mut(id)
                .map(|canisters| {
                    canisters.remove(canister);
                    canisters.is_empty()
                })
                .unwrap_or(false);
            if remove_entry {
                s.available_pool.remove(id);
            }
        });
    }

    // ----- requests -----

    pub fn get_receipt(request_id: &ByteArray<32>) -> Option<ProvisionReceipt> {
        REQUEST_STORE
            .with_borrow(|r| r.get(request_id))
            .map(|req| req.into_receipt(*request_id))
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
        remove_available(&req.provision_template_id, &canister);
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
        let (receipt, template_id, was_reserved) = REQUEST_STORE.with_borrow_mut(|r| {
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
                return Ok((cur.into_receipt(*request_id), None, false));
            }
            if cur.stage != ProvisionStage::InstallPending {
                return Err("request is not pending installation".to_string());
            }
            let was_reserved = true;
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
                r.remove(&key);
            });
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
            return commit_install_record(
                request_id,
                attempt,
                current.expected_module_hash,
                now_ms,
            );
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
        if pool.state != PoolCanisterState::Reserved || pool.request_id.as_ref() != Some(request_id)
        {
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
        add_available(&template_id, canister);
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
}
