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
    collections::{BTreeMap, BTreeSet},
    io::Read,
    ops,
};

use crate::canister_memory::{retired_map_len, DefaultMemoryImpl};
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

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct State {
    pub name: String,
    pub managers: BTreeSet<Principal>,
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

impl_cbor_storable!(State, "State data");

/// Returns the module hash the management canister reports once `artifact`
/// is installed. For a raw module that is the artifact hash itself.
fn module_hash_from_artifact(
    artifact: &[u8],
    artifact_hash: ByteArray<32>,
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
            Ok(artifact_hash)
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
/// Retired monolithic artifact store; must be empty before this version runs.
const LEGACY_WASM_MEMORY_ID: MemoryId = MemoryId::new(1);
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

pub mod state;

pub mod wasm;

#[cfg(test)]
mod test;

/// Provisioning: governance-approved templates, a pre-created canister pool and
/// request-id-keyed idempotent reservation, installation and release.
///
/// The pool exists because the management canister cannot be asked "which
/// canister did you create for my request id?". A create whose response is lost
/// may leave a canister nobody knows about, so creation is kept out of any paid
/// flow: a caller reserves an already-recorded canister, and every later retry
/// installs onto that same principal.
pub mod provision;
