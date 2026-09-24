use candid::Principal;
use cbor2::{from_slice, to_writer};
#[cfg(target_family = "wasm")]
use ic_canister_sig_creation::signature_map::LABEL_SIG;
use ic_canister_sig_creation::{
    signature_map::{CanisterSigInputs, SignatureMap},
    DELEGATION_SIG_DOMAIN,
};
#[cfg(target_family = "wasm")]
use ic_cdk::api::certified_data_set;
#[cfg(target_family = "wasm")]
use ic_certification::labeled_hash;
use ic_cose_chain_key::{classify_failure, cost_upper_bound, FailureKind, Operation};
use ic_cose_types::{
    cose::{
        cwt::{scope_claim, ClaimsSet},
        encrypt0::try_decode_encrypt0,
        format_error, mac3_256,
        sign1::{cose_sign1, EdDSA},
    },
    types::{namespace::*, setting::*, state::StateInfo, PublicKeyOutput, SchnorrAlgorithm},
    MILLISECONDS,
};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    StableBTreeMap, StableCell, Storable,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use sha3::Digest;
use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug},
    ops,
};

use crate::{
    canister_memory::{retired_map_len, DefaultMemoryImpl},
    chain_key::{
        derive_ecdsa_public_key, derive_schnorr_public_key, ecdsa_public_key, schnorr_public_key,
    },
    rand_bytes,
    vetkd::derivation_path_to_context,
};

const SESSION_EXPIRES_IN_MS: u64 = 1000 * 3600 * 24; // 1 day
const CURRENT_SCHEMA_VERSION: u32 = 2;
const MAX_NAMESPACE_PAGE_BYTES: usize = 1536 * 1024;
const MAX_NAMESPACE_ROLE_PRINCIPALS: usize = 4_000;
const MAX_NAMESPACE_FIXED_DELEGATORS: usize = 5_000;
const MAX_SIGNATURE_INTENTS: u64 = 4_096;
/// Namespace members live in the ACL stores. Version 0 marked records whose
/// members were still embedded; 0.11 migrated them and this version refuses
/// to start while any remain.
const ACL_VERSION: u8 = 1;

fn legacy_vetkd_context_version() -> u8 {
    1
}

fn identity_cose_algorithm(algorithm: SchnorrAlgorithm) -> Result<i64, String> {
    match algorithm {
        SchnorrAlgorithm::Ed25519 => Ok(EdDSA),
        SchnorrAlgorithm::Bip340secp256k1 => Err(
            "BIP340 identity tokens are unsupported: COSE ES256K identifies ECDSA, not Schnorr"
                .to_string(),
        ),
    }
}

fn certify_signature_root() {
    #[cfg(target_family = "wasm")]
    certified_data_set(labeled_hash(
        LABEL_SIG,
        &SIGNATURES.with_borrow(|sigs| sigs.root_hash()),
    ));
}

fn signature_intent_id(seed: &[u8], message: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(b"ic-cose:canister-signature-intent:v1");
    hasher.update((seed.len() as u64).to_be_bytes());
    hasher.update(seed);
    hasher.update((message.len() as u64).to_be_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

fn canister_time_ns() -> u64 {
    #[cfg(target_family = "wasm")]
    {
        ic_cdk::api::time()
    }
    #[cfg(not(target_family = "wasm"))]
    {
        0
    }
}

type Memory = VirtualMemory<DefaultMemoryImpl>;

fn from_cbor_bytes<T>(bytes: &[u8], context: &str) -> T
where
    T: DeserializeOwned,
{
    from_slice(bytes).unwrap_or_else(|err| panic!("failed to decode {context}: {err:?}"))
}

fn to_cbor_bytes<T>(value: &T, capacity: usize, context: &str) -> Vec<u8>
where
    T: Serialize,
{
    let mut buf = Vec::with_capacity(capacity);
    to_writer(value, &mut buf).unwrap_or_else(|err| panic!("failed to encode {context}: {err:?}"));
    buf
}

/// Implements CBOR `Storable` for `$ty`, pre-sizing the buffer with `$hint`.
macro_rules! impl_cbor_storable {
    ($ty:ty, $ctx:literal, |$value:ident| $hint:expr) => {
        impl Storable for $ty {
            const BOUND: Bound = Bound::Unbounded;

            fn into_bytes(self) -> Vec<u8> {
                self.to_bytes().into_owned()
            }

            fn to_bytes(&self) -> Cow<'_, [u8]> {
                let $value = self;
                Cow::Owned(to_cbor_bytes(self, $hint, $ctx))
            }

            fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
                from_cbor_bytes(&bytes, $ctx)
            }
        }
    };
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct State {
    #[serde(rename = "n")]
    pub name: String,
    #[serde(rename = "ek")]
    pub ecdsa_key_name: String,
    #[serde(rename = "ep")]
    pub ecdsa_public_key: Option<PublicKeyOutput>,
    #[serde(rename = "sk")]
    pub schnorr_key_name: String,
    #[serde(rename = "sep")]
    pub schnorr_ed25519_public_key: Option<PublicKeyOutput>,
    #[serde(rename = "ssp")]
    pub schnorr_secp256k1_public_key: Option<PublicKeyOutput>,
    #[serde(rename = "vk")]
    pub vetkd_key_name: String,
    #[serde(rename = "m")]
    pub managers: BTreeSet<Principal>, // managers can read and write namespaces, not settings
    // auditors can read and list namespaces and settings info even if it is private
    #[serde(rename = "a")]
    pub auditors: BTreeSet<Principal>,
    #[serde(rename = "aa")]
    pub allowed_apis: BTreeSet<String>, // allowed APIs
    #[serde(rename = "s")]
    pub subnet_size: u64, // legacy informational field
    #[serde(rename = "f")]
    pub freezing_threshold: u64, // freezing writing threshold in cycles
    #[serde(default, rename = "iv")]
    pub init_vector: ByteArray<32>, // should not be exposed
    #[serde(default, rename = "gov")]
    pub governance_canister: Option<Principal>,
    /// Version 1 hashed concatenated context components. Version 2 uses a
    /// length-delimited encoding and is the default for new installations.
    #[serde(default = "legacy_vetkd_context_version", rename = "vcv")]
    pub vetkd_context_version: u8,
    #[serde(default, skip)]
    pub low_wasm_memory: bool,
}

impl State {
    pub fn to_info(&self, with_keys: bool) -> StateInfo {
        let key = |key: &Option<PublicKeyOutput>| key.clone().filter(|_| with_keys);
        StateInfo {
            name: self.name.clone(),
            ecdsa_key_name: self.ecdsa_key_name.clone(),
            schnorr_key_name: self.schnorr_key_name.clone(),
            vetkd_key_name: self.vetkd_key_name.clone(),
            managers: self.managers.clone(),
            auditors: self.auditors.clone(),
            allowed_apis: self.allowed_apis.clone(),
            namespace_total: 0,
            subnet_size: self.subnet_size,
            freezing_threshold: self.freezing_threshold,
            ecdsa_public_key: key(&self.ecdsa_public_key),
            schnorr_ed25519_public_key: key(&self.schnorr_ed25519_public_key),
            schnorr_secp256k1_public_key: key(&self.schnorr_secp256k1_public_key),
            governance_canister: self.governance_canister,
            vetkd_context_version: self.vetkd_context_version,
            low_wasm_memory: self.low_wasm_memory,
        }
    }
}

/// Namespace record. Its managers, auditors, users and fixed-identity
/// delegators live in [`ACL_STORE`] and [`FIXED_IDENTITY_STORE`]; only their
/// counts are kept here, so rewriting the record stays cheap.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Namespace {
    #[serde(rename = "d")]
    pub desc: String,
    #[serde(rename = "ca")]
    pub created_at: u64, // unix timestamp in milliseconds
    #[serde(rename = "ua")]
    pub updated_at: u64, // unix timestamp in milliseconds
    #[serde(rename = "mp")]
    pub max_payload_size: u64, // max payload size in bytes
    #[serde(rename = "pb")]
    pub payload_bytes_total: u64, // total payload size in bytes
    #[serde(rename = "s")]
    pub status: i8, // -1: archived; 0: readable and writable; 1: readonly
    #[serde(rename = "v")]
    pub visibility: u8, // 0: private; 1: public
    #[serde(rename = "g")]
    pub gas_balance: u128, // namespace cycles budget
    #[serde(default, rename = "se")]
    pub session_expires_in_ms: u64, // session expires in milliseconds
    #[serde(default, rename = "av")]
    pub acl_version: u8,
    #[serde(default, rename = "mc")]
    pub manager_count: u32,
    #[serde(default, rename = "ac")]
    pub auditor_count: u32,
    #[serde(default, rename = "uc")]
    pub user_count: u32,
    #[serde(default, rename = "fc")]
    pub fixed_delegator_count: u32,
}

const ROLE_MANAGER: u8 = 0;
const ROLE_AUDITOR: u8 = 1;
const ROLE_USER: u8 = 2;

pub enum NamespaceReadPermission {
    Full,
    User,
    None,
}

fn acl_contains(namespace: &str, role: u8, principal: &Principal) -> bool {
    principal != &Principal::anonymous()
        && ACL_STORE.with_borrow(|store| {
            store.contains_key(&AclKey(namespace.to_string(), role, *principal))
        })
}

impl Namespace {
    /// Conservative size of this namespace's info with all members embedded.
    fn info_size_hint(&self) -> usize {
        let role_principals = self
            .manager_count
            .saturating_add(self.auditor_count)
            .saturating_add(self.user_count) as usize;
        256usize
            .saturating_add(self.desc.len())
            .saturating_add(role_principals.saturating_mul(Principal::MAX_LENGTH_IN_BYTES + 68))
            // One fixed-identity name may exist per delegator. Account for its
            // maximum validated length as a conservative response-size bound.
            .saturating_add(
                (self.fixed_delegator_count as usize)
                    .saturating_mul(Principal::MAX_LENGTH_IN_BYTES + 68 + 64),
            )
    }

    fn role_count(&self, role: u8) -> u32 {
        match role {
            ROLE_MANAGER => self.manager_count,
            ROLE_AUDITOR => self.auditor_count,
            _ => self.user_count,
        }
    }

    fn set_role_count(&mut self, role: u8, count: u32) {
        match role {
            ROLE_MANAGER => self.manager_count = count,
            ROLE_AUDITOR => self.auditor_count = count,
            _ => self.user_count = count,
        }
    }

    /// Namespace info without members; see [`ns::namespace_info`].
    pub fn to_info(&self, name: String) -> NamespaceInfo {
        NamespaceInfo {
            name,
            desc: self.desc.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            max_payload_size: self.max_payload_size,
            payload_bytes_total: self.payload_bytes_total,
            status: self.status,
            visibility: self.visibility,
            managers: BTreeSet::new(),
            auditors: BTreeSet::new(),
            users: BTreeSet::new(),
            manager_count: self.manager_count,
            auditor_count: self.auditor_count,
            user_count: self.user_count,
            fixed_delegator_count: self.fixed_delegator_count,
            gas_balance: self.gas_balance,
            fixed_id_names: BTreeMap::new(),
            session_expires_in_ms: self.session_expires_in_ms,
        }
    }

    pub fn access<'a>(&'a self, namespace: &'a str, caller: &'a Principal) -> NamespaceAccess<'a> {
        NamespaceAccess {
            ns: self,
            namespace,
            caller,
            roles: Default::default(),
        }
    }
}

/// A caller's permissions on one namespace.
///
/// Each role is resolved lazily and at most once, so a permission decision
/// that consults the same role repeatedly still pays one ACL lookup for it.
pub struct NamespaceAccess<'a> {
    ns: &'a Namespace,
    namespace: &'a str,
    caller: &'a Principal,
    roles: [Cell<Option<bool>>; 3],
}

impl NamespaceAccess<'_> {
    fn has(&self, role: u8) -> bool {
        let slot = &self.roles[role as usize];
        if let Some(value) = slot.get() {
            return value;
        }
        let value = acl_contains(self.namespace, role, self.caller);
        slot.set(Some(value));
        value
    }

    pub fn is_manager(&self) -> bool {
        self.has(ROLE_MANAGER)
    }

    pub fn is_auditor(&self) -> bool {
        self.has(ROLE_AUDITOR)
    }

    pub fn is_user(&self) -> bool {
        self.has(ROLE_USER)
    }

    pub fn read_permission(&self) -> NamespaceReadPermission {
        if self.ns.visibility == 1 || self.is_manager() || self.is_auditor() {
            NamespaceReadPermission::Full
        } else if self.ns.status >= 0 && self.is_user() {
            NamespaceReadPermission::User
        } else {
            NamespaceReadPermission::None
        }
    }

    /// Namespace managers may always change administrative metadata, including
    /// moving a namespace out of the read-only state. Content writes remain
    /// governed by [`Self::can_write_setting`].
    pub fn can_manage_namespace(&self) -> bool {
        self.is_manager()
    }

    pub fn can_read_namespace(&self) -> bool {
        self.ns.visibility == 1
            || self.is_manager()
            || self.is_auditor()
            || (self.ns.status >= 0 && self.is_user())
    }

    pub fn can_write_setting(&self, spk: &SettingPathKey) -> bool {
        if self.ns.status != 0 {
            return false;
        }
        // only managers can create server side settings for any subject
        if spk.1 == 0 {
            return self.is_manager();
        }
        // users can create settings for themselves and update them
        self.caller == &spk.2 && self.is_user()
    }

    fn partial_can_read_setting(&self, spk: &SettingPathKey) -> Option<bool> {
        if self.ns.visibility == 1 {
            return Some(true);
        }
        if self.ns.status < 0 {
            return Some(self.is_manager() || self.is_auditor());
        }
        if self.is_manager() || self.is_auditor() || self.caller == &spk.2 {
            return Some(true);
        }
        None
    }

    pub fn has_signing_permission(&self) -> bool {
        self.is_manager() || (self.ns.status >= 0 && self.is_user())
    }
}

impl_cbor_storable!(Namespace, "Namespace data", |ns| 256 + ns.desc.len());

/// A setting's metadata and current payload, as the API sees it. Stored split
/// into [`SettingMeta`] and [`SettingData`] so metadata edits never rewrite
/// the payload.
#[derive(Clone, Default)]
pub struct Setting {
    pub desc: String,
    pub created_at: u64, // unix timestamp in milliseconds
    pub updated_at: u64, // unix timestamp in milliseconds
    pub status: i8,      // -1: archived; 0: readable and writable; 1: readonly
    pub version: u32,
    pub readers: BTreeSet<Principal>, // readers can read the setting
    pub tags: BTreeMap<String, String>, // tags for query
    pub payload: Option<ByteBuf>,
    pub dek: Option<ByteBuf>, // Data Encryption Key that encrypted by BYOK or vetKey in COSE_Encrypt0
}

impl Setting {
    fn into_parts(self) -> (SettingMeta, SettingData) {
        (
            SettingMeta {
                desc: self.desc,
                created_at: self.created_at,
                updated_at: self.updated_at,
                status: self.status,
                version: self.version,
                readers: self.readers,
                tags: self.tags,
            },
            SettingData {
                payload: self.payload,
                dek: self.dek,
            },
        )
    }

    fn data_size(&self) -> u64 {
        self.payload
            .as_ref()
            .map_or(0, |value| value.len() as u64)
            .saturating_add(self.dek.as_ref().map_or(0, |value| value.len() as u64))
    }

    pub fn into_info(self, subject: Principal, key: ByteBuf, with_payload: bool) -> SettingInfo {
        SettingInfo {
            key,
            subject,
            desc: self.desc,
            created_at: self.created_at,
            updated_at: self.updated_at,
            status: self.status,
            version: self.version,
            readers: self.readers,
            tags: self.tags,
            dek: if with_payload { self.dek } else { None },
            payload: if with_payload { self.payload } else { None },
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct SettingMeta {
    #[serde(rename = "d")]
    desc: String,
    #[serde(rename = "ca")]
    created_at: u64,
    #[serde(rename = "ua")]
    updated_at: u64,
    #[serde(rename = "s")]
    status: i8,
    #[serde(rename = "v")]
    version: u32,
    #[serde(rename = "r")]
    readers: BTreeSet<Principal>,
    #[serde(rename = "t")]
    tags: BTreeMap<String, String>,
}

impl SettingMeta {
    fn into_setting(self, data: Option<SettingData>) -> Setting {
        let data = data.unwrap_or_default();
        Setting {
            desc: self.desc,
            created_at: self.created_at,
            updated_at: self.updated_at,
            status: self.status,
            version: self.version,
            readers: self.readers,
            tags: self.tags,
            payload: data.payload,
            dek: data.dek,
        }
    }
}

impl_cbor_storable!(SettingMeta, "SettingMeta data", |meta| {
    let readers = meta.readers.len() * (Principal::MAX_LENGTH_IN_BYTES + 2);
    let tags = meta
        .tags
        .iter()
        .fold(0, |size, (key, value)| size + key.len() + value.len() + 4);
    256 + meta.desc.len() + readers + tags
});

#[derive(Clone, Default, Deserialize, Serialize)]
struct SettingData {
    #[serde(rename = "p")]
    payload: Option<ByteBuf>,
    #[serde(rename = "k")]
    dek: Option<ByteBuf>,
}

impl SettingData {
    fn size(&self) -> usize {
        self.payload.as_ref().map_or(0, |value| value.len())
            + self.dek.as_ref().map_or(0, |value| value.len())
    }
}

impl_cbor_storable!(SettingData, "SettingData data", |data| data.size() + 32);

// SettingPathKey: (namespace name, 0 or 1, subject, setting name, version)
#[derive(Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct SettingPathKey(pub String, pub u8, pub Principal, pub ByteBuf, pub u32);

impl SettingPathKey {
    pub fn from_path(val: SettingPath, caller: Principal) -> Self {
        Self(
            val.ns,
            if val.user_owned { 1 } else { 0 },
            val.subject.unwrap_or(caller),
            val.key,
            val.version,
        )
    }

    pub fn v0(&self) -> SettingPathKey {
        SettingPathKey(self.0.clone(), self.1, self.2, self.3.clone(), 0)
    }
}

impl_cbor_storable!(SettingPathKey, "SettingPathKey data", |key| key.0.len()
    + key.3.len()
    + 64);

impl fmt::Display for SettingPathKey {
    /// Formats the `Resource` enum into a human-readable string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({},{},{},{},{})",
            self.0,
            self.1,
            self.2.to_text(),
            hex::encode(&self.3),
            self.4
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
struct AclKey(String, u8, Principal);

impl_cbor_storable!(AclKey, "AclKey data", |key| key.0.len() + 48);

#[derive(Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
struct FixedIdentityKey(String, String, Principal);

impl_cbor_storable!(FixedIdentityKey, "FixedIdentityKey data", |key| key.0.len()
    + key.1.len()
    + 48);

#[derive(Clone, Deserialize, Serialize)]
struct SignatureIntent {
    seed: Vec<u8>,
    message: Vec<u8>,
    expires_at_ns: u64,
}

impl_cbor_storable!(SignatureIntent, "SignatureIntent data", |intent| intent
    .seed
    .len()
    + intent.message.len()
    + 32);

#[derive(Clone, Deserialize, Serialize)]
pub struct SettingArchived {
    #[serde(rename = "a")]
    pub archived_at: u64,
    #[serde(rename = "d")]
    pub deprecated: bool, // true if the payload should not be used for some reason
    #[serde(rename = "p")]
    pub payload: Option<ByteBuf>,
    #[serde(rename = "k")]
    pub dek: Option<ByteBuf>,
}

impl SettingArchived {
    fn data_size(&self) -> u64 {
        self.payload
            .as_ref()
            .map_or(0, |value| value.len() as u64)
            .saturating_add(self.dek.as_ref().map_or(0, |value| value.len() as u64))
    }
}

impl_cbor_storable!(
    SettingArchived,
    "SettingArchived data",
    |archived| archived.data_size() as usize + 64
);

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
// MemoryId 1 held the retired monolithic namespace store; schema v2 left it empty.
const PAYLOADS_MEMORY_ID: MemoryId = MemoryId::new(2);
const NAMESPACES_MEMORY_ID: MemoryId = MemoryId::new(3);
/// Retired monolithic setting store; must be empty before this version runs.
const LEGACY_SETTINGS_MEMORY_ID: MemoryId = MemoryId::new(4);
const SCHEMA_MEMORY_ID: MemoryId = MemoryId::new(5);
const SETTING_META_MEMORY_ID: MemoryId = MemoryId::new(6);
const SETTING_DATA_MEMORY_ID: MemoryId = MemoryId::new(7);
const ACL_MEMORY_ID: MemoryId = MemoryId::new(8);
const FIXED_IDENTITY_MEMORY_ID: MemoryId = MemoryId::new(9);
const SIGNATURE_INTENT_MEMORY_ID: MemoryId = MemoryId::new(10);

thread_local! {
    static SIGNATURES : RefCell<SignatureMap> = RefCell::new(SignatureMap::default());
    static STATE: RefCell<State> = RefCell::new(State::default());

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static STATE_STORE: RefCell<StableCell<Vec<u8>, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(STATE_MEMORY_ID)),
            Vec::new()
        )
    );

    static PAYLOADS_STORE: RefCell<StableBTreeMap<SettingPathKey, SettingArchived, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(PAYLOADS_MEMORY_ID)),
        )
    );

    static NAMESPACES_STORE: RefCell<StableBTreeMap<String, Namespace, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(NAMESPACES_MEMORY_ID)),
        )
    );

    static SCHEMA_STORE: RefCell<StableCell<u32, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(SCHEMA_MEMORY_ID)),
            0
        )
    );

    static SETTING_META_STORE: RefCell<StableBTreeMap<SettingPathKey, SettingMeta, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(SETTING_META_MEMORY_ID)))
    );

    static SETTING_DATA_STORE: RefCell<StableBTreeMap<SettingPathKey, SettingData, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(SETTING_DATA_MEMORY_ID)))
    );

    static ACL_STORE: RefCell<StableBTreeMap<AclKey, u8, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(ACL_MEMORY_ID)))
    );

    static FIXED_IDENTITY_STORE: RefCell<StableBTreeMap<FixedIdentityKey, u8, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(FIXED_IDENTITY_MEMORY_ID)))
    );

    static SIGNATURE_INTENT_STORE: RefCell<StableBTreeMap<[u8; 32], SignatureIntent, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(SIGNATURE_INTENT_MEMORY_ID)))
    );
}

pub mod ns;
pub mod state;
#[cfg(test)]
mod test;
