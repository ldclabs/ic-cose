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
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug},
    ops,
};

use crate::{
    canister_memory::DefaultMemoryImpl,
    ecdsa::{derive_public_key, ecdsa_public_key},
    rand_bytes,
    schnorr::{derive_schnorr_public_key, schnorr_public_key},
    vetkd::derivation_path_to_context,
};

const SESSION_EXPIRES_IN_MS: u64 = 1000 * 3600 * 24; // 1 day
const CURRENT_SCHEMA_VERSION: u32 = 2;
const MAX_NAMESPACE_RECORD_BYTES: usize = 512 * 1024;
const MAX_NAMESPACE_PAGE_BYTES: usize = 3 * MAX_NAMESPACE_RECORD_BYTES;
const MAX_NAMESPACE_ROLE_PRINCIPALS: usize = 4_000;
const MAX_NAMESPACE_FIXED_DELEGATORS: usize = 5_000;
const MAX_SIGNATURE_INTENTS: u64 = 4_096;

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
            ecdsa_public_key: if with_keys {
                self.ecdsa_public_key.clone()
            } else {
                None
            },
            schnorr_ed25519_public_key: if with_keys {
                self.schnorr_ed25519_public_key.clone()
            } else {
                None
            },
            schnorr_secp256k1_public_key: if with_keys {
                self.schnorr_secp256k1_public_key.clone()
            } else {
                None
            },
            governance_canister: self.governance_canister,
            vetkd_context_version: self.vetkd_context_version,
            low_wasm_memory: self.low_wasm_memory,
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct NamespaceLegacy {
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
    #[serde(rename = "m")]
    pub managers: BTreeSet<Principal>, // managers can read and write all settings
    #[serde(rename = "a")]
    pub auditors: BTreeSet<Principal>, // auditors can read all settings
    #[serde(rename = "u")]
    pub users: BTreeSet<Principal>, // users can read and write settings they created
    #[serde(rename = "ss")]
    pub settings: BTreeMap<(Principal, ByteBuf), Setting>, // settings created by managers for users
    #[serde(rename = "us")]
    pub user_settings: BTreeMap<(Principal, ByteBuf), Setting>, // settings created by users
    #[serde(rename = "g")]
    pub gas_balance: u128, // namespace cycles budget
    #[serde(default, rename = "f")]
    pub fixed_id_names: BTreeMap<String, BTreeSet<Principal>>, // fixed_id_name -> users
    #[serde(default, rename = "se")]
    pub session_expires_in_ms: u64, // session expires in milliseconds
}

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
    #[serde(rename = "m")]
    pub managers: BTreeSet<Principal>, // managers can read and write all settings
    #[serde(rename = "a")]
    pub auditors: BTreeSet<Principal>, // auditors can read all settings
    #[serde(rename = "u")]
    pub users: BTreeSet<Principal>, // users can read and write settings they created
    #[serde(rename = "g")]
    pub gas_balance: u128, // namespace cycles budget
    #[serde(default, rename = "f")]
    pub fixed_id_names: BTreeMap<String, BTreeSet<Principal>>, // fixed_id_name -> users
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

impl Namespace {
    fn encoded_size_hint(&self) -> usize {
        let direct_principals = self
            .managers
            .len()
            .saturating_add(self.auditors.len())
            .saturating_add(self.users.len());
        let fixed_id_size = self
            .fixed_id_names
            .iter()
            .fold(0usize, |size, (name, delegators)| {
                size.saturating_add(name.len()).saturating_add(
                    delegators
                        .len()
                        .saturating_mul(Principal::MAX_LENGTH_IN_BYTES + 2),
                )
            });

        256usize
            .saturating_add(self.desc.len())
            .saturating_add(direct_principals.saturating_mul(Principal::MAX_LENGTH_IN_BYTES + 2))
            .saturating_add(fixed_id_size)
    }

    fn info_size_hint(&self) -> usize {
        if self.acl_version == 0 {
            return self.encoded_size_hint();
        }
        let role_principals = self
            .manager_count
            .saturating_add(self.auditor_count)
            .saturating_add(self.user_count) as usize;
        let fixed_delegators = self.fixed_delegator_count as usize;
        self.encoded_size_hint()
            .saturating_add(role_principals.saturating_mul(Principal::MAX_LENGTH_IN_BYTES + 68))
            // One fixed-identity name may exist per delegator. Account for its
            // maximum validated length as a conservative response-size bound.
            .saturating_add(
                fixed_delegators.saturating_mul(Principal::MAX_LENGTH_IN_BYTES + 68 + 64),
            )
    }

    pub fn into_info(self, name: String) -> NamespaceInfo {
        let manager_count = if self.acl_version == 0 {
            self.managers
                .iter()
                .filter(|principal| **principal != Principal::anonymous())
                .count() as u32
        } else {
            self.manager_count
        };
        let auditor_count = if self.acl_version == 0 {
            self.auditors
                .iter()
                .filter(|principal| **principal != Principal::anonymous())
                .count() as u32
        } else {
            self.auditor_count
        };
        let user_count = if self.acl_version == 0 {
            self.users
                .iter()
                .filter(|principal| **principal != Principal::anonymous())
                .count() as u32
        } else {
            self.user_count
        };
        let fixed_delegator_count = if self.acl_version == 0 {
            self.fixed_id_names
                .values()
                .map(|principals| {
                    principals
                        .iter()
                        .filter(|principal| **principal != Principal::anonymous())
                        .count()
                })
                .sum::<usize>() as u32
        } else {
            self.fixed_delegator_count
        };
        NamespaceInfo {
            name,
            desc: self.desc,
            created_at: self.created_at,
            updated_at: self.updated_at,
            max_payload_size: self.max_payload_size,
            payload_bytes_total: self.payload_bytes_total,
            status: self.status,
            visibility: self.visibility,
            managers: self.managers,
            auditors: self.auditors,
            users: self.users,
            manager_count,
            auditor_count,
            user_count,
            fixed_delegator_count,
            gas_balance: self.gas_balance,
            fixed_id_names: self.fixed_id_names,
            session_expires_in_ms: self.session_expires_in_ms,
        }
    }

    fn has_role(&self, namespace: &str, role: u8, caller: &Principal) -> bool {
        if caller == &Principal::anonymous() {
            return false;
        }
        if self.acl_version == 0 {
            return match role {
                ROLE_MANAGER => self.managers.contains(caller),
                ROLE_AUDITOR => self.auditors.contains(caller),
                ROLE_USER => self.users.contains(caller),
                _ => false,
            };
        }
        ACL_STORE
            .with_borrow(|store| store.contains_key(&AclKey(namespace.to_string(), role, *caller)))
    }

    pub fn read_permission(&self, namespace: &str, caller: &Principal) -> NamespaceReadPermission {
        if self.visibility == 1 {
            return NamespaceReadPermission::Full;
        }

        if self.has_role(namespace, ROLE_MANAGER, caller)
            || self.has_role(namespace, ROLE_AUDITOR, caller)
        {
            NamespaceReadPermission::Full
        } else if self.status >= 0 && self.has_role(namespace, ROLE_USER, caller) {
            NamespaceReadPermission::User
        } else {
            NamespaceReadPermission::None
        }
    }

    /// Namespace managers may always change administrative metadata, including
    /// moving a namespace out of the read-only state. Content writes remain
    /// governed by [`Self::can_write_setting`].
    pub fn can_manage_namespace(&self, namespace: &str, caller: &Principal) -> bool {
        self.has_role(namespace, ROLE_MANAGER, caller)
    }

    pub fn can_read_namespace(&self, namespace: &str, caller: &Principal) -> bool {
        if self.visibility == 1 {
            return true;
        }

        if self.status < 0 {
            return self.has_role(namespace, ROLE_MANAGER, caller)
                || self.has_role(namespace, ROLE_AUDITOR, caller);
        }

        self.has_role(namespace, ROLE_MANAGER, caller)
            || self.has_role(namespace, ROLE_AUDITOR, caller)
            || self.has_role(namespace, ROLE_USER, caller)
    }

    pub fn can_write_setting(&self, caller: &Principal, spk: &SettingPathKey) -> bool {
        if self.status != 0 {
            return false;
        }

        // only managers can create server side settings for any subject
        if spk.1 == 0 {
            return self.has_role(&spk.0, ROLE_MANAGER, caller);
        }

        // users can create settings for themselves and update them
        self.has_role(&spk.0, ROLE_USER, caller) && caller == &spk.2
    }

    fn partial_can_read_setting(&self, caller: &Principal, spk: &SettingPathKey) -> Option<bool> {
        if self.visibility == 1 {
            return Some(true);
        }

        if self.status < 0 {
            return Some(
                self.has_role(&spk.0, ROLE_MANAGER, caller)
                    || self.has_role(&spk.0, ROLE_AUDITOR, caller),
            );
        }

        if self.has_role(&spk.0, ROLE_MANAGER, caller)
            || self.has_role(&spk.0, ROLE_AUDITOR, caller)
            || caller == &spk.2
        {
            return Some(true);
        }
        None
    }

    pub fn has_ns_signing_permission(&self, namespace: &str, caller: &Principal) -> bool {
        if self.status < 0 && !self.has_role(namespace, ROLE_MANAGER, caller) {
            return false;
        }
        self.has_role(namespace, ROLE_MANAGER, caller)
            || self.has_role(namespace, ROLE_USER, caller)
    }
}

impl Storable for Namespace {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        let capacity = self.encoded_size_hint();
        to_cbor_bytes(&self, capacity, "Namespace data")
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_cbor_bytes(
            self,
            self.encoded_size_hint(),
            "Namespace data",
        ))
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "Namespace data")
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Setting {
    #[serde(rename = "d")]
    pub desc: String,
    #[serde(rename = "ca")]
    pub created_at: u64, // unix timestamp in milliseconds
    #[serde(rename = "ua")]
    pub updated_at: u64, // unix timestamp in milliseconds
    #[serde(rename = "s")]
    pub status: i8, // -1: archived; 0: readable and writable; 1: readonly
    #[serde(rename = "v")]
    pub version: u32,
    #[serde(rename = "r")]
    pub readers: BTreeSet<Principal>, // readers can read the setting
    #[serde(rename = "t")]
    pub tags: BTreeMap<String, String>, // tags for query
    #[serde(rename = "p")]
    pub payload: Option<ByteBuf>,
    #[serde(rename = "k")]
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

    fn encoded_size_hint(&self) -> usize {
        let payload_size = self.payload.as_ref().map_or(0, |value| value.len());
        let dek_size = self.dek.as_ref().map_or(0, |value| value.len());
        let readers_size = self
            .readers
            .len()
            .saturating_mul(Principal::MAX_LENGTH_IN_BYTES + 2);
        let tags_size = self.tags.iter().fold(0usize, |size, (key, value)| {
            size.saturating_add(key.len())
                .saturating_add(value.len())
                .saturating_add(4)
        });
        payload_size
            .saturating_add(dek_size)
            .saturating_add(self.desc.len())
            .saturating_add(readers_size)
            .saturating_add(tags_size)
            .saturating_add(256)
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

impl Storable for Setting {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        let capacity = self.encoded_size_hint();
        to_cbor_bytes(&self, capacity, "Setting data")
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_cbor_bytes(
            self,
            self.encoded_size_hint(),
            "Setting data",
        ))
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "Setting data")
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

impl Storable for SettingMeta {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        to_cbor_bytes(&self, 512 + self.desc.len(), "SettingMeta data")
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_cbor_bytes(
            self,
            512 + self.desc.len(),
            "SettingMeta data",
        ))
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "SettingMeta data")
    }
}

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

impl Storable for SettingData {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        to_cbor_bytes(&self, self.size() + 32, "SettingData data")
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_cbor_bytes(self, self.size() + 32, "SettingData data"))
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "SettingData data")
    }
}

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

    fn encoded_size_hint(&self) -> usize {
        self.0.len().saturating_add(self.3.len()).saturating_add(64)
    }
}

impl Storable for SettingPathKey {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        let capacity = self.encoded_size_hint();
        to_cbor_bytes(&self, capacity, "SettingPathKey data")
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_cbor_bytes(
            self,
            self.encoded_size_hint(),
            "SettingPathKey data",
        ))
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "SettingPathKey data")
    }
}

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

impl Storable for AclKey {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        to_cbor_bytes(&self, self.0.len() + 48, "AclKey data")
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_cbor_bytes(self, self.0.len() + 48, "AclKey data"))
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "AclKey data")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
struct FixedIdentityKey(String, String, Principal);

impl Storable for FixedIdentityKey {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        to_cbor_bytes(
            &self,
            self.0.len() + self.1.len() + 48,
            "FixedIdentityKey data",
        )
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_cbor_bytes(
            self,
            self.0.len() + self.1.len() + 48,
            "FixedIdentityKey data",
        ))
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "FixedIdentityKey data")
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct SignatureIntent {
    seed: Vec<u8>,
    message: Vec<u8>,
    expires_at_ns: u64,
}

impl Storable for SignatureIntent {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        to_cbor_bytes(
            &self,
            self.seed.len() + self.message.len() + 32,
            "SignatureIntent data",
        )
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_cbor_bytes(
            self,
            self.seed.len() + self.message.len() + 32,
            "SignatureIntent data",
        ))
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "SignatureIntent data")
    }
}

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

    fn encoded_size_hint(&self) -> usize {
        self.payload
            .as_ref()
            .map_or(0, |value| value.len())
            .saturating_add(self.dek.as_ref().map_or(0, |value| value.len()))
            .saturating_add(64)
    }
}

impl Storable for SettingArchived {
    const BOUND: Bound = Bound::Unbounded;

    fn into_bytes(self) -> Vec<u8> {
        let capacity = self.encoded_size_hint();
        to_cbor_bytes(&self, capacity, "SettingArchived data")
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_cbor_bytes(
            self,
            self.encoded_size_hint(),
            "SettingArchived data",
        ))
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_cbor_bytes(&bytes, "SettingArchived data")
    }
}

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const NSLEGACY_MEMORY_ID: MemoryId = MemoryId::new(1);
const PAYLOADS_MEMORY_ID: MemoryId = MemoryId::new(2);
const NAMESPACES_MEMORY_ID: MemoryId = MemoryId::new(3);
const SETTINGS_MEMORY_ID: MemoryId = MemoryId::new(4);
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

    static NSLEGACY_STORE: RefCell<StableCell<Vec<u8>, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(NSLEGACY_MEMORY_ID)),
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

    static SETTINGS_STORE: RefCell<StableBTreeMap<SettingPathKey, Setting, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(SETTINGS_MEMORY_ID)),
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
