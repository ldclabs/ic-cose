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
    ecdsa::{derive_public_key, ecdsa_public_key, sign_with_ecdsa, sign_with_ecdsa_cost},
    rand_bytes,
    schnorr::{
        derive_schnorr_public_key, schnorr_public_key, sign_with_schnorr, sign_with_schnorr_cost,
    },
    vetkd::{vetkd_derive_key_cost, vetkd_encrypted_key, vetkd_public_key, vetkd_public_key_cost},
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
    fn from_setting(setting: &Setting) -> Self {
        Self {
            desc: setting.desc.clone(),
            created_at: setting.created_at,
            updated_at: setting.updated_at,
            status: setting.status,
            version: setting.version,
            readers: setting.readers.clone(),
            tags: setting.tags.clone(),
        }
    }

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
    fn from_setting(setting: &Setting) -> Self {
        Self {
            payload: setting.payload.clone(),
            dek: setting.dek.clone(),
        }
    }

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

pub mod state {
    use super::*;

    pub fn with<R>(f: impl FnOnce(&State) -> R) -> R {
        STATE.with_borrow(f)
    }

    pub fn with_mut<R>(f: impl FnOnce(&mut State) -> R) -> R {
        STATE.with_borrow_mut(f)
    }

    pub fn is_controller(caller: &Principal) -> bool {
        STATE.with_borrow(|s| s.governance_canister.as_ref() == Some(caller))
    }

    pub fn is_manager(caller: &Principal) -> bool {
        STATE.with_borrow(|s| s.managers.contains(caller))
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

    pub fn allowed_api(api: &str) -> Result<(), String> {
        if with(|s| s.allowed_apis.is_empty() || s.allowed_apis.contains(api)) {
            Ok(())
        } else {
            Err(format!("API {} not allowed", api))
        }
    }

    pub fn add_signature(seed: &[u8], message: &[u8]) -> Result<(), String> {
        const SIGNATURE_TTL_NS: u64 = 60 * 1_000_000_000;
        let now = canister_time_ns();
        let id = signature_intent_id(seed, message);
        SIGNATURE_INTENT_STORE.with_borrow_mut(|store| -> Result<(), String> {
            if !store.contains_key(&id) && store.len() >= MAX_SIGNATURE_INTENTS {
                let expired: Vec<[u8; 32]> = store
                    .iter()
                    .filter_map(|entry| {
                        (entry.value().expires_at_ns <= now).then_some(*entry.key())
                    })
                    .collect();
                if store.len().saturating_sub(expired.len() as u64) >= MAX_SIGNATURE_INTENTS {
                    return Err(format!(
                        "too many active signature intents; retry after {} seconds",
                        SIGNATURE_TTL_NS / 1_000_000_000
                    ));
                }
                for key in expired {
                    store.remove(&key);
                }
            }
            store.insert(
                id,
                SignatureIntent {
                    seed: seed.to_vec(),
                    message: message.to_vec(),
                    expires_at_ns: now.saturating_add(SIGNATURE_TTL_NS),
                },
            );
            Ok(())
        })?;
        SIGNATURES.with_borrow_mut(|sigs| {
            let sig_inputs = CanisterSigInputs {
                domain: DELEGATION_SIG_DOMAIN,
                seed,
                message,
            };
            sigs.add_signature(&sig_inputs);
        });
        certify_signature_root();
        Ok(())
    }

    pub fn get_signature(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
        SIGNATURES.with_borrow(|sigs| {
            let sig_inputs = CanisterSigInputs {
                domain: DELEGATION_SIG_DOMAIN,
                seed,
                message,
            };
            sigs.get_signature_as_cbor(&sig_inputs, None)
                .map_err(|err| format!("failed to get signature: {:?}", err))
        })
    }

    pub async fn init_public_key() -> bool {
        let (ecdsa_key_name, schnorr_ed25519_key_name, schnorr_secp256k1_key_name, needs_iv) =
            with(|r| {
                (
                    r.ecdsa_public_key
                        .is_none()
                        .then(|| r.ecdsa_key_name.clone()),
                    r.schnorr_ed25519_public_key
                        .is_none()
                        .then(|| r.schnorr_key_name.clone()),
                    r.schnorr_secp256k1_public_key
                        .is_none()
                        .then(|| r.schnorr_key_name.clone()),
                    *r.init_vector == [0u8; 32],
                )
            });

        let ecdsa_public_key = if let Some(key_name) = ecdsa_key_name {
            ecdsa_public_key(key_name, vec![])
                .await
                .map_err(|err| {
                    ic_cdk::api::debug_print(format!("failed to retrieve ECDSA public key: {err}"))
                })
                .ok()
        } else {
            None
        };

        let schnorr_ed25519_public_key = if let Some(key_name) = schnorr_ed25519_key_name {
            schnorr_public_key(key_name, SchnorrAlgorithm::Ed25519, vec![])
                .await
                .map_err(|err| {
                    ic_cdk::api::debug_print(format!(
                        "failed to retrieve Schnorr Ed25519 public key: {err}"
                    ))
                })
                .ok()
        } else {
            None
        };

        let schnorr_secp256k1_public_key = if let Some(key_name) = schnorr_secp256k1_key_name {
            schnorr_public_key(key_name, SchnorrAlgorithm::Bip340secp256k1, vec![])
                .await
                .map_err(|err| {
                    ic_cdk::api::debug_print(format!(
                        "failed to retrieve Schnorr Secp256k1 public key: {err}"
                    ))
                })
                .ok()
        } else {
            None
        };

        let iv = if needs_iv {
            rand_bytes::<32>()
                .await
                .map_err(|err| {
                    ic_cdk::api::debug_print(format!(
                        "failed to generate initialization vector: {err}"
                    ))
                })
                .ok()
        } else {
            None
        };

        // this runs again after an upgrade when something is still missing, so it
        // must be idempotent: never clear a key that was already retrieved, and
        // never rotate the IV, which feeds every KEK derived so far.
        with_mut(|r| {
            if ecdsa_public_key.is_some() {
                r.ecdsa_public_key = ecdsa_public_key;
            }
            if schnorr_ed25519_public_key.is_some() {
                r.schnorr_ed25519_public_key = schnorr_ed25519_public_key;
            }
            if schnorr_secp256k1_public_key.is_some() {
                r.schnorr_secp256k1_public_key = schnorr_secp256k1_public_key;
            }
            if *r.init_vector == [0u8; 32] {
                if let Some(iv) = iv {
                    r.init_vector = iv.into();
                }
            }
        });
        !needs_public_key_init()
    }

    /// Returns true if some key material could not be retrieved yet, so that
    /// [`init_public_key`] can be retried instead of leaving the ECDSA, Schnorr
    /// and KEK APIs permanently broken.
    pub fn needs_public_key_init() -> bool {
        with(|s| {
            s.ecdsa_public_key.is_none()
                || s.schnorr_ed25519_public_key.is_none()
                || s.schnorr_secp256k1_public_key.is_none()
                || *s.init_vector == [0u8; 32]
        })
    }

    pub fn initialize_schema() {
        SCHEMA_STORE.with_borrow_mut(|r| {
            r.set(CURRENT_SCHEMA_VERSION);
        });
        certify_signature_root();
    }

    fn restore_signature_intents() {
        let now = canister_time_ns();
        let intents: Vec<([u8; 32], SignatureIntent)> =
            SIGNATURE_INTENT_STORE.with_borrow(|store| {
                store
                    .iter()
                    .map(|entry| (*entry.key(), entry.value()))
                    .collect()
            });
        SIGNATURES.with_borrow_mut(|signatures| {
            for (key, intent) in intents {
                if intent.expires_at_ns <= now {
                    SIGNATURE_INTENT_STORE.with_borrow_mut(|store| {
                        store.remove(&key);
                    });
                    continue;
                }
                signatures.add_signature(&CanisterSigInputs {
                    domain: DELEGATION_SIG_DOMAIN,
                    seed: &intent.seed,
                    message: &intent.message,
                });
            }
        });
    }

    pub fn load(migrate_legacy_namespaces: bool) {
        STATE_STORE.with_borrow(|r| {
            STATE.with_borrow_mut(|h| {
                let v: State = from_cbor_bytes(r.get(), "STATE_STORE data");
                *h = v;
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
            state.auditors.remove(&Principal::anonymous());
        });

        let schema = SCHEMA_STORE.with_borrow(|r| *r.get());
        if schema < CURRENT_SCHEMA_VERSION {
            let legacy = NSLEGACY_STORE.with_borrow(|r| r.get().clone());
            if migrate_legacy_namespaces && !legacy.is_empty() {
                if NAMESPACES_STORE.with_borrow(|r| r.len()) > 0 {
                    ic_cdk::trap(
                        "legacy namespace migration requested but current namespaces are not empty",
                    );
                }
                let m: BTreeMap<String, NamespaceLegacy> =
                    from_cbor_bytes(&legacy, "NS_STORE data");
                ns::migrate(m);
            }
            NSLEGACY_STORE.with_borrow_mut(|r| {
                r.set(Vec::new());
            });
            SCHEMA_STORE.with_borrow_mut(|r| {
                r.set(CURRENT_SCHEMA_VERSION);
            });
        }

        restore_signature_intents();
        certify_signature_root();
    }

    pub fn save() {
        STATE.with_borrow(|h| {
            STATE_STORE.with_borrow_mut(|r| {
                r.set(to_cbor_bytes(h, 512, "STATE_STORE data"));
            });
        });
    }
}

pub mod ns {
    use super::*;

    fn load_setting_metadata(key: &SettingPathKey) -> Option<(Setting, bool)> {
        if let Some(meta) = SETTING_META_STORE.with_borrow(|store| store.get(key)) {
            let mut setting = meta.into_setting(None);
            setting.readers.remove(&Principal::anonymous());
            return Some((setting, false));
        }
        SETTINGS_STORE
            .with_borrow(|store| store.get(key))
            .map(|mut setting| {
                setting.readers.remove(&Principal::anonymous());
                (setting, true)
            })
    }

    fn load_setting(key: &SettingPathKey) -> Option<Setting> {
        if let Some(meta) = SETTING_META_STORE.with_borrow(|store| store.get(key)) {
            let data = SETTING_DATA_STORE.with_borrow(|store| store.get(key));
            let mut setting = meta.into_setting(data);
            setting.readers.remove(&Principal::anonymous());
            return Some(setting);
        }
        SETTINGS_STORE.with_borrow(|store| {
            store.get(key).map(|mut setting| {
                setting.readers.remove(&Principal::anonymous());
                setting
            })
        })
    }

    fn contains_setting(key: &SettingPathKey) -> bool {
        SETTING_META_STORE.with_borrow(|store| store.contains_key(key))
            || SETTINGS_STORE.with_borrow(|store| store.contains_key(key))
    }

    fn save_setting(key: SettingPathKey, setting: Setting) {
        let meta = SettingMeta::from_setting(&setting);
        let data = SettingData::from_setting(&setting);
        SETTING_META_STORE.with_borrow_mut(|store| {
            store.insert(key.clone(), meta);
        });
        SETTING_DATA_STORE.with_borrow_mut(|store| {
            if data.payload.is_some() || data.dek.is_some() {
                store.insert(key.clone(), data);
            } else {
                store.remove(&key);
            }
        });
        SETTINGS_STORE.with_borrow_mut(|store| {
            store.remove(&key);
        });
    }

    fn save_setting_metadata(key: SettingPathKey, setting: Setting, was_legacy: bool) {
        if was_legacy {
            save_setting(key, setting);
        } else {
            SETTING_META_STORE.with_borrow_mut(|store| {
                store.insert(key, SettingMeta::from_setting(&setting));
            });
        }
    }

    fn remove_setting(key: &SettingPathKey) -> Option<Setting> {
        if let Some(meta) = SETTING_META_STORE.with_borrow_mut(|store| store.remove(key)) {
            let data = SETTING_DATA_STORE.with_borrow_mut(|store| store.remove(key));
            return Some(meta.into_setting(data));
        }
        SETTINGS_STORE.with_borrow_mut(|store| store.remove(key))
    }

    fn ensure_acl_v1(namespace: &str, ns: &mut Namespace) {
        if ns.acl_version != 0 {
            return;
        }
        ACL_STORE.with_borrow_mut(|store| {
            for principal in &ns.managers {
                if *principal != Principal::anonymous() {
                    store.insert(AclKey(namespace.to_string(), ROLE_MANAGER, *principal), 0);
                }
            }
            for principal in &ns.auditors {
                if *principal != Principal::anonymous() {
                    store.insert(AclKey(namespace.to_string(), ROLE_AUDITOR, *principal), 0);
                }
            }
            for principal in &ns.users {
                if *principal != Principal::anonymous() {
                    store.insert(AclKey(namespace.to_string(), ROLE_USER, *principal), 0);
                }
            }
        });
        FIXED_IDENTITY_STORE.with_borrow_mut(|store| {
            for (name, delegators) in &ns.fixed_id_names {
                for principal in delegators {
                    if *principal != Principal::anonymous() {
                        store.insert(
                            FixedIdentityKey(namespace.to_string(), name.clone(), *principal),
                            0,
                        );
                    }
                }
            }
        });
        ns.manager_count = ns
            .managers
            .iter()
            .filter(|principal| **principal != Principal::anonymous())
            .count() as u32;
        ns.auditor_count = ns
            .auditors
            .iter()
            .filter(|principal| **principal != Principal::anonymous())
            .count() as u32;
        ns.user_count = ns
            .users
            .iter()
            .filter(|principal| **principal != Principal::anonymous())
            .count() as u32;
        ns.fixed_delegator_count = ns
            .fixed_id_names
            .values()
            .map(|values| {
                values
                    .iter()
                    .filter(|principal| **principal != Principal::anonymous())
                    .count()
            })
            .sum::<usize>() as u32;
        ns.managers.clear();
        ns.auditors.clear();
        ns.users.clear();
        ns.fixed_id_names.clear();
        ns.acl_version = 1;
    }

    fn role_members(namespace: &str, ns: &Namespace, role: u8) -> BTreeSet<Principal> {
        if ns.acl_version == 0 {
            return match role {
                ROLE_MANAGER => ns.managers.clone(),
                ROLE_AUDITOR => ns.auditors.clone(),
                ROLE_USER => ns.users.clone(),
                _ => BTreeSet::new(),
            }
            .into_iter()
            .filter(|principal| *principal != Principal::anonymous())
            .collect();
        }
        ACL_STORE.with_borrow(|store| {
            store
                .range(ops::RangeFrom {
                    start: AclKey(
                        namespace.to_string(),
                        role,
                        Principal::management_canister(),
                    ),
                })
                .take_while(|entry| entry.key().0 == namespace && entry.key().1 == role)
                .map(|entry| entry.key().2)
                .collect()
        })
    }

    fn fixed_identities(namespace: &str, ns: &Namespace) -> BTreeMap<String, BTreeSet<Principal>> {
        if ns.acl_version == 0 {
            return ns
                .fixed_id_names
                .iter()
                .filter_map(|(name, principals)| {
                    let principals: BTreeSet<_> = principals
                        .iter()
                        .copied()
                        .filter(|principal| *principal != Principal::anonymous())
                        .collect();
                    (!principals.is_empty()).then(|| (name.clone(), principals))
                })
                .collect();
        }
        FIXED_IDENTITY_STORE.with_borrow(|store| {
            let mut values = BTreeMap::<String, BTreeSet<Principal>>::new();
            for entry in store
                .range(ops::RangeFrom {
                    start: FixedIdentityKey(
                        namespace.to_string(),
                        String::new(),
                        Principal::management_canister(),
                    ),
                })
                .take_while(|entry| entry.key().0 == namespace)
            {
                values
                    .entry(entry.key().1.clone())
                    .or_default()
                    .insert(entry.key().2);
            }
            values
        })
    }

    pub(super) fn namespace_info(name: String, ns: Namespace) -> NamespaceInfo {
        let mut info = ns.clone().into_info(name.clone());
        if ns.acl_version == 0 {
            info.managers.remove(&Principal::anonymous());
            info.auditors.remove(&Principal::anonymous());
            info.users.remove(&Principal::anonymous());
            info.fixed_id_names = fixed_identities(&name, &ns);
        } else {
            info.managers = role_members(&name, &ns, ROLE_MANAGER);
            info.auditors = role_members(&name, &ns, ROLE_AUDITOR);
            info.users = role_members(&name, &ns, ROLE_USER);
            info.fixed_id_names = fixed_identities(&name, &ns);
        }
        info
    }

    pub(super) fn namespace_summary(name: String, ns: Namespace) -> NamespaceInfo {
        let mut info = ns.into_info(name);
        info.managers.clear();
        info.auditors.clear();
        info.users.clear();
        info.fixed_id_names.clear();
        info
    }

    fn namespace_info_bounded(name: String, ns: Namespace) -> NamespaceInfo {
        if ns.info_size_hint() > MAX_NAMESPACE_PAGE_BYTES {
            namespace_summary(name, ns)
        } else {
            namespace_info(name, ns)
        }
    }

    fn remove_namespace_acl(namespace: &str) {
        ACL_STORE.with_borrow_mut(|store| {
            let keys: Vec<AclKey> = store
                .range(ops::RangeFrom {
                    start: AclKey(
                        namespace.to_string(),
                        ROLE_MANAGER,
                        Principal::management_canister(),
                    ),
                })
                .take_while(|entry| entry.key().0 == namespace)
                .map(|entry| entry.key().clone())
                .collect();
            for key in keys {
                store.remove(&key);
            }
        });
        FIXED_IDENTITY_STORE.with_borrow_mut(|store| {
            let keys: Vec<FixedIdentityKey> = store
                .range(ops::RangeFrom {
                    start: FixedIdentityKey(
                        namespace.to_string(),
                        String::new(),
                        Principal::management_canister(),
                    ),
                })
                .take_while(|entry| entry.key().0 == namespace)
                .map(|entry| entry.key().clone())
                .collect();
            for key in keys {
                store.remove(&key);
            }
        });
    }

    fn mutate_members(
        namespace: String,
        caller: &Principal,
        role: u8,
        values: BTreeSet<Principal>,
        add: bool,
        now_ms: u64,
    ) -> Result<(), String> {
        with_mut(namespace.clone(), |ns| {
            if !ns.can_manage_namespace(&namespace, caller) {
                return Err("no permission".to_string());
            }
            let current = role_members(&namespace, ns, role);
            let mut next = current.clone();
            if add {
                next.extend(values.iter().copied());
                if next.len() > MAX_NAMESPACE_ROLE_PRINCIPALS {
                    return Err(format!(
                        "namespace role count exceeds the limit {}",
                        MAX_NAMESPACE_ROLE_PRINCIPALS
                    ));
                }
            } else {
                next.retain(|principal| !values.contains(principal));
                if role == ROLE_MANAGER && next.is_empty() {
                    return Err("namespace must retain at least one manager".to_string());
                }
            }
            ensure_acl_v1(&namespace, ns);
            ACL_STORE.with_borrow_mut(|store| {
                for principal in values {
                    let key = AclKey(namespace.clone(), role, principal);
                    if add {
                        store.insert(key, 0);
                    } else {
                        store.remove(&key);
                    }
                }
            });
            let count = next.len() as u32;
            match role {
                ROLE_MANAGER => ns.manager_count = count,
                ROLE_AUDITOR => ns.auditor_count = count,
                ROLE_USER => ns.user_count = count,
                _ => unreachable!(),
            }
            ns.updated_at = now_ms;
            Ok(())
        })
    }

    pub fn add_managers(
        namespace: String,
        caller: &Principal,
        values: BTreeSet<Principal>,
        now_ms: u64,
    ) -> Result<(), String> {
        mutate_members(namespace, caller, ROLE_MANAGER, values, true, now_ms)
    }

    pub fn remove_managers(
        namespace: String,
        caller: &Principal,
        values: BTreeSet<Principal>,
        now_ms: u64,
    ) -> Result<(), String> {
        mutate_members(namespace, caller, ROLE_MANAGER, values, false, now_ms)
    }

    pub fn recover_managers(
        namespace: String,
        values: BTreeSet<Principal>,
        now_ms: u64,
    ) -> Result<(), String> {
        with_mut(namespace.clone(), |ns| {
            if !role_members(&namespace, ns, ROLE_MANAGER).is_empty() {
                return Err("namespace still has a manager".to_string());
            }
            ensure_acl_v1(&namespace, ns);
            ACL_STORE.with_borrow_mut(|store| {
                for principal in &values {
                    store.insert(AclKey(namespace.clone(), ROLE_MANAGER, *principal), 0);
                }
            });
            ns.manager_count = values.len() as u32;
            ns.updated_at = now_ms;
            Ok(())
        })
    }

    pub fn add_auditors(
        namespace: String,
        caller: &Principal,
        values: BTreeSet<Principal>,
        now_ms: u64,
    ) -> Result<(), String> {
        mutate_members(namespace, caller, ROLE_AUDITOR, values, true, now_ms)
    }

    pub fn remove_auditors(
        namespace: String,
        caller: &Principal,
        values: BTreeSet<Principal>,
        now_ms: u64,
    ) -> Result<(), String> {
        mutate_members(namespace, caller, ROLE_AUDITOR, values, false, now_ms)
    }

    pub fn add_users(
        namespace: String,
        caller: &Principal,
        values: BTreeSet<Principal>,
        now_ms: u64,
    ) -> Result<(), String> {
        mutate_members(namespace, caller, ROLE_USER, values, true, now_ms)
    }

    pub fn remove_users(
        namespace: String,
        caller: &Principal,
        values: BTreeSet<Principal>,
        now_ms: u64,
    ) -> Result<(), String> {
        mutate_members(namespace, caller, ROLE_USER, values, false, now_ms)
    }

    pub fn is_member(
        namespace: &str,
        caller: &Principal,
        member_kind: &str,
        user: &Principal,
    ) -> Result<bool, String> {
        with(&namespace.to_string(), |ns| {
            if !ns.can_read_namespace(namespace, caller) {
                return Err("no permission".to_string());
            }
            let role = match member_kind {
                "manager" => ROLE_MANAGER,
                "auditor" => ROLE_AUDITOR,
                "user" => ROLE_USER,
                _ => return Err(format!("invalid member kind: {member_kind}")),
            };
            Ok(ns.has_role(namespace, role, user))
        })
    }

    pub fn list_members(
        namespace: &str,
        caller: &Principal,
        member_kind: &str,
        prev: Option<Principal>,
        take: usize,
    ) -> Result<Vec<Principal>, String> {
        with(&namespace.to_string(), |ns| {
            if !ns.can_read_namespace(namespace, caller) {
                return Err("no permission".to_string());
            }
            let role = match member_kind {
                "manager" => ROLE_MANAGER,
                "auditor" => ROLE_AUDITOR,
                "user" => ROLE_USER,
                _ => return Err(format!("invalid member kind: {member_kind}")),
            };
            if ns.acl_version == 0 {
                return Ok(role_members(namespace, &ns, role)
                    .into_iter()
                    .filter(|principal| prev.is_none_or(|cursor| principal > &cursor))
                    .take(take)
                    .collect());
            }
            let lower = prev
                .map(|principal| {
                    std::ops::Bound::Excluded(AclKey(namespace.to_string(), role, principal))
                })
                .unwrap_or_else(|| {
                    std::ops::Bound::Included(AclKey(
                        namespace.to_string(),
                        role,
                        Principal::management_canister(),
                    ))
                });
            Ok(ACL_STORE.with_borrow(|store| {
                store
                    .range((lower, std::ops::Bound::Unbounded))
                    .take_while(|entry| entry.key().0 == namespace && entry.key().1 == role)
                    .take(take)
                    .map(|entry| entry.key().2)
                    .collect()
            }))
        })
    }

    pub fn list_fixed_identity_names(
        namespace: &str,
        caller: &Principal,
        prev: Option<String>,
        take: usize,
    ) -> Result<Vec<String>, String> {
        with(&namespace.to_string(), |ns| {
            if !ns.can_read_namespace(namespace, caller) {
                return Err("no permission".to_string());
            }
            if ns.acl_version == 0 {
                return Ok(ns
                    .fixed_id_names
                    .iter()
                    .filter(|(_, principals)| {
                        principals
                            .iter()
                            .any(|principal| *principal != Principal::anonymous())
                    })
                    .map(|(name, _)| name)
                    .filter(|name| prev.as_ref().is_none_or(|cursor| *name > cursor))
                    .take(take)
                    .cloned()
                    .collect());
            }

            let start_name = prev.clone().unwrap_or_default();
            Ok(FIXED_IDENTITY_STORE.with_borrow(|store| {
                let mut last_name: Option<String> = None;
                store
                    .range(ops::RangeFrom {
                        start: FixedIdentityKey(
                            namespace.to_string(),
                            start_name,
                            Principal::management_canister(),
                        ),
                    })
                    .take_while(|entry| entry.key().0 == namespace)
                    .filter_map(|entry| {
                        let name = &entry.key().1;
                        if prev.as_ref().is_some_and(|cursor| name <= cursor)
                            || last_name.as_ref() == Some(name)
                        {
                            return None;
                        }
                        last_name = Some(name.clone());
                        Some(name.clone())
                    })
                    .take(take)
                    .collect()
            }))
        })
    }

    pub fn get_delegators(
        namespace: &str,
        name: &str,
        caller: &Principal,
    ) -> Result<BTreeSet<Principal>, String> {
        with(&namespace.to_string(), |ns| {
            if !ns.can_read_namespace(namespace, caller) {
                return Err("no permission".to_string());
            }
            let values: BTreeSet<Principal> = if ns.acl_version == 0 {
                ns.fixed_id_names
                    .get(name)
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|principal| *principal != Principal::anonymous())
                    .collect()
            } else {
                FIXED_IDENTITY_STORE.with_borrow(|store| {
                    store
                        .range(ops::RangeFrom {
                            start: FixedIdentityKey(
                                namespace.to_string(),
                                name.to_string(),
                                Principal::management_canister(),
                            ),
                        })
                        .take_while(|entry| entry.key().0 == namespace && entry.key().1 == name)
                        .map(|entry| entry.key().2)
                        .collect()
                })
            };
            if values.is_empty() {
                Err("NotFound: name not found".to_string())
            } else {
                Ok(values)
            }
        })
    }

    pub fn mutate_delegators(
        namespace: String,
        name: String,
        caller: &Principal,
        values: BTreeSet<Principal>,
        add: bool,
        now_ms: u64,
    ) -> Result<BTreeSet<Principal>, String> {
        with_mut(namespace.clone(), |ns| {
            if !ns.can_manage_namespace(&namespace, caller) {
                return Err("no permission".to_string());
            }
            let current = if ns.acl_version == 0 {
                ns.fixed_id_names.get(&name).cloned().unwrap_or_default()
            } else {
                FIXED_IDENTITY_STORE.with_borrow(|store| {
                    store
                        .range(ops::RangeFrom {
                            start: FixedIdentityKey(
                                namespace.clone(),
                                name.clone(),
                                Principal::management_canister(),
                            ),
                        })
                        .take_while(|entry| entry.key().0 == namespace && entry.key().1 == name)
                        .map(|entry| entry.key().2)
                        .collect()
                })
            };
            let current_len = current.len();
            let current_total = if ns.acl_version == 0 {
                ns.fixed_id_names.values().map(BTreeSet::len).sum::<usize>()
            } else {
                ns.fixed_delegator_count as usize
            };
            let mut next = current;
            if add {
                next.extend(values.iter().copied());
                if next.len() > MAX_NAMESPACE_FIXED_DELEGATORS
                    || current_total
                        .saturating_sub(current_len)
                        .saturating_add(next.len())
                        > MAX_NAMESPACE_FIXED_DELEGATORS
                {
                    return Err("fixed identity delegators exceed the namespace limit".to_string());
                }
            } else {
                next.retain(|principal| !values.contains(principal));
            }
            let next_total = current_total
                .saturating_sub(current_len)
                .saturating_add(next.len());
            ensure_acl_v1(&namespace, ns);
            FIXED_IDENTITY_STORE.with_borrow_mut(|store| {
                for principal in values {
                    let key = FixedIdentityKey(namespace.clone(), name.clone(), principal);
                    if add {
                        store.insert(key, 0);
                    } else {
                        store.remove(&key);
                    }
                }
            });
            ns.fixed_delegator_count = next_total as u32;
            ns.updated_at = now_ms;
            Ok(next)
        })
    }

    pub fn delegation_session_expiry(
        namespace: &str,
        name: &str,
        caller: &Principal,
    ) -> Result<u64, String> {
        if caller == &Principal::anonymous() {
            return Err("anonymous user is not a delegator".to_string());
        }
        with(&namespace.to_string(), |ns| {
            let allowed = if ns.acl_version == 0 {
                ns.fixed_id_names
                    .get(name)
                    .is_some_and(|delegators| delegators.contains(caller))
            } else {
                FIXED_IDENTITY_STORE.with_borrow(|store| {
                    store.contains_key(&FixedIdentityKey(
                        namespace.to_string(),
                        name.to_string(),
                        *caller,
                    ))
                })
            };
            if allowed {
                Ok(ns.session_expires_in_ms)
            } else {
                Err(format!("caller {} is not a delegator", caller))
            }
        })
    }

    pub(super) fn debit_namespace_cycles(
        ns: &mut Namespace,
        amount: u128,
        liquid: u128,
        threshold: u128,
    ) -> Result<(), String> {
        let required = threshold
            .checked_add(amount)
            .ok_or_else(|| "cycle reserve calculation overflowed".to_string())?;
        if liquid < required {
            return Err(format!(
                "insufficient liquid cycles: balance {liquid}, required {required}"
            ));
        }
        if ns.gas_balance < amount {
            return Err(format!(
                "insufficient namespace gas: balance {}, required {}",
                ns.gas_balance, amount
            ));
        }
        ns.gas_balance -= amount;
        Ok(())
    }

    fn charge_namespace_cycles(namespace: &str, amount: u128) -> Result<(), String> {
        let threshold = state::with(|s| u128::from(s.freezing_threshold));
        let liquid = ic_cdk::api::canister_liquid_cycle_balance();
        with_mut(namespace.to_string(), |ns| {
            debit_namespace_cycles(ns, amount, liquid, threshold)?;
            ensure_acl_v1(namespace, ns);
            Ok(())
        })
    }

    fn management_call_cost(method: &str, payload_bytes: usize) -> u128 {
        ic_cdk::api::cost_call(method.len() as u64, payload_bytes as u64)
    }

    pub fn charge_raw_rand(namespace: &str) -> Result<(), String> {
        charge_namespace_cycles(namespace, management_call_cost("raw_rand", 0))
    }

    pub fn top_up_namespace(
        namespace: String,
        requested: u128,
        available: u128,
        now_ms: u64,
    ) -> Result<u128, String> {
        if requested > available {
            return Err("insufficient cycles".to_string());
        }
        with_mut(namespace.clone(), |ns| {
            ns.gas_balance
                .checked_add(requested)
                .ok_or_else(|| "namespace gas balance overflowed".to_string())?;
            ensure_acl_v1(&namespace, ns);
            let received = ic_cdk::api::msg_cycles_accept(requested);
            ns.gas_balance = ns
                .gas_balance
                .checked_add(received)
                .expect("accepted cycles were pre-validated against the gas balance");
            ns.updated_at = now_ms;
            Ok(received)
        })
    }

    pub fn migrate(m: BTreeMap<String, NamespaceLegacy>) {
        if m.is_empty() {
            return;
        }

        NAMESPACES_STORE.with_borrow_mut(|r| {
            for (name, ns) in m {
                let mut nns = Namespace {
                    desc: ns.desc,
                    created_at: ns.created_at,
                    updated_at: ns.updated_at,
                    max_payload_size: ns.max_payload_size,
                    payload_bytes_total: ns.payload_bytes_total,
                    status: ns.status,
                    visibility: ns.visibility,
                    managers: ns.managers,
                    auditors: ns.auditors,
                    users: ns.users,
                    gas_balance: ns.gas_balance,
                    fixed_id_names: ns.fixed_id_names,
                    session_expires_in_ms: ns.session_expires_in_ms,
                    ..Default::default()
                };
                ensure_acl_v1(&name, &mut nns);
                r.insert(name.clone(), nns);
                for (k, setting) in ns.settings {
                    let spk = SettingPathKey(name.clone(), 0, k.0, k.1, 0);
                    save_setting(spk, setting);
                }
                for (k, setting) in ns.user_settings {
                    let spk = SettingPathKey(name.clone(), 1, k.0, k.1, 0);
                    save_setting(spk, setting);
                }
            }
        });
    }

    pub fn namespace_count() -> u64 {
        NAMESPACES_STORE.with_borrow(|r| r.len())
    }

    pub fn migrate_legacy_settings(take: usize) -> u64 {
        let keys: Vec<SettingPathKey> =
            SETTINGS_STORE.with_borrow(|store| store.keys().take(take).collect());
        for key in &keys {
            if let Some(setting) = SETTINGS_STORE.with_borrow(|store| store.get(key)) {
                save_setting(key.clone(), setting);
            }
        }
        keys.len() as u64
    }

    pub fn migrate_legacy_namespace_acls(take: usize) -> u64 {
        let names: Vec<String> = NAMESPACES_STORE.with_borrow(|store| {
            store
                .iter()
                .filter_map(|entry| (entry.value().acl_version == 0).then(|| entry.key().clone()))
                .take(take)
                .collect()
        });
        for name in &names {
            let _ = with_mut(name.clone(), |namespace| {
                ensure_acl_v1(name, namespace);
                Ok(())
            });
        }
        names.len() as u64
    }

    pub fn rebuild_payload_bytes(namespace: String, caller: &Principal) -> Result<u64, String> {
        with_mut(namespace.clone(), |ns| {
            if !ns.can_manage_namespace(&namespace, caller) {
                return Err("no permission".to_string());
            }
            let start = SettingPathKey(
                namespace.clone(),
                0,
                Principal::management_canister(),
                ByteBuf::new(),
                0,
            );
            let legacy = SETTINGS_STORE.with_borrow(|store| {
                store
                    .range(ops::RangeFrom {
                        start: start.clone(),
                    })
                    .take_while(|entry| entry.key().0 == namespace)
                    .fold(0u64, |total, entry| {
                        total.saturating_add(entry.value().data_size())
                    })
            });
            let current = SETTING_DATA_STORE.with_borrow(|store| {
                store
                    .range(ops::RangeFrom {
                        start: start.clone(),
                    })
                    .take_while(|entry| entry.key().0 == namespace)
                    .fold(0u64, |total, entry| {
                        total.saturating_add(entry.value().size() as u64)
                    })
            });
            let archived = PAYLOADS_STORE.with_borrow(|store| {
                store
                    .range(ops::RangeFrom { start })
                    .take_while(|entry| entry.key().0 == namespace)
                    .fold(0u64, |total, entry| {
                        total.saturating_add(entry.value().data_size())
                    })
            });
            let total = legacy.saturating_add(current).saturating_add(archived);
            ensure_acl_v1(&namespace, ns);
            ns.payload_bytes_total = total;
            Ok(total)
        })
    }

    const MAX_KEY: [u8; 64] = [255u8; 64];

    fn signing_derivation_path(
        domain: &[u8],
        namespace: String,
        suffix: Vec<ByteBuf>,
    ) -> Vec<Vec<u8>> {
        let mut path = Vec::with_capacity(suffix.len() + 2);
        path.push(domain.to_vec());
        path.push(namespace.into_bytes());
        path.extend(suffix.into_iter().map(ByteBuf::into_vec));
        path
    }

    #[cfg(test)]
    pub fn list_setting_keys(
        namespace: &str,
        user_owned: bool,
        subject: Option<Principal>,
    ) -> Vec<(Principal, ByteBuf)> {
        list_setting_keys_page(namespace, user_owned, subject, None, usize::MAX)
    }

    pub fn list_setting_keys_page(
        namespace: &str,
        user_owned: bool,
        subject: Option<Principal>,
        prev: Option<(Principal, ByteBuf)>,
        take: usize,
    ) -> Vec<(Principal, ByteBuf)> {
        let kind = u8::from(user_owned);
        let start = SettingPathKey(
            namespace.to_owned(),
            kind,
            subject.unwrap_or_else(Principal::management_canister),
            ByteBuf::new(),
            0,
        );
        let lower = prev
            .map(|(principal, key)| {
                std::ops::Bound::Excluded(SettingPathKey(
                    namespace.to_owned(),
                    kind,
                    principal,
                    key,
                    u32::MAX,
                ))
            })
            .unwrap_or(std::ops::Bound::Included(start));
        let upper = if let Some(subject) = subject {
            std::ops::Bound::Included(SettingPathKey(
                namespace.to_owned(),
                kind,
                subject,
                ByteBuf::from(MAX_KEY.as_ref()),
                u32::MAX,
            ))
        } else {
            std::ops::Bound::Excluded(SettingPathKey(
                namespace.to_owned(),
                kind + 1,
                Principal::management_canister(),
                ByteBuf::new(),
                0,
            ))
        };
        let legacy = SETTINGS_STORE.with_borrow(|store| {
            store
                .keys_range((lower.clone(), upper.clone()))
                .take(take)
                .collect::<Vec<_>>()
        });
        let modern = SETTING_META_STORE.with_borrow(|store| {
            store
                .keys_range((lower, upper))
                .take(take)
                .collect::<Vec<_>>()
        });
        legacy
            .into_iter()
            .chain(modern)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(take)
            .map(|key| (key.2, key.3))
            .collect()
    }

    pub fn with<R>(
        namespace: &String,
        f: impl FnOnce(Namespace) -> Result<R, String>,
    ) -> Result<R, String> {
        NAMESPACES_STORE.with_borrow(|r| {
            r.get(namespace)
                .map(f)
                .unwrap_or_else(|| Err(format!("NotFound: namespace {} not found", namespace)))
        })
    }

    pub fn with_mut<R>(
        namespace: String,
        f: impl FnOnce(&mut Namespace) -> Result<R, String>,
    ) -> Result<R, String> {
        NAMESPACES_STORE.with_borrow_mut(|r| match r.get(&namespace) {
            Some(mut ns) => match f(&mut ns) {
                Ok(rt) => {
                    r.insert(namespace, ns);
                    Ok(rt)
                }
                Err(err) => Err(err),
            },
            None => Err(format!("NotFound: namespace {} not found", namespace)),
        })
    }

    pub fn has_kek_permission(caller: &Principal, spk: &SettingPathKey) -> bool {
        with(&spk.0, |ns| {
            if ns.status < 0 && !ns.has_role(&spk.0, ROLE_MANAGER, caller) {
                return Ok(false);
            }

            if caller == &spk.2
                || ns.has_role(&spk.0, ROLE_AUDITOR, caller)
                || (spk.1 == 0 && ns.has_role(&spk.0, ROLE_MANAGER, caller))
            {
                return Ok(true);
            }

            let setting = load_setting_metadata(&spk.v0()).map(|(setting, _)| setting);
            Ok(setting.is_some_and(|s| s.readers.contains(caller)))
        })
        .unwrap_or(false)
    }

    pub fn ecdsa_public_key(
        caller: &Principal,
        namespace: String,
        derivation_path: Vec<ByteBuf>,
    ) -> Result<PublicKeyOutput, String> {
        ic_cose_types::types::validate_derivation_path(&derivation_path)?;
        with(&namespace, |ns| {
            if !ns.can_read_namespace(&namespace, caller) {
                Err("no permission".to_string())?;
            }
            Ok(())
        })?;

        state::with(|s| {
            let pk = s.ecdsa_public_key.as_ref().ok_or("no ecdsa public key")?;
            let path = signing_derivation_path(b"COSE_ECDSA_Signing", namespace, derivation_path);
            derive_public_key(pk, path)
        })
    }

    pub async fn ecdsa_sign_with(
        caller: &Principal,
        namespace: String,
        derivation_path: Vec<ByteBuf>,
        message: ByteBuf,
    ) -> Result<ByteBuf, String> {
        if message.len() != 32 {
            return Err("message must be 32 bytes".to_string());
        }
        ic_cose_types::types::validate_derivation_path(&derivation_path)?;
        with(&namespace, |ns| {
            if !ns.has_ns_signing_permission(&namespace, caller) {
                Err("no permission".to_string())?;
            }
            Ok(())
        })?;

        let key_name = state::with(|s| s.ecdsa_key_name.clone());
        let path =
            signing_derivation_path(b"COSE_ECDSA_Signing", namespace.clone(), derivation_path);
        charge_namespace_cycles(
            &namespace,
            sign_with_ecdsa_cost(&key_name, &path, &message)?,
        )?;
        let sig = sign_with_ecdsa(key_name, path, message.into_vec()).await?;
        Ok(ByteBuf::from(sig))
    }

    pub fn schnorr_public_key(
        caller: &Principal,
        alg: SchnorrAlgorithm,
        namespace: String,
        derivation_path: Vec<ByteBuf>,
    ) -> Result<PublicKeyOutput, String> {
        ic_cose_types::types::validate_derivation_path(&derivation_path)?;
        with(&namespace, |ns| {
            if !ns.can_read_namespace(&namespace, caller) {
                Err("no permission".to_string())?;
            }
            Ok(())
        })?;

        state::with(|s| {
            let pk = match alg {
                SchnorrAlgorithm::Bip340secp256k1 => s
                    .schnorr_secp256k1_public_key
                    .as_ref()
                    .ok_or("no schnorr secp256k1 public key")?,
                SchnorrAlgorithm::Ed25519 => s
                    .schnorr_ed25519_public_key
                    .as_ref()
                    .ok_or("no schnorr ed25519 public key")?,
            };
            let path = signing_derivation_path(b"COSE_Schnorr_Signing", namespace, derivation_path);
            derive_schnorr_public_key(alg, pk, path)
        })
    }

    pub async fn schnorr_sign_with(
        caller: &Principal,
        alg: SchnorrAlgorithm,
        namespace: String,
        derivation_path: Vec<ByteBuf>,
        message: ByteBuf,
    ) -> Result<ByteBuf, String> {
        ic_cose_types::types::validate_derivation_path(&derivation_path)?;
        with(&namespace, |ns| {
            if !ns.has_ns_signing_permission(&namespace, caller) {
                Err("no permission".to_string())?;
            }
            Ok(())
        })?;

        let key_name = state::with(|s| s.schnorr_key_name.clone());
        let path =
            signing_derivation_path(b"COSE_Schnorr_Signing", namespace.clone(), derivation_path);
        charge_namespace_cycles(
            &namespace,
            sign_with_schnorr_cost(&key_name, alg, &path, &message)?,
        )?;
        let sig = sign_with_schnorr(key_name, alg, path, message.into_vec()).await?;
        Ok(ByteBuf::from(sig))
    }

    const CWT_EXPIRATION_SECONDS: i64 = 3600;
    fn identity_permission(namespace: &String, caller: &Principal) -> Result<String, String> {
        with(namespace, |ns| {
            if ns.has_role(namespace, ROLE_MANAGER, caller) {
                Ok(format!("Namespace.*:{namespace}"))
            } else if ns.has_role(namespace, ROLE_USER, caller) {
                if ns.has_role(namespace, ROLE_AUDITOR, caller) {
                    Ok(format!(
                        "Namespace.Read:{namespace} Namespace.*.SubjectedSetting:{namespace}"
                    ))
                } else {
                    Ok(format!(
                        "Namespace.Read.Info:{namespace} Namespace.*.SubjectedSetting:{namespace}"
                    ))
                }
            } else if ns.has_role(namespace, ROLE_AUDITOR, caller) {
                Ok(format!("Namespace.Read:{namespace}"))
            } else {
                Err("no permission".to_string())
            }
        })
    }

    pub async fn sign_identity(
        caller: &Principal,
        namespace: String,
        audience: String,
        algorithm: SchnorrAlgorithm,
    ) -> Result<ByteBuf, String> {
        let cose_algorithm = identity_cose_algorithm(algorithm)?;
        identity_permission(&namespace, caller)?;

        let key_name = state::with(|s| s.schnorr_key_name.clone());
        charge_raw_rand(&namespace)?;
        let cwt_id: [u8; 16] = rand_bytes().await?;
        // `raw_rand` is an await boundary: roles may have changed while this
        // message was suspended, before the expensive signature is dispatched.
        let permission = identity_permission(&namespace, caller)?;
        let now_sec = (ic_cdk::api::time() / MILLISECONDS / 1000) as i64;
        let claims = ClaimsSet {
            issuer: Some(ic_cdk::api::canister_self().to_text()),
            subject: Some(caller.to_text()),
            audience: Some(audience.into()),
            expiration: Some((now_sec + CWT_EXPIRATION_SECONDS).into()),
            not_before: Some(now_sec.into()),
            issued_at: Some(now_sec.into()),
            cwt_id: Some(cwt_id.into()),
            extra: scope_claim(permission),
        };
        let payload = claims.to_vec().map_err(format_error)?;
        let mut sign1 = cose_sign1(payload, cose_algorithm, None)?;
        let tbs_data = sign1
            .prepare_signature(None, None, Some(caller.as_slice()))
            .map_err(format_error)?;
        charge_namespace_cycles(
            &namespace,
            sign_with_schnorr_cost(&key_name, algorithm, &[], &tbs_data)?,
        )?;
        let sig = sign_with_schnorr(key_name, algorithm, vec![], tbs_data).await?;
        sign1.set_signature(sig).map_err(format_error)?;
        let token = sign1.to_vec().map_err(format_error)?;
        Ok(ByteBuf::from(token))
    }

    pub fn inner_derive_kek(spk: &SettingPathKey, key_id: &[u8]) -> Result<[u8; 32], String> {
        state::with(|s| {
            if *s.init_vector == [0u8; 32] {
                return Err("key derivation is not initialized".to_string());
            }
            let pk = s
                .schnorr_secp256k1_public_key
                .as_ref()
                .ok_or("no schnorr secp256k1 public key")?;

            let derivation_path = vec![
                b"COSE_Symmetric_Key".to_vec(),
                s.init_vector.to_vec(),
                spk.2.as_slice().to_vec(),
                vec![spk.1],
                spk.0.as_bytes().to_vec(),
            ];
            let pk =
                derive_schnorr_public_key(SchnorrAlgorithm::Bip340secp256k1, pk, derivation_path)?;
            Ok(mac3_256(&pk.public_key, key_id))
        })
    }

    pub async fn inner_vetkd_public_key(spk: &SettingPathKey) -> Result<Vec<u8>, String> {
        let (key_name, context_version) =
            state::with(|r| (r.vetkd_key_name.clone(), r.vetkd_context_version));
        let context = [
            b"COSE_Symmetric_Key".as_slice(),
            spk.2.as_slice(),
            &[spk.1],
            spk.0.as_bytes(),
        ];
        charge_namespace_cycles(
            &spk.0,
            vetkd_public_key_cost(&key_name, context_version, &context)?,
        )?;
        vetkd_public_key(key_name, context_version, &context).await
    }

    pub async fn inner_vetkd_encrypted_key(
        spk: &SettingPathKey,
        key_id: Vec<u8>,
        transport_public_key: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let (key_name, context_version) =
            state::with(|r| (r.vetkd_key_name.clone(), r.vetkd_context_version));
        let context = [
            b"COSE_Symmetric_Key".as_slice(),
            spk.2.as_slice(),
            &[spk.1],
            spk.0.as_bytes(),
        ];
        let cost = vetkd_derive_key_cost(
            &key_name,
            context_version,
            &context,
            &key_id,
            &transport_public_key,
        )?;
        charge_namespace_cycles(&spk.0, cost)?;

        vetkd_encrypted_key(
            key_name,
            context_version,
            &context,
            key_id,
            transport_public_key,
        )
        .await
    }

    pub fn get_namespace(caller: &Principal, namespace: String) -> Result<NamespaceInfo, String> {
        with(&namespace, |ns| {
            if !ns.can_read_namespace(&namespace, caller) {
                Err("no permission".to_string())?;
            }
            Ok(namespace_info_bounded(namespace.clone(), ns))
        })
    }

    pub fn get_namespace_v2(
        caller: &Principal,
        namespace: String,
        with_members: bool,
    ) -> Result<NamespaceInfo, String> {
        with(&namespace, |ns| {
            if !ns.can_read_namespace(&namespace, caller) {
                return Err("no permission".to_string());
            }
            if with_members {
                if ns.info_size_hint() > MAX_NAMESPACE_PAGE_BYTES {
                    return Err(
                        "namespace members exceed one response; use paginated member methods"
                            .to_string(),
                    );
                }
                Ok(namespace_info(namespace.clone(), ns))
            } else {
                Ok(namespace_summary(namespace.clone(), ns))
            }
        })
    }

    pub fn list_namespaces(prev: Option<String>, take: usize) -> Vec<NamespaceInfo> {
        NAMESPACES_STORE.with_borrow(|r| {
            let mut res = Vec::with_capacity(take);
            let mut estimated_bytes = 0usize;
            match prev {
                Some(p) => {
                    for e in r.range(ops::RangeTo { end: p }).rev() {
                        let value = e.value();
                        let item_bytes = value.info_size_hint();
                        if !res.is_empty()
                            && estimated_bytes.saturating_add(item_bytes) > MAX_NAMESPACE_PAGE_BYTES
                        {
                            break;
                        }
                        estimated_bytes = estimated_bytes.saturating_add(item_bytes);
                        res.push(namespace_info_bounded(e.key().clone(), value));
                        if res.len() >= take {
                            break;
                        }
                    }
                }
                None => {
                    for e in r.iter().rev() {
                        let value = e.value();
                        let item_bytes = value.info_size_hint();
                        if !res.is_empty()
                            && estimated_bytes.saturating_add(item_bytes) > MAX_NAMESPACE_PAGE_BYTES
                        {
                            break;
                        }
                        estimated_bytes = estimated_bytes.saturating_add(item_bytes);
                        res.push(namespace_info_bounded(e.key().clone(), value));
                        if res.len() >= take {
                            break;
                        }
                    }
                }
            };
            res
        })
    }

    pub fn create_namespace(
        input: CreateNamespaceInput,
        now_ms: u64,
    ) -> Result<NamespaceInfo, String> {
        NAMESPACES_STORE.with_borrow_mut(|r| {
            if r.contains_key(&input.name) {
                Err(format!("namespace {} already exists", input.name))?;
            }
            let mut ns = Namespace {
                desc: input.desc.unwrap_or_default(),
                created_at: now_ms,
                updated_at: now_ms,
                max_payload_size: input.max_payload_size.unwrap_or(MAX_PAYLOAD_SIZE),
                visibility: input.visibility,
                managers: input.managers,
                auditors: input.auditors,
                users: input.users,
                session_expires_in_ms: input.session_expires_in_ms.unwrap_or(SESSION_EXPIRES_IN_MS),
                ..Default::default()
            };

            if ns.encoded_size_hint() > MAX_NAMESPACE_RECORD_BYTES {
                return Err(format!(
                    "namespace record exceeds the limit {} bytes",
                    MAX_NAMESPACE_RECORD_BYTES
                ));
            }
            ensure_acl_v1(&input.name, &mut ns);
            let info = namespace_info(input.name.clone(), ns.clone());
            r.insert(input.name, ns);
            Ok(info)
        })
    }

    pub fn update_namespace_info(
        caller: &Principal,
        input: UpdateNamespaceInput,
        now_ms: u64,
    ) -> Result<(), String> {
        let namespace = input.name.clone();
        with_mut(namespace.clone(), |ns| {
            if !ns.can_manage_namespace(&namespace, caller) {
                Err("no permission".to_string())?;
            }

            ensure_acl_v1(&namespace, ns);

            if let Some(desc) = input.desc {
                ns.desc = desc;
            }
            if let Some(max_payload_size) = input.max_payload_size {
                ns.max_payload_size = max_payload_size;
            }
            if let Some(status) = input.status {
                ns.status = status;
            }
            if let Some(visibility) = input.visibility {
                ns.visibility = visibility;
            }
            if let Some(session_expires_in_ms) = input.session_expires_in_ms {
                ns.session_expires_in_ms = session_expires_in_ms;
            }
            ns.updated_at = now_ms;
            Ok(())
        })
    }

    pub fn delete_namespace(caller: &Principal, namespace: String) -> Result<(), String> {
        NAMESPACES_STORE.with_borrow_mut(|r| match r.get(&namespace) {
            Some(ns) => {
                if !ns.can_manage_namespace(&namespace, caller) {
                    Err("no permission".to_string())?;
                }
                let has_legacy = SETTINGS_STORE.with_borrow(|rr| {
                    // the range is open-ended, so the first key it yields may already
                    // belong to a later namespace: only a key still carrying this
                    // namespace means the namespace is not empty.
                    let mut iter = rr.keys_range(ops::RangeFrom {
                        start: &SettingPathKey(
                            namespace.clone(),
                            0,
                            Principal::management_canister(), // the smallest principal
                            ByteBuf::new(),
                            0,
                        ),
                    });
                    iter.next().is_some_and(|k| k.0 == namespace)
                });
                let has_modern = SETTING_META_STORE.with_borrow(|rr| {
                    let mut iter = rr.keys_range(ops::RangeFrom {
                        start: &SettingPathKey(
                            namespace.clone(),
                            0,
                            Principal::management_canister(),
                            ByteBuf::new(),
                            0,
                        ),
                    });
                    iter.next().is_some_and(|k| k.0 == namespace)
                });
                if has_legacy || has_modern {
                    return Err(format!("namespace {} is not empty", namespace));
                }
                remove_namespace_acl(&namespace);
                r.remove(&namespace);
                Ok(())
            }
            None => Err(format!("NotFound: namespace {} not found", namespace)),
        })
    }

    fn try_get_setting(
        caller: &Principal,
        spk: &SettingPathKey,
        with_data: bool,
    ) -> Option<Setting> {
        with(&spk.0, |ns| {
            let can = ns.partial_can_read_setting(caller, spk);
            if can == Some(false) {
                return Ok(None);
            }

            let key = spk.v0();
            let setting = load_setting_metadata(&key).and_then(|(mut setting, legacy)| {
                if spk.4 > setting.version
                    || (can != Some(true) && !setting.readers.contains(caller))
                {
                    return None;
                }
                if with_data && !legacy {
                    if let Some(data) = SETTING_DATA_STORE.with_borrow(|store| store.get(&key)) {
                        setting.payload = data.payload;
                        setting.dek = data.dek;
                    }
                }
                Some(setting)
            });
            Ok(setting)
        })
        .unwrap_or(None)
    }

    pub fn get_setting_info(caller: Principal, spk: SettingPathKey) -> Result<SettingInfo, String> {
        let setting = try_get_setting(&caller, &spk, false)
            .ok_or_else(|| format!("NotFound: setting {} not found or no permission", spk))?;

        Ok(setting.into_info(spk.2, spk.3, false))
    }

    pub fn get_setting(caller: Principal, spk: SettingPathKey) -> Result<SettingInfo, String> {
        let setting = try_get_setting(&caller, &spk, true)
            .ok_or_else(|| format!("NotFound: setting {} not found or no permission", spk))?;

        if spk.4 != 0 && spk.4 != setting.version {
            Err("version mismatch".to_string())?;
        };

        Ok(setting.into_info(spk.2, spk.3, true))
    }

    pub fn get_setting_archived_payload(
        caller: Principal,
        spk: SettingPathKey,
    ) -> Result<SettingArchivedPayload, String> {
        let setting = try_get_setting(&caller, &spk, false)
            .ok_or_else(|| format!("NotFound: setting {} not found or no permission", spk))?;

        if spk.4 == 0 || spk.4 >= setting.version {
            Err("version mismatch".to_string())?;
        };

        let payload = PAYLOADS_STORE.with_borrow(|r| {
            r.get(&spk)
                .ok_or_else(|| format!("NotFound: setting {} payload not found", spk))
        })?;

        Ok(SettingArchivedPayload {
            version: spk.4,
            archived_at: payload.archived_at,
            deprecated: payload.deprecated,
            payload: payload.payload,
            dek: payload.dek,
        })
    }

    pub fn create_setting(
        caller: Principal,
        spk: SettingPathKey,
        input: CreateSettingInput,
        now_ms: u64,
    ) -> Result<CreateSettingOutput, String> {
        with_mut(spk.0.clone(), |ns| {
            if !ns.can_write_setting(&caller, &spk) {
                Err("no permission".to_string())?;
            }

            if spk.4 != 0 {
                Err("version mismatch".to_string())?;
            }

            if let Some(ref payload) = input.payload {
                if payload.len() as u64 > ns.max_payload_size {
                    Err("payload size exceeds the limit".to_string())?;
                }
            }

            let size = match input.dek {
                Some(ref dek) => {
                    // should be valid COSE encrypt0 dek
                    try_decode_encrypt0(dek)?;
                    // should be valid COSE encrypt0 payload
                    if let Some(ref payload) = input.payload {
                        try_decode_encrypt0(payload)?;
                        payload.len() + dek.len()
                    } else {
                        dek.len()
                    }
                }
                None => input
                    .payload
                    .as_ref()
                    .map(|payload| payload.len())
                    .unwrap_or(0),
            };

            if contains_setting(&spk) {
                return Err(format!("setting {} already exists", spk));
            }
            ensure_acl_v1(&spk.0, ns);
            save_setting(
                spk,
                Setting {
                    desc: input.desc.unwrap_or_default(),
                    created_at: now_ms,
                    updated_at: now_ms,
                    status: input.status.unwrap_or(0),
                    tags: input.tags.unwrap_or_default(),
                    payload: input.payload,
                    dek: input.dek,
                    version: 1,
                    ..Default::default()
                },
            );

            let output = CreateSettingOutput {
                created_at: now_ms,
                updated_at: now_ms,
                version: 1,
            };

            ns.payload_bytes_total = ns.payload_bytes_total.saturating_add(size as u64);
            Ok(output)
        })
    }

    pub fn with_setting_mut<R>(
        caller: &Principal,
        spk: &SettingPathKey,
        f: impl FnOnce(&mut Setting) -> Result<R, String>,
    ) -> Result<R, String> {
        with(&spk.0, |ns| {
            if !ns.can_write_setting(caller, spk) {
                Err("no permission".to_string())?;
            }

            let spkv0 = spk.v0();
            match load_setting_metadata(&spkv0) {
                Some((mut setting, was_legacy)) => {
                    if setting.version != spk.4 {
                        Err("version mismatch".to_string())?;
                    }
                    match f(&mut setting) {
                        Ok(rt) => {
                            save_setting_metadata(spkv0, setting, was_legacy);
                            Ok(rt)
                        }
                        Err(err) => Err(err),
                    }
                }
                None => Err(format!("NotFound: setting {} not found", spk)),
            }
        })
    }

    pub fn delete_setting(caller: &Principal, spk: &SettingPathKey) -> Result<(), String> {
        with_mut(spk.0.clone(), |ns| {
            if !ns.can_write_setting(caller, spk) {
                Err("no permission".to_string())?;
            }

            let spkv0 = spk.v0();
            match load_setting(&spkv0) {
                Some(setting) => {
                    if setting.version != spk.4 {
                        Err("version mismatch".to_string())?;
                    }
                    if setting.status >= 1 {
                        Err("readonly setting can not be deleted".to_string())?;
                    }

                    ensure_acl_v1(&spk.0, ns);
                    remove_setting(&spkv0);
                    let mut removed_bytes = setting.data_size();
                    if spk.4 > 1 {
                        PAYLOADS_STORE.with_borrow_mut(|rr| {
                            let mut pk = spk.clone();
                            for v in 1..spk.4 {
                                pk.4 = v;
                                if let Some(archived) = rr.remove(&pk) {
                                    removed_bytes =
                                        removed_bytes.saturating_add(archived.data_size());
                                }
                            }
                        });
                    }
                    ns.payload_bytes_total = ns.payload_bytes_total.saturating_sub(removed_bytes);

                    Ok(())
                }
                None => Err(format!("NotFound: setting {} not found", spk)),
            }
        })
    }

    pub fn update_setting_payload(
        caller: Principal,
        spk: SettingPathKey,
        input: UpdateSettingPayloadInput,
        now_ms: u64,
    ) -> Result<UpdateSettingOutput, String> {
        with_mut(spk.0.clone(), |ns| {
            if !ns.can_write_setting(&caller, &spk) {
                Err("no permission".to_string())?;
            }

            let mut size = if let Some(ref payload) = input.payload {
                payload.len()
            } else {
                0
            };
            if size as u64 > ns.max_payload_size {
                Err("payload size exceeds the limit".to_string())?;
            }
            if let Some(ref dek) = input.dek {
                size += dek.len();
                // A DEK is itself a COSE_Encrypt0 envelope. Reject malformed
                // data before reading or rewriting the current setting.
                try_decode_encrypt0(dek)?;
            }

            let spkv0 = spk.v0();
            let output = match load_setting(&spkv0) {
                Some(mut setting) => {
                    if setting.version != spk.4 {
                        Err("version mismatch".to_string())?;
                    }
                    if setting.status != 0 {
                        Err("setting is not writable".to_string())?;
                    }
                    if setting.version >= ic_cose_types::types::setting::MAX_SETTING_VERSIONS {
                        return Err("setting version limit reached".to_string());
                    }
                    let next_version = setting
                        .version
                        .checked_add(1)
                        .ok_or_else(|| "setting version exhausted".to_string())?;

                    if setting.dek.is_some() || input.dek.is_some() {
                        // When only the DEK changes, validate the retained payload
                        // as well; otherwise plaintext could be relabeled as encrypted.
                        if let Some(payload) = input.payload.as_ref().or(setting.payload.as_ref()) {
                            try_decode_encrypt0(payload)?;
                        }
                    }

                    ensure_acl_v1(&spk.0, ns);

                    if setting.payload.is_some() || setting.dek.is_some() {
                        PAYLOADS_STORE.with_borrow_mut(|r| {
                            r.insert(
                                spk.clone(),
                                SettingArchived {
                                    archived_at: now_ms,
                                    deprecated: input.deprecate_current.unwrap_or(false),
                                    payload: setting.payload.clone(),
                                    dek: setting.dek.clone(),
                                },
                            );
                        });
                    }

                    setting.version = next_version;
                    setting.updated_at = now_ms;
                    if let Some(status) = input.status {
                        setting.status = status;
                    }
                    if let Some(payload) = input.payload {
                        setting.payload = Some(payload);
                    }
                    if let Some(dek) = input.dek {
                        setting.dek = Some(dek);
                    }

                    size = setting.data_size() as usize;

                    let output = UpdateSettingOutput {
                        created_at: setting.created_at,
                        updated_at: setting.updated_at,
                        version: setting.version,
                    };
                    save_setting(spkv0, setting);
                    Ok(output)
                }
                None => Err(format!("NotFound: setting {} not found", spk)),
            }?;

            ns.payload_bytes_total = ns.payload_bytes_total.saturating_add(size as u64);
            Ok(output)
        })
    }

    pub fn update_setting_info(
        caller: Principal,
        spk: SettingPathKey,
        input: UpdateSettingInfoInput,
        now_ms: u64,
    ) -> Result<UpdateSettingOutput, String> {
        with_setting_mut(&caller, &spk, |setting| {
            if let Some(status) = input.status {
                setting.status = status;
            }
            if let Some(desc) = input.desc {
                setting.desc = desc;
            }
            if let Some(tags) = input.tags {
                setting.tags = tags;
            }
            setting.updated_at = now_ms;

            Ok(UpdateSettingOutput {
                created_at: setting.created_at,
                updated_at: setting.updated_at,
                version: setting.version,
            })
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
            NAMESPACES_STORE
                .with_borrow(|store| store.get(&namespace).unwrap().payload_bytes_total),
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
            NAMESPACES_STORE
                .with_borrow(|store| store.get(&namespace).unwrap().payload_bytes_total),
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
            ns::list_fixed_identity_names(&namespace, &second, Some("alpha".to_string()), 10,)
                .unwrap(),
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
        assert!(!ACL_STORE.with_borrow(|store| {
            store.contains_key(&AclKey(namespace, ROLE_MANAGER, manager))
        }));
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
}
