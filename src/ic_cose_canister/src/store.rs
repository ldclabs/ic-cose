use candid::Principal;
use ciborium::{from_reader, into_writer};
use ic_canister_sig_creation::{
    signature_map::{CanisterSigInputs, SignatureMap, LABEL_SIG},
    DELEGATION_SIG_DOMAIN,
};
use ic_cdk::api::certified_data_set;
use ic_certification::labeled_hash;
use ic_cose_types::{
    cose::{
        cwt::{ClaimsSet, Timestamp, SCOPE_NAME},
        encrypt0::try_decode_encrypt0,
        format_error, mac3_256, sha256,
        sign1::{cose_sign1, ES256K},
        CborSerializable,
    },
    types::{namespace::*, setting::*, state::StateInfo, PublicKeyOutput, SchnorrAlgorithm},
};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    DefaultMemoryImpl, StableBTreeMap, StableCell, Storable,
};
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug},
    ops,
};

use crate::{
    ecdsa::{derive_public_key, ecdsa_public_key, sign_with_ecdsa},
    rand_bytes,
    schnorr::{derive_schnorr_public_key, schnorr_public_key, sign_with_schnorr},
    vetkd::{vetkd_encrypted_key, vetkd_public_key},
};

const SESSION_EXPIRES_IN_MS: u64 = 1000 * 3600 * 24; // 1 day

type Memory = VirtualMemory<DefaultMemoryImpl>;

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
    pub subnet_size: u64,
    #[serde(rename = "f")]
    pub freezing_threshold: u64, // freezing writing threshold in cycles
    #[serde(default, rename = "iv")]
    pub init_vector: ByteArray<32>, // should not be exposed
    #[serde(default, rename = "gov")]
    pub governance_canister: Option<Principal>,
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
    pub gas_balance: u128, // gas balance, TODO: https://internetcomputer.org/docs/current/developer-docs/gas-cost
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
    pub gas_balance: u128, // gas balance, TODO: https://internetcomputer.org/docs/current/developer-docs/gas-cost
    #[serde(default, rename = "f")]
    pub fixed_id_names: BTreeMap<String, BTreeSet<Principal>>, // fixed_id_name -> users
    #[serde(default, rename = "se")]
    pub session_expires_in_ms: u64, // session expires in milliseconds
}

pub enum NamespaceReadPermission {
    Full,
    User,
    None,
}

impl Namespace {
    pub fn into_info(self, name: String) -> NamespaceInfo {
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
            gas_balance: self.gas_balance,
            fixed_id_names: self.fixed_id_names,
            session_expires_in_ms: self.session_expires_in_ms,
        }
    }

    pub fn read_permission(&self, caller: &Principal) -> NamespaceReadPermission {
        if self.visibility == 1 {
            return NamespaceReadPermission::Full;
        }

        if self.managers.contains(caller) || self.auditors.contains(caller) {
            NamespaceReadPermission::Full
        } else if self.status >= 0 && self.users.contains(caller) {
            NamespaceReadPermission::User
        } else {
            NamespaceReadPermission::None
        }
    }

    pub fn can_write_namespace(&self, caller: &Principal) -> bool {
        self.status < 1 && self.managers.contains(caller)
    }

    pub fn can_read_namespace(&self, caller: &Principal) -> bool {
        if self.visibility == 1 {
            return true;
        }

        if self.status < 0 {
            return self.managers.contains(caller) || self.auditors.contains(caller);
        }

        self.managers.contains(caller)
            || self.auditors.contains(caller)
            || self.users.contains(caller)
    }

    pub fn can_write_setting(&self, caller: &Principal, spk: &SettingPathKey) -> bool {
        if self.status != 0 {
            return false;
        }

        // only managers can create server side settings for any subject
        if spk.1 == 0 {
            return self.managers.contains(caller);
        }

        // users can create settings for themselves and update them
        self.users.contains(caller) && caller == &spk.2
    }

    fn partial_can_read_setting(&self, caller: &Principal, spk: &SettingPathKey) -> Option<bool> {
        if self.visibility == 1 {
            return Some(true);
        }

        if self.status < 0 {
            return Some(self.managers.contains(caller) || self.auditors.contains(caller));
        }

        if self.managers.contains(caller) || self.auditors.contains(caller) || caller == &spk.2 {
            return Some(true);
        }
        None
    }

    pub fn has_ns_signing_permission(&self, caller: &Principal) -> bool {
        if self.status < 0 && !self.managers.contains(caller) {
            return false;
        }
        self.managers.contains(caller) || self.users.contains(caller)
    }
}

impl Storable for Namespace {
    const BOUND: Bound = Bound::Unbounded;

    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        into_writer(self, &mut buf).expect("failed to encode Namespace data");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_reader(&bytes[..]).expect("failed to decode Namespace data")
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

    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        into_writer(self, &mut buf).expect("failed to encode Setting data");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_reader(&bytes[..]).expect("failed to decode Setting data")
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
}

impl Storable for SettingPathKey {
    const BOUND: Bound = Bound::Unbounded;

    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        into_writer(self, &mut buf).expect("failed to encode SettingPathKey data");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_reader(&bytes[..]).expect("failed to decode SettingPathKey data")
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
            const_hex::encode(&self.3),
            self.4
        )
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

impl Storable for SettingArchived {
    const BOUND: Bound = Bound::Unbounded;

    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        into_writer(self, &mut buf).expect("failed to encode SettingArchived data");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_reader(&bytes[..]).expect("failed to decode SettingArchived data")
    }
}

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const NSLEGACY_MEMORY_ID: MemoryId = MemoryId::new(1);
const PAYLOADS_MEMORY_ID: MemoryId = MemoryId::new(2);
const NAMESPACES_MEMORY_ID: MemoryId = MemoryId::new(3);
const SETTINGS_MEMORY_ID: MemoryId = MemoryId::new(4);

thread_local! {
    static SIGNATURES : RefCell<SignatureMap> = RefCell::new(SignatureMap::default());
    static STATE: RefCell<State> = RefCell::new(State::default());
    static NS: RefCell<BTreeMap<String, NamespaceLegacy>> = const { RefCell::new(BTreeMap::new()) };

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static STATE_STORE: RefCell<StableCell<Vec<u8>, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(STATE_MEMORY_ID)),
            Vec::new()
        ).expect("failed to init STATE_STORE store")
    );

    static NSLEGACY_STORE: RefCell<StableCell<Vec<u8>, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(NSLEGACY_MEMORY_ID)),
            Vec::new()
        ).expect("failed to init NS_STORE store")
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

    pub fn allowed_api(api: &str) -> Result<(), String> {
        if with(|s| s.allowed_apis.is_empty() || s.allowed_apis.contains(api)) {
            Ok(())
        } else {
            Err(format!("API {} not allowed", api))
        }
    }

    pub fn add_signature(seed: &[u8], message: &[u8]) {
        SIGNATURES.with_borrow_mut(|sigs| {
            let sig_inputs = CanisterSigInputs {
                domain: DELEGATION_SIG_DOMAIN,
                seed,
                message,
            };
            sigs.add_signature(&sig_inputs);

            certified_data_set(labeled_hash(LABEL_SIG, &sigs.root_hash()));
        });
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

    pub async fn init_public_key() {
        let (ecdsa_key_name, schnorr_key_name) =
            with(|r| (r.ecdsa_key_name.clone(), r.schnorr_key_name.clone()));

        let ecdsa_public_key = ecdsa_public_key(ecdsa_key_name, vec![])
            .await
            .map_err(|err| {
                ic_cdk::api::debug_print(format!("failed to retrieve ECDSA public key: {err}"))
            })
            .ok();

        let schnorr_ed25519_public_key =
            schnorr_public_key(schnorr_key_name.clone(), SchnorrAlgorithm::Ed25519, vec![])
                .await
                .map_err(|err| {
                    ic_cdk::api::debug_print(format!(
                        "failed to retrieve Schnorr Ed25519 public key: {err}"
                    ))
                })
                .ok();

        let schnorr_secp256k1_public_key =
            schnorr_public_key(schnorr_key_name, SchnorrAlgorithm::Bip340secp256k1, vec![])
                .await
                .map_err(|err| {
                    ic_cdk::api::debug_print(format!(
                        "failed to retrieve Schnorr Secp256k1 public key: {err}"
                    ))
                })
                .ok();

        let iv: [u8; 32] = rand_bytes().await.expect("failed to generate IV");

        with_mut(|r| {
            r.ecdsa_public_key = ecdsa_public_key;
            r.schnorr_ed25519_public_key = schnorr_ed25519_public_key;
            r.schnorr_secp256k1_public_key = schnorr_secp256k1_public_key;
            r.init_vector = iv.into();
        });
    }

    pub fn load() {
        STATE_STORE.with_borrow(|r| {
            STATE.with_borrow_mut(|h| {
                let v: State =
                    from_reader(&r.get()[..]).expect("failed to decode STATE_STORE data");
                *h = v;
            });
        });

        let count = NAMESPACES_STORE.with_borrow(|r| r.len());
        if count > 0 {
            return; // already migrated
        }
        NSLEGACY_STORE.with_borrow(|r| {
            let data = r.get();
            if data.is_empty() {
                return;
            }
            let m: BTreeMap<String, NamespaceLegacy> =
                from_reader(&data[..]).expect("failed to decode NS_STORE data");
            ns::migrate(m);
        });
    }

    pub fn save() {
        STATE.with_borrow(|h| {
            STATE_STORE.with_borrow_mut(|r| {
                let mut buf = vec![];
                into_writer(h, &mut buf).expect("failed to encode STATE_STORE data");
                r.set(buf).expect("failed to set STATE_STORE data");
            });
        });
    }
}

pub mod ns {
    use ic_cose_types::cose::iana::Algorithm::EdDSA;

    use super::*;

    pub fn migrate(m: BTreeMap<String, NamespaceLegacy>) {
        if m.is_empty() {
            return;
        }

        NAMESPACES_STORE.with_borrow_mut(|r| {
            SETTINGS_STORE.with_borrow_mut(|rs| {
                for (name, ns) in m {
                    let nns = Namespace {
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
                    };
                    r.insert(name.clone(), nns);
                    for (k, setting) in ns.settings {
                        let spk = SettingPathKey(name.clone(), 0, k.0, k.1, 0);
                        rs.insert(spk, setting);
                    }
                    for (k, setting) in ns.user_settings {
                        let spk = SettingPathKey(name.clone(), 1, k.0, k.1, 0);
                        rs.insert(spk, setting);
                    }
                }
            })
        });
    }

    pub fn namespace_count() -> u64 {
        NAMESPACES_STORE.with_borrow(|r| r.len())
    }

    const MAX_KEY: [u8; 64] = [255u8; 64];
    pub fn list_setting_keys(
        namespace: &str,
        user_owned: bool,
        subject: Option<Principal>,
    ) -> Vec<(Principal, ByteBuf)> {
        SETTINGS_STORE.with_borrow(|r| {
            let range = if let Some(subject) = subject {
                ops::Range {
                    start: &SettingPathKey(
                        namespace.to_owned(),
                        if user_owned { 1 } else { 0 },
                        subject,
                        ByteBuf::new(),
                        0,
                    ),
                    end: &SettingPathKey(
                        namespace.to_owned(),
                        if user_owned { 1 } else { 0 },
                        subject,
                        ByteBuf::from(MAX_KEY.as_ref()),
                        0,
                    ),
                }
            } else {
                ops::Range {
                    start: &SettingPathKey(
                        namespace.to_owned(),
                        if user_owned { 1 } else { 0 },
                        Principal::anonymous(),
                        ByteBuf::new(),
                        0,
                    ),
                    end: &SettingPathKey(
                        namespace.to_owned(),
                        if user_owned { 2 } else { 1 },
                        Principal::management_canister(),
                        ByteBuf::new(),
                        u32::MAX,
                    ),
                }
            };
            r.keys_range(range).map(|k| (k.2, k.3)).collect()
        })
    }

    pub fn with<R>(
        namespace: &String,
        f: impl FnOnce(Namespace) -> Result<R, String>,
    ) -> Result<R, String> {
        NAMESPACES_STORE.with_borrow(|r| {
            r.get(namespace)
                .map(f)
                .unwrap_or_else(|| Err(format!("namespace {} not found", namespace)))
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
            None => Err(format!("namespace {} not found", namespace)),
        })
    }

    pub fn has_kek_permission(caller: &Principal, spk: &SettingPathKey) -> bool {
        with(&spk.0, |ns| {
            if ns.status < 0 && !ns.managers.contains(caller) {
                return Ok(false);
            }

            if caller == &spk.2
                || ns.auditors.contains(caller)
                || (spk.1 == 0 && ns.managers.contains(caller))
            {
                return Ok(true);
            }

            let setting = SETTINGS_STORE.with_borrow(|m| m.get(&spk.v0()));
            Ok(setting.is_some_and(|s| s.readers.contains(caller)))
        })
        .unwrap_or(false)
    }

    pub fn ecdsa_public_key(
        caller: &Principal,
        namespace: String,
        derivation_path: Vec<ByteBuf>,
    ) -> Result<PublicKeyOutput, String> {
        with(&namespace, |ns| {
            if !ns.can_read_namespace(caller) {
                Err("no permission".to_string())?;
            }

            state::with(|s| {
                let pk = s.ecdsa_public_key.as_ref().ok_or("no ecdsa public key")?;
                let mut path: Vec<Vec<u8>> = Vec::with_capacity(derivation_path.len() + 3);
                path.push(b"COSE_ECDSA_Signing".to_vec());
                path.push(namespace.to_bytes().to_vec());
                path.extend(derivation_path.into_iter().map(|b| b.into_vec()));
                derive_public_key(pk, path)
            })
        })
    }

    pub async fn ecdsa_sign_with(
        caller: &Principal,
        namespace: String,
        derivation_path: Vec<ByteBuf>,
        message: ByteBuf,
    ) -> Result<ByteBuf, String> {
        with(&namespace, |ns| {
            if !ns.has_ns_signing_permission(caller) {
                Err("no permission".to_string())?;
            }
            Ok(())
        })?;

        let key_name = state::with(|s| s.ecdsa_key_name.clone());
        let mut path: Vec<Vec<u8>> = Vec::with_capacity(derivation_path.len() + 3);
        path.push(b"COSE_ECDSA_Signing".to_vec());
        path.push(namespace.to_bytes().to_vec());
        path.extend(derivation_path.into_iter().map(|b| b.into_vec()));
        let sig = sign_with_ecdsa(key_name, path, message.into_vec()).await?;
        Ok(ByteBuf::from(sig))
    }

    pub fn schnorr_public_key(
        caller: &Principal,
        alg: SchnorrAlgorithm,
        namespace: String,
        derivation_path: Vec<ByteBuf>,
    ) -> Result<PublicKeyOutput, String> {
        with(&namespace, |ns| {
            if !ns.can_read_namespace(caller) {
                Err("no permission".to_string())?;
            }

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
                let mut path: Vec<Vec<u8>> = Vec::with_capacity(derivation_path.len() + 3);
                path.push(b"COSE_Schnorr_Signing".to_vec());
                path.push(namespace.to_bytes().to_vec());
                path.extend(derivation_path.into_iter().map(|b| b.into_vec()));
                derive_schnorr_public_key(alg, pk, path)
            })
        })
    }

    pub async fn schnorr_sign_with(
        caller: &Principal,
        alg: SchnorrAlgorithm,
        namespace: String,
        derivation_path: Vec<ByteBuf>,
        message: ByteBuf,
    ) -> Result<ByteBuf, String> {
        with(&namespace, |ns| {
            if !ns.has_ns_signing_permission(caller) {
                Err("no permission".to_string())?;
            }
            Ok(())
        })?;

        let key_name = state::with(|s| s.schnorr_key_name.clone());
        let mut path: Vec<Vec<u8>> = Vec::with_capacity(derivation_path.len() + 3);
        path.push(b"COSE_Schnorr_Signing".to_vec());
        path.push(namespace.to_bytes().to_vec());
        path.extend(derivation_path.into_iter().map(|b| b.into_vec()));
        let sig = sign_with_schnorr(key_name, alg, path, message.into_vec()).await?;
        Ok(ByteBuf::from(sig))
    }

    const CWT_EXPIRATION_SECONDS: i64 = 3600;
    pub async fn sign_identity(
        caller: &Principal,
        namespace: String,
        audience: String,
        now_ms: u64,
        algorithm: SchnorrAlgorithm,
    ) -> Result<ByteBuf, String> {
        let permission = with(&namespace, |ns| {
            if ns.managers.contains(caller) {
                Ok(format!("Namespace.*:{}", namespace))
            } else if ns.users.contains(caller) {
                if ns.auditors.contains(caller) {
                    Ok(format!(
                        "Namespace.Read:{} Namespace.*.SubjectedSetting:{}",
                        namespace, namespace
                    ))
                } else {
                    Ok(format!(
                        "Namespace.Read.Info:{} Namespace.*.SubjectedSetting:{}",
                        namespace, namespace
                    ))
                }
            } else if ns.auditors.contains(caller) {
                Ok(format!("Namespace.Read:{}", namespace))
            } else {
                Err("no permission".to_string())
            }
        })?;

        let key_name = state::with(|s| s.schnorr_key_name.clone());
        let now_sec = (now_ms / 1000) as i64;
        let cwt_id: [u8; 16] = rand_bytes().await?;
        let claims = ClaimsSet {
            issuer: Some(ic_cdk::api::canister_self().to_text()),
            subject: Some(caller.to_text()),
            audience: Some(audience),
            expiration_time: Some(Timestamp::WholeSeconds(now_sec + CWT_EXPIRATION_SECONDS)),
            not_before: Some(Timestamp::WholeSeconds(now_sec)),
            issued_at: Some(Timestamp::WholeSeconds(now_sec)),
            cwt_id: Some(cwt_id.into()),
            rest: vec![(SCOPE_NAME.clone(), permission.into())],
        };
        let payload = claims.to_vec().map_err(format_error)?;
        let alg = match algorithm {
            SchnorrAlgorithm::Ed25519 => EdDSA,
            SchnorrAlgorithm::Bip340secp256k1 => ES256K,
        };
        let mut sign1 = cose_sign1(payload, alg, None)?;
        let mut tbs_data = sign1.tbs_data(caller.as_slice());
        if algorithm == SchnorrAlgorithm::Bip340secp256k1 {
            tbs_data = sha256(&tbs_data).into();
        }
        let sig = sign_with_schnorr(key_name, algorithm, vec![], tbs_data).await?;
        sign1.signature = sig;
        let token = sign1.to_vec().map_err(format_error)?;
        Ok(ByteBuf::from(token))
    }

    pub fn inner_derive_kek(spk: &SettingPathKey, key_id: &[u8]) -> Result<[u8; 32], String> {
        state::with(|s| {
            let pk = s
                .schnorr_secp256k1_public_key
                .as_ref()
                .ok_or("no schnorr secp256k1 public key")?;

            let derivation_path = vec![
                b"COSE_Symmetric_Key".to_vec(),
                s.init_vector.to_vec(),
                spk.2.to_bytes().to_vec(),
                vec![spk.1],
                spk.0.to_bytes().to_vec(),
            ];
            let pk =
                derive_schnorr_public_key(SchnorrAlgorithm::Bip340secp256k1, pk, derivation_path)?;
            Ok(mac3_256(&pk.public_key, key_id))
        })
    }

    pub async fn inner_vetkd_public_key(spk: &SettingPathKey) -> Result<Vec<u8>, String> {
        let key_name = state::with(|r| r.vetkd_key_name.clone());

        vetkd_public_key(
            key_name,
            &[
                b"COSE_Symmetric_Key",
                spk.2.to_bytes().as_ref(),
                &[spk.1],
                spk.0.to_bytes().as_ref(),
            ],
        )
        .await
    }

    pub async fn inner_vetkd_encrypted_key(
        spk: &SettingPathKey,
        key_id: Vec<u8>,
        transport_public_key: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let key_name = state::with(|r| r.vetkd_key_name.clone());

        vetkd_encrypted_key(
            key_name,
            &[
                b"COSE_Symmetric_Key",
                spk.2.to_bytes().as_ref(),
                &[spk.1],
                spk.0.to_bytes().as_ref(),
            ],
            key_id,
            transport_public_key,
        )
        .await
    }

    pub fn get_namespace(caller: &Principal, namespace: String) -> Result<NamespaceInfo, String> {
        with(&namespace, |ns| {
            if !ns.can_read_namespace(caller) {
                Err("no permission".to_string())?;
            }
            Ok(ns.into_info(namespace.clone()))
        })
    }

    pub fn list_namespaces(prev: Option<String>, take: usize) -> Vec<NamespaceInfo> {
        NAMESPACES_STORE.with_borrow(|r| {
            let mut res = Vec::with_capacity(take);
            match prev {
                Some(p) => {
                    for (k, v) in r.range(ops::RangeTo { end: p }).rev() {
                        res.push(v.into_info(k.clone()));
                        if res.len() >= take {
                            break;
                        }
                    }
                }
                None => {
                    for (k, v) in r.iter().rev() {
                        res.push(v.into_info(k.clone()));
                        if res.len() >= take {
                            break;
                        }
                    }
                }
            };
            res
        })
    }

    pub async fn create_namespace(
        caller: &Principal,
        input: CreateNamespaceInput,
        now_ms: u64,
    ) -> Result<NamespaceInfo, String> {
        if !state::with(|s| s.managers.contains(caller)) {
            Err("no permission".to_string())?;
        }

        NAMESPACES_STORE.with_borrow_mut(|r| {
            if r.contains_key(&input.name) {
                Err(format!("namespace {} already exists", input.name))?;
            }
            let ns = Namespace {
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

            let info = ns.clone().into_info(input.name.clone());
            r.insert(input.name, ns);
            Ok(info)
        })
    }

    pub fn update_namespace_info(
        caller: &Principal,
        input: UpdateNamespaceInput,
        now_ms: u64,
    ) -> Result<(), String> {
        with_mut(input.name, |ns| {
            if !ns.can_write_namespace(caller) {
                Err("no permission".to_string())?;
            }

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
                if !ns.can_write_namespace(caller) {
                    Err("no permission".to_string())?;
                }
                SETTINGS_STORE.with_borrow(|rr| {
                    let mut iter = rr.keys_range(ops::RangeFrom {
                        start: &SettingPathKey(
                            namespace.clone(),
                            0,
                            Principal::anonymous(),
                            ByteBuf::new(),
                            0,
                        ),
                    });
                    if iter.next().is_some() {
                        return Err(format!("namespace {} is not empty", namespace));
                    }
                    Ok(())
                })?;
                r.remove(&namespace);
                Ok(())
            }
            None => Err(format!("namespace {} not found", namespace)),
        })
    }

    pub fn try_get_setting(caller: &Principal, spk: &SettingPathKey) -> Option<Setting> {
        with(&spk.0, |ns| {
            let can = ns.partial_can_read_setting(caller, spk);
            if can == Some(false) {
                return Ok(None);
            }

            let setting = SETTINGS_STORE.with_borrow(|m| m.get(&spk.v0()));
            Ok(setting.filter(|s| {
                spk.4 <= s.version && (can == Some(true) || s.readers.contains(caller))
            }))
        })
        .unwrap_or(None)
    }

    pub fn get_setting_info(caller: Principal, spk: SettingPathKey) -> Result<SettingInfo, String> {
        let setting = try_get_setting(&caller, &spk)
            .ok_or_else(|| format!("setting {} not found or no permission", spk))?;

        Ok(setting.into_info(spk.2, spk.3, false))
    }

    pub fn get_setting(caller: Principal, spk: SettingPathKey) -> Result<SettingInfo, String> {
        let setting = try_get_setting(&caller, &spk)
            .ok_or_else(|| format!("setting {} not found or no permission", &spk))?;

        if spk.4 != 0 && spk.4 != setting.version {
            Err("version mismatch".to_string())?;
        };

        Ok(setting.into_info(spk.2, spk.3, true))
    }

    pub fn get_setting_archived_payload(
        caller: Principal,
        spk: SettingPathKey,
    ) -> Result<SettingArchivedPayload, String> {
        let setting = try_get_setting(&caller, &spk)
            .ok_or_else(|| format!("setting {} not found or no permission", &spk))?;

        if spk.4 == 0 || spk.4 >= setting.version {
            Err("version mismatch".to_string())?;
        };

        let payload = PAYLOADS_STORE.with_borrow(|r| {
            r.get(&spk)
                .ok_or_else(|| format!("setting {} payload not found", &spk))
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
                        if payload.len() as u64 > ns.max_payload_size {
                            Err("payload size exceeds the limit".to_string())?;
                        }
                        try_decode_encrypt0(payload)?;
                        payload.len() + dek.len()
                    } else {
                        dek.len()
                    }
                }
                None => {
                    // try to validate plain payload
                    if let Some(ref payload) = input.payload {
                        try_decode_payload(payload)?;
                        payload.len()
                    } else {
                        0
                    }
                }
            };

            let output = SETTINGS_STORE.with_borrow_mut(|m| {
                if m.contains_key(&spk) {
                    return Err(format!("setting {} already exists", &spk));
                }

                m.insert(
                    spk.clone(),
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

                Ok(CreateSettingOutput {
                    created_at: now_ms,
                    updated_at: now_ms,
                    version: 1,
                })
            })?;

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
            SETTINGS_STORE.with_borrow_mut(|r| match r.get(&spkv0) {
                Some(mut setting) => {
                    if setting.version != spk.4 {
                        Err("version mismatch".to_string())?;
                    }
                    if setting.status >= 1 {
                        Err("readonly setting can not be updated".to_string())?;
                    }

                    match f(&mut setting) {
                        Ok(rt) => {
                            r.insert(spkv0.clone(), setting);
                            Ok(rt)
                        }
                        Err(err) => Err(err),
                    }
                }
                None => Err(format!("setting {} not found", &spk)),
            })
        })
    }

    pub fn delete_setting(caller: &Principal, spk: &SettingPathKey) -> Result<(), String> {
        with(&spk.0, |ns| {
            if !ns.can_write_setting(caller, spk) {
                Err("no permission".to_string())?;
            }

            let spkv0 = spk.v0();
            SETTINGS_STORE.with_borrow_mut(|r| match r.get(&spkv0) {
                Some(setting) => {
                    if setting.version != spk.4 {
                        Err("version mismatch".to_string())?;
                    }
                    if setting.status >= 1 {
                        Err("readonly setting can not be deleted".to_string())?;
                    }

                    r.remove(&spkv0);
                    if spk.4 > 1 {
                        PAYLOADS_STORE.with_borrow_mut(|rr| {
                            let mut pk = spk.clone();
                            for v in 1..spk.4 {
                                pk.4 = v;
                                rr.remove(&pk);
                            }
                        });
                    }

                    Ok(())
                }
                None => Err(format!("setting {} not found", &spk)),
            })
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
            }

            let spkv0 = spk.v0();
            let output = SETTINGS_STORE.with_borrow_mut(|r| match r.get(&spkv0) {
                Some(mut setting) => {
                    if setting.version != spk.4 {
                        Err("version mismatch".to_string())?;
                    }
                    if setting.status >= 1 {
                        Err("readonly setting can not be updated".to_string())?;
                    }

                    if setting.dek.is_some() || input.dek.is_some() {
                        if let Some(ref payload) = input.payload {
                            // should be valid COSE encrypt0 payload
                            try_decode_encrypt0(payload)?;
                        }
                    } else if let Some(ref payload) = input.payload {
                        // try to validate plain payload
                        try_decode_payload(payload)?;
                    }

                    if let Some(payload) = setting.payload.as_ref() {
                        PAYLOADS_STORE.with(|r| {
                            r.borrow_mut().insert(
                                spk.clone(),
                                SettingArchived {
                                    archived_at: now_ms,
                                    deprecated: input.deprecate_current.unwrap_or(false),
                                    payload: Some(payload.clone()),
                                    dek: setting.dek.clone(),
                                },
                            );
                        });
                    }

                    setting.version = setting.version.saturating_add(1);
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

                    r.insert(spkv0, setting.clone());
                    Ok(UpdateSettingOutput {
                        created_at: setting.created_at,
                        updated_at: setting.updated_at,
                        version: setting.version,
                    })
                }
                None => Err(format!("setting {} not found", &spk)),
            })?;

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
}
