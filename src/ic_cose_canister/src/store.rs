use candid::Principal;
use ciborium::{from_reader, from_reader_with_buffer, into_writer};
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
use serde_bytes::ByteBuf;
use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt, ops,
};

use crate::{
    ecdsa::{derive_public_key, ecdsa_public_key, sign_with_ecdsa},
    rand_bytes,
    schnorr::{derive_schnorr_public_key, schnorr_public_key, sign_with_schnorr},
    vetkd::{vetkd_encrypted_key, vetkd_public_key},
};

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
}

impl State {
    pub fn to_info(&self) -> StateInfo {
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
        }
    }
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
    #[serde(rename = "ss")]
    pub settings: BTreeMap<(Principal, ByteBuf), Setting>, // settings created by managers for users
    #[serde(rename = "us")]
    pub user_settings: BTreeMap<(Principal, ByteBuf), Setting>, // settings created by users
    #[serde(rename = "g")]
    pub gas_balance: u128, // gas balance, TODO: https://internetcomputer.org/docs/current/developer-docs/gas-cost
}

impl Namespace {
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
            managers: self.managers.clone(),
            auditors: self.auditors.clone(),
            users: self.users.clone(),
            settings_total: self.settings.len() as u64,
            user_settings_total: self.user_settings.len() as u64,
            gas_balance: self.gas_balance,
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

    pub fn has_setting_kek_permission(&self, caller: &Principal, spk: &SettingPathKey) -> bool {
        if self.status < 0 && !self.managers.contains(caller) {
            return false;
        }

        caller == &spk.2
            || self.auditors.contains(caller)
            || (spk.1 == 0 && self.managers.contains(caller))
    }

    pub fn check_and_get_setting(
        &self,
        caller: &Principal,
        spk: &SettingPathKey,
    ) -> Option<&Setting> {
        let can = self.partial_can_read_setting(caller, spk);
        if can == Some(false) {
            return None;
        }

        let setting_key = (spk.2, spk.3.clone());
        let setting = match spk.1 {
            0 => self.settings.get(&setting_key),
            1 => self.user_settings.get(&setting_key),
            _ => None,
        };

        setting.filter(|s| spk.4 <= s.version && (can == Some(true) || s.readers.contains(caller)))
    }

    pub fn get_setting_mut(&mut self, spk: &SettingPathKey) -> Option<&mut Setting> {
        let setting_key = (spk.2, spk.3.clone());
        match spk.1 {
            0 => self.settings.get_mut(&setting_key),
            1 => self.user_settings.get_mut(&setting_key),
            _ => None,
        }
    }

    pub fn try_insert_setting(&mut self, spk: SettingPathKey, setting: Setting) -> bool {
        let setting_key = (spk.2, spk.3);
        let entry = match spk.1 {
            0 => self.settings.entry(setting_key),
            1 => self.user_settings.entry(setting_key),
            _ => {
                return false;
            }
        };
        match entry {
            Entry::Vacant(e) => {
                e.insert(setting);
                true
            }
            Entry::Occupied(_) => false,
        }
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
    pub fn to_info(&self, subject: Principal, key: ByteBuf) -> SettingInfo {
        SettingInfo {
            key,
            subject,
            desc: self.desc.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            status: self.status,
            version: self.version,
            readers: self.readers.clone(),
            tags: self.tags.clone(),
            dek: None,
            payload: None,
        }
    }
}

// SettingPathKey: (namespace name, 0 or 1, subject, setting name, version)
#[derive(Clone, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
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
    pub payload: ByteBuf,
    #[serde(rename = "k")]
    pub dek: Option<ByteBuf>,
}

impl Storable for SettingArchived {
    const BOUND: Bound = Bound::Unbounded;

    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        into_writer(self, &mut buf).expect("failed to encode SettingArchivedPayload data");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_reader(&bytes[..]).expect("failed to decode SettingArchivedPayload data")
    }
}

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const NS_MEMORY_ID: MemoryId = MemoryId::new(1);
const PAYLOADS_MEMORY_ID: MemoryId = MemoryId::new(2);

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
    static NS: RefCell<BTreeMap<String, Namespace>> = const { RefCell::new(BTreeMap::new()) };

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static STATE_STORE: RefCell<StableCell<Vec<u8>, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(STATE_MEMORY_ID)),
            Vec::new()
        ).expect("failed to init STATE_STORE store")
    );

    static NS_STORE: RefCell<StableCell<Vec<u8>, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(NS_MEMORY_ID)),
            Vec::new()
        ).expect("failed to init NS_STORE store")
    );

    static PAYLOADS_STORE: RefCell<StableBTreeMap<SettingPathKey, SettingArchived, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(PAYLOADS_MEMORY_ID)),
        )
    );
}

pub mod state {
    use super::*;

    pub fn with<R>(f: impl FnOnce(&State) -> R) -> R {
        STATE.with(|r| f(&r.borrow()))
    }

    pub fn with_mut<R>(f: impl FnOnce(&mut State) -> R) -> R {
        STATE.with(|r| f(&mut r.borrow_mut()))
    }

    pub fn allowed_api(api: &str) -> Result<(), String> {
        if with(|s| s.allowed_apis.is_empty() || s.allowed_apis.contains(api)) {
            Ok(())
        } else {
            Err(format!("API {} not allowed", api))
        }
    }

    pub async fn init_public_key() {
        let (ecdsa_key_name, schnorr_key_name) =
            with(|r| (r.ecdsa_key_name.clone(), r.schnorr_key_name.clone()));

        let ecdsa_public_key = ecdsa_public_key(ecdsa_key_name, vec![])
            .await
            .map_err(|err| ic_cdk::print(&format!("failed to retrieve ECDSA public key: {err}")))
            .ok();

        let schnorr_ed25519_public_key =
            schnorr_public_key(schnorr_key_name.clone(), SchnorrAlgorithm::Ed25519, vec![])
                .await
                .map_err(|err| {
                    ic_cdk::print(&format!(
                        "failed to retrieve Schnorr Ed25519 public key: {err}"
                    ))
                })
                .ok();

        let schnorr_secp256k1_public_key =
            schnorr_public_key(schnorr_key_name, SchnorrAlgorithm::Bip340Secp256k1, vec![])
                .await
                .map_err(|err| {
                    ic_cdk::print(&format!(
                        "failed to retrieve Schnorr Secp256k1 public key: {err}"
                    ))
                })
                .ok();

        with_mut(|r| {
            r.ecdsa_public_key = ecdsa_public_key;
            r.schnorr_ed25519_public_key = schnorr_ed25519_public_key;
            r.schnorr_secp256k1_public_key = schnorr_secp256k1_public_key;
        });
    }

    pub fn load() {
        let mut scratch = [0; 4096];
        STATE_STORE.with(|r| {
            STATE.with(|h| {
                let v: State = from_reader_with_buffer(&r.borrow().get()[..], &mut scratch)
                    .expect("failed to decode STATE_STORE data");
                *h.borrow_mut() = v;
            });
        });
        NS_STORE.with(|r| {
            NS.with(|h| {
                let v: BTreeMap<String, Namespace> =
                    from_reader_with_buffer(&r.borrow().get()[..], &mut scratch)
                        .expect("failed to decode NS_STORE data");
                *h.borrow_mut() = v;
            });
        });
    }

    pub fn save() {
        STATE.with(|h| {
            STATE_STORE.with(|r| {
                let mut buf = vec![];
                into_writer(&(*h.borrow()), &mut buf).expect("failed to encode STATE_STORE data");
                r.borrow_mut()
                    .set(buf)
                    .expect("failed to set STATE_STORE data");
            });
        });
        NS.with(|h| {
            NS_STORE.with(|r| {
                let mut buf = vec![];
                into_writer(&(*h.borrow()), &mut buf).expect("failed to encode NS_STORE data");
                r.borrow_mut()
                    .set(buf)
                    .expect("failed to set NS_STORE data");
            });
        });
    }
}

pub mod ns {
    use ic_cose_types::cose::iana::Algorithm::EdDSA;

    use super::*;

    pub fn namespace_count() -> u64 {
        NS.with(|r| r.borrow().len() as u64)
    }

    pub fn with<R>(
        namespace: &str,
        f: impl FnOnce(&Namespace) -> Result<R, String>,
    ) -> Result<R, String> {
        NS.with(|r| {
            r.borrow()
                .get(namespace)
                .map(f)
                .unwrap_or_else(|| Err(format!("namespace {} not found", namespace)))
        })
    }

    pub fn with_mut<R>(
        namespace: &str,
        f: impl FnOnce(&mut Namespace) -> Result<R, String>,
    ) -> Result<R, String> {
        NS.with(|r| {
            r.borrow_mut()
                .get_mut(namespace)
                .map(f)
                .unwrap_or_else(|| Err(format!("namespace {} not found", namespace)))
        })
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
                    SchnorrAlgorithm::Bip340Secp256k1 => s
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
            issuer: Some(ic_cdk::id().to_text()),
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
            SchnorrAlgorithm::Bip340Secp256k1 => ES256K,
        };
        let mut sign1 = cose_sign1(payload, alg, None)?;
        let mut tbs_data = sign1.tbs_data(caller.as_slice());
        if algorithm == SchnorrAlgorithm::Bip340Secp256k1 {
            tbs_data = sha256(&tbs_data).into();
        }
        let sig = sign_with_schnorr(key_name, algorithm, vec![], tbs_data).await?;
        sign1.signature = sig;
        let token = sign1.to_vec().map_err(format_error)?;
        Ok(ByteBuf::from(token))
    }

    pub async fn inner_schnorr_kek(
        spk: &SettingPathKey,
        key_id: &[u8],
    ) -> Result<[u8; 32], String> {
        let key_name = state::with(|r| r.schnorr_key_name.clone());
        let derivation_path = vec![
            b"COSE_Symmetric_Key".to_vec(),
            spk.2.to_bytes().to_vec(),
            vec![spk.1],
            spk.0.to_bytes().to_vec(),
        ];
        let message = mac3_256(spk.0.as_bytes(), key_id);
        let sig = sign_with_schnorr(
            key_name,
            SchnorrAlgorithm::Ed25519,
            derivation_path,
            message.into(),
        )
        .await?;
        Ok(mac3_256(spk.0.as_bytes(), &sig))
    }

    pub async fn inner_vetkd_public_key(spk: &SettingPathKey) -> Result<Vec<u8>, String> {
        let key_name = state::with(|r| r.vetkd_key_name.clone());
        let derivation_path = vec![
            b"COSE_Symmetric_Key".to_vec(),
            spk.2.to_bytes().to_vec(),
            vec![spk.1],
            spk.0.to_bytes().to_vec(),
        ];
        vetkd_public_key(key_name, derivation_path).await
    }

    pub async fn inner_vetkd_encrypted_key(
        spk: &SettingPathKey,
        key_id: Vec<u8>,
        encryption_public_key: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let key_name = state::with(|r| r.vetkd_key_name.clone());
        let derivation_path = vec![
            b"COSE_Symmetric_Key".to_vec(),
            spk.2.to_bytes().to_vec(),
            vec![spk.1],
            spk.0.to_bytes().to_vec(),
        ];

        vetkd_encrypted_key(key_name, key_id, derivation_path, encryption_public_key).await
    }

    pub fn get_namespace(caller: &Principal, namespace: String) -> Result<NamespaceInfo, String> {
        with(&namespace, |ns| {
            if !ns.can_read_namespace(caller) {
                Err("no permission".to_string())?;
            }
            Ok(ns.to_info(namespace.clone()))
        })
    }

    pub fn list_namespaces(prev: Option<String>, take: usize) -> Vec<NamespaceInfo> {
        NS.with(|r| {
            let m = r.borrow();
            let mut res = Vec::with_capacity(take);
            match prev {
                Some(p) => {
                    for (k, v) in m.range(ops::RangeTo { end: p }).rev() {
                        res.push(v.to_info(k.clone()));
                        if res.len() >= take {
                            break;
                        }
                    }
                }
                None => {
                    for (k, v) in m.iter().rev() {
                        res.push(v.to_info(k.clone()));
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

        NS.with(|r| {
            let mut m = r.borrow_mut();
            if m.contains_key(&input.name) {
                Err(format!("namespace {} already exists", input.name))?;
            }
            let ns = Namespace {
                desc: input.desc.unwrap_or_default(),
                created_at: now_ms,
                updated_at: now_ms,
                max_payload_size: input.max_payload_size.unwrap_or(MAX_PAYLOAD_SIZE),
                visibility: input.visibility,
                managers: input.managers,
                ..Default::default()
            };

            let info = ns.to_info(input.name.clone());
            m.insert(input.name, ns);
            Ok(info)
        })
    }

    pub fn update_namespace_info(
        caller: &Principal,
        input: UpdateNamespaceInput,
        now_ms: u64,
    ) -> Result<(), String> {
        with_mut(&input.name, |ns| {
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
            ns.updated_at = now_ms;
            Ok(())
        })
    }

    pub fn get_setting_info(caller: Principal, spk: SettingPathKey) -> Result<SettingInfo, String> {
        with(&spk.0.clone(), |ns| {
            let setting = ns
                .check_and_get_setting(&caller, &spk)
                .ok_or_else(|| format!("setting {} not found or no permission", spk))?;

            Ok(setting.to_info(spk.2, spk.3))
        })
    }

    pub fn get_setting(caller: Principal, spk: SettingPathKey) -> Result<SettingInfo, String> {
        with(&spk.0.clone(), |ns| {
            let setting = ns
                .check_and_get_setting(&caller, &spk)
                .ok_or_else(|| format!("setting {} not found or no permission", &spk))?;

            if spk.4 != 0 || spk.4 != setting.version {
                Err("version mismatch".to_string())?;
            };

            let mut res = setting.to_info(spk.2, spk.3);
            res.dek = setting.dek.clone();
            res.payload = setting.payload.clone();
            Ok(res)
        })
    }

    pub fn get_setting_archived_payload(
        caller: Principal,
        spk: SettingPathKey,
    ) -> Result<SettingArchivedPayload, String> {
        with(&spk.0.clone(), |ns| {
            let setting = ns
                .check_and_get_setting(&caller, &spk)
                .ok_or_else(|| format!("setting {} not found or no permission", &spk))?;

            if spk.4 == 0 || spk.4 >= setting.version {
                Err("version mismatch".to_string())?;
            };

            let payload = PAYLOADS_STORE.with(|r| {
                let m = r.borrow();
                m.get(&spk)
                    .ok_or_else(|| format!("setting {} payload not found", &spk))
            })?;

            Ok(SettingArchivedPayload {
                version: spk.4,
                archived_at: payload.archived_at,
                deprecated: payload.deprecated,
                payload: payload.payload,
                dek: payload.dek,
            })
        })
    }

    pub fn create_setting(
        caller: Principal,
        spk: SettingPathKey,
        input: CreateSettingInput,
        now_ms: u64,
    ) -> Result<CreateSettingOutput, String> {
        with_mut(&spk.0.clone(), |ns| {
            if !ns.can_write_setting(&caller, &spk) {
                Err("no permission".to_string())?;
            }

            if spk.4 != 0 {
                Err("version mismatch".to_string())?;
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
                        try_decode_payload(ns.max_payload_size, payload)?;
                        payload.len()
                    } else {
                        0
                    }
                }
            };

            let output = CreateSettingOutput {
                created_at: now_ms,
                updated_at: now_ms,
                version: 1,
            };

            if !ns.try_insert_setting(
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
            ) {
                Err("setting already exists".to_string())?;
            }

            ns.payload_bytes_total = ns.payload_bytes_total.saturating_add(size as u64);
            Ok(output)
        })
    }

    pub fn update_setting_payload(
        caller: Principal,
        spk: SettingPathKey,
        input: UpdateSettingPayloadInput,
        now_ms: u64,
    ) -> Result<UpdateSettingOutput, String> {
        with_mut(&spk.0, |ns| {
            if !ns.can_write_setting(&caller, &spk) {
                Err("no permission".to_string())?;
            }
            let size = input.payload.len();
            let output = {
                let max_payload_size = ns.max_payload_size;
                let setting = ns
                    .get_setting_mut(&spk)
                    .ok_or_else(|| format!("setting {} not found", &spk))?;
                if setting.version != spk.4 {
                    Err("version mismatch".to_string())?;
                }
                if setting.status == 1 {
                    Err("readonly setting can not be updated".to_string())?;
                }

                match setting.dek {
                    Some(_) => {
                        if input.payload.len() as u64 > max_payload_size {
                            Err("payload size exceeds the limit".to_string())?;
                        }
                        // should be valid COSE encrypt0 payload
                        try_decode_encrypt0(&input.payload)?;
                    }
                    None => {
                        // try to validate plain payload
                        try_decode_payload(max_payload_size, &input.payload)?;
                    }
                }

                if let Some(payload) = setting.payload.as_ref() {
                    PAYLOADS_STORE.with(|r| {
                        r.borrow_mut().insert(
                            spk.clone(),
                            SettingArchived {
                                archived_at: now_ms,
                                deprecated: input.deprecate_current.unwrap_or(false),
                                payload: payload.clone(),
                                dek: setting.dek.clone(),
                            },
                        );
                    });
                }

                if let Some(status) = input.status {
                    setting.status = status;
                }
                setting.version = setting.version.saturating_add(1);
                setting.payload = Some(input.payload);
                setting.updated_at = now_ms;
                UpdateSettingOutput {
                    created_at: setting.created_at,
                    updated_at: setting.updated_at,
                    version: setting.version,
                }
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
        with_mut(&spk.0, |ns| {
            if !ns.can_write_setting(caller, spk) {
                Err("no permission".to_string())?;
            }
            let setting = ns
                .get_setting_mut(spk)
                .ok_or_else(|| format!("setting {} not found", spk))?;
            if setting.version != spk.4 {
                Err("version mismatch".to_string())?;
            }
            if setting.status == 1 {
                Err("readonly setting can not be updated".to_string())?;
            }
            f(setting)
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
