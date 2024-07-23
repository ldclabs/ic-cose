use candid::Principal;
use ciborium::{from_reader, from_reader_with_buffer, into_writer};
use ic_cose_types::{
    cose::{try_decode_encrypt0, ECDHInput},
    crypto::ecdh_x25519,
    namespace::NamespaceInfo,
    setting::*,
    sha3_256_n,
    state::StateInfo,
    ByteN,
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
use x25519_dalek::{PublicKey, SharedSecret};

use crate::ecdsa::{derive_public_key, public_key_with, sign_with, ECDSAPublicKey};

type Memory = VirtualMemory<DefaultMemoryImpl>;

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct State {
    pub name: String,
    pub ecdsa_key_name: String,
    pub ecdsa_public_key: Option<ECDSAPublicKey>,
    pub vetkd_key_name: String,
    pub managers: BTreeSet<Principal>, // managers can read and write namespaces, not settings
    // auditors can read and list namespaces and settings info even if it is private
    pub auditors: BTreeSet<Principal>,
    pub subnet_size: u64,
    pub service_fee: u64, // in cycles
    pub incoming_cycles: u128,
    pub uncollectible_cycles: u128, // cycles that cannot be collected
    pub freezing_threshold: u128,   // cycles
}

impl State {
    pub fn to_info(&self, _caller: &Principal) -> StateInfo {
        StateInfo {
            name: self.name.clone(),
            ecdsa_key_name: self.ecdsa_key_name.clone(),
            ecdsa_public_key: self
                .ecdsa_public_key
                .as_ref()
                .map(|k| ByteBuf::from(k.public_key.clone())),
            vetkd_key_name: self.vetkd_key_name.clone(),
            managers: self.managers.clone(),
            auditors: self.auditors.clone(),
            subnet_size: self.subnet_size,
            service_fee: self.service_fee,
            incoming_cycles: self.incoming_cycles,
            uncollectible_cycles: self.uncollectible_cycles,
            freezing_threshold: self.freezing_threshold,
            ..Default::default()
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Namespace {
    pub name: String,
    pub desc: String,
    pub iv: ByteN<12>, // Initialization Vector for encryption, permanent with the namespace
    pub created_at: u64, // unix timestamp in milliseconds
    pub updated_at: u64, // unix timestamp in milliseconds
    pub max_payload_size: u64, // max payload size in bytes
    pub total_payload_size: u64, // total payload size in bytes
    pub status: i8,    // -1: archived; 0: readable and writable; 1: readonly
    pub visibility: u8, // 0: private; 1: public
    pub managers: BTreeSet<Principal>, // managers can read and write all settings
    pub auditors: BTreeSet<Principal>, // auditors can read all settings
    pub members: BTreeSet<Principal>, // members can read and write settings they created
    pub settings: BTreeMap<(Principal, String), Setting>, // settings created by managers for members
    pub client_settings: BTreeMap<(Principal, String), Setting>, // settings created by members
    pub balance: u128,                                    // cycles or alternative token
}

impl Namespace {
    pub fn to_info(&self, key: String) -> NamespaceInfo {
        NamespaceInfo {
            key,
            name: self.name.clone(),
            desc: self.desc.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            max_payload_size: self.max_payload_size,
            total_payload_size: self.total_payload_size,
            status: self.status,
            visibility: self.visibility,
            managers: self.managers.clone(),
            auditors: self.auditors.clone(),
            members: self.members.clone(),
            settings_count: self.settings.len() as u64,
            client_settings_count: self.client_settings.len() as u64,
            balance: self.balance,
        }
    }

    pub fn can_write_setting(&self, caller: &Principal, spk: &SettingPathKey) -> bool {
        if self.status != 0 {
            return false;
        }

        // only managers can create server side settings for any subject
        if spk.1 == 0 {
            return self.managers.contains(caller);
        }

        // members can create settings for themselves and update them
        self.members.contains(caller) && caller == &spk.2
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
            || self.members.contains(caller)
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
        self.managers.contains(caller) || self.members.contains(caller)
    }

    pub fn has_setting_kek_permission(&self, caller: &Principal, spk: &SettingPathKey) -> bool {
        if self.status < 0 && !self.managers.contains(caller) {
            return false;
        }

        caller == &spk.2 || (spk.1 == 0 && self.managers.contains(caller))
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
            1 => self.client_settings.get(&setting_key),
            _ => None,
        };

        setting.filter(|s| spk.4 <= s.version && (can == Some(true) || s.readers.contains(caller)))
    }

    pub fn get_setting_mut(&mut self, spk: &SettingPathKey) -> Option<&mut Setting> {
        let setting_key = (spk.2, spk.3.clone());
        match spk.1 {
            0 => self.settings.get_mut(&setting_key),
            1 => self.client_settings.get_mut(&setting_key),
            _ => None,
        }
    }

    pub fn try_insert_setting(&mut self, spk: &SettingPathKey, setting: Setting) -> bool {
        let setting_key = (spk.2, spk.3.clone());
        let entry = match spk.1 {
            0 => self.settings.entry(setting_key),
            1 => self.client_settings.entry(setting_key),
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
    pub desc: String,
    pub created_at: u64, // unix timestamp in milliseconds
    pub updated_at: u64, // unix timestamp in milliseconds
    pub status: i8, // -1: archived; 0: readable and writable; 1: readonlypub auditors: BTreeSet<Principal>,
    pub version: u32,
    pub readers: BTreeSet<Principal>, // readers can read the setting
    pub tags: BTreeMap<String, String>, // tags for query
    pub payload: ByteBuf,
    pub dek: Option<ByteBuf>, // Data Encryption Key that encrypted by BYOK or vetKey in COSE_Encrypt0
}

impl Setting {
    pub fn to_info(&self, subject: Principal, key: String) -> SettingInfo {
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
            dek: self.dek.clone(),
            payload: None,
            public_key: None,
        }
    }
}

// SettingPathKey: (namespace key, 0 or 1, subject, setting key, version)
#[derive(Clone, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct SettingPathKey(pub String, pub u8, pub Principal, pub String, pub u32);

impl SettingPathKey {
    pub fn from_path(val: SettingPath, caller: Principal) -> Self {
        Self(
            val.ns,
            if val.client { 1 } else { 0 },
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
            self.3,
            self.4
        )
    }
}

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const NS_MEMORY_ID: MemoryId = MemoryId::new(2);
const PAYLOADS_MEMORY_ID: MemoryId = MemoryId::new(3);

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

    static PAYLOADS_STORE: RefCell<StableBTreeMap<SettingPathKey, Vec<u8>, Memory>> = RefCell::new(
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

    pub async fn init_ecdsa_public_key() {
        let ecdsa_key_name = with(|r| {
            if r.ecdsa_public_key.is_none() {
                Some(r.ecdsa_key_name.clone())
            } else {
                None
            }
        });

        if let Some(ecdsa_key_name) = ecdsa_key_name {
            let ecdsa_public_key = public_key_with(ecdsa_key_name, vec![])
                .await
                .unwrap_or_else(|err| {
                    ic_cdk::trap(&format!("failed to retrieve ECDSA public key: {err}"))
                });
            with_mut(|r| {
                r.ecdsa_public_key = Some(ecdsa_public_key);
            });
        }
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
    ) -> Result<ByteBuf, String> {
        with(&namespace, |ns| {
            if !ns.can_read_namespace(caller) {
                Err("no permission".to_string())?;
            }

            state::with(|s| {
                let pk = s.ecdsa_public_key.as_ref().ok_or("no ecdsa public key")?;
                let mut path: Vec<Vec<u8>> = Vec::with_capacity(derivation_path.len() + 1);
                path.push(namespace.to_bytes().to_vec());
                path.extend(derivation_path.into_iter().map(|b| b.into_vec()));
                let derived_pk = derive_public_key(pk, path);
                Ok(ByteBuf::from(derived_pk.public_key))
            })
        })
    }

    pub async fn ecdsa_sign(
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
        let mut path: Vec<Vec<u8>> = Vec::with_capacity(derivation_path.len() + 1);
        path.push(namespace.to_bytes().to_vec());
        path.extend(derivation_path.into_iter().map(|b| b.into_vec()));
        let sig = sign_with(key_name, path, message.into_vec()).await?;
        Ok(ByteBuf::from(sig))
    }

    pub async fn ecdh_public_key(
        caller: &Principal,
        spk: &SettingPathKey,
        ecdh: &ECDHInput,
    ) -> Result<ByteN<32>, String> {
        with(&spk.0, |ns| {
            ns.check_and_get_setting(caller, spk)
                .ok_or_else(|| format!("setting {} not found or no permission", spk))?;
            Ok(())
        })?;

        let (_, pk) = inner_ecdh_x25519_static_secret(spk, ecdh).await?;
        Ok(pk.to_bytes().into())
    }

    pub async fn inner_ecdh_x25519_static_secret(
        spk: &SettingPathKey,
        ecdh: &ECDHInput,
    ) -> Result<(SharedSecret, PublicKey), String> {
        let key_name = state::with(|r| r.ecdsa_key_name.clone());
        let derivation_path = vec![
            b"ECDH_EllipticCurveX25519_Setting".to_vec(),
            spk.2.to_bytes().to_vec(),
            vec![spk.1],
        ];
        let message_hash = sha3_256_n([spk.0.as_bytes(), spk.3.as_bytes(), ecdh.nonce.as_ref()]);
        let sig = sign_with(key_name, derivation_path, message_hash.to_vec()).await?;
        let secret_key = sha3_256_n([&sig, ecdh.nonce.as_ref()]);
        Ok(ecdh_x25519(secret_key, *ecdh.public_key))
    }

    pub async fn inner_ecdsa_setting_kek(
        spk: &SettingPathKey,
        partial_key: &[u8],
    ) -> Result<[u8; 32], String> {
        let key_name = state::with(|r| r.ecdsa_key_name.clone());
        let derivation_path = vec![
            b"KEK_COSE_Encrypt0_Setting".to_vec(),
            spk.2.to_bytes().to_vec(),
            vec![spk.1],
        ];
        let message_hash = sha3_256_n([spk.0.as_bytes(), partial_key]);
        let sig = sign_with(key_name, derivation_path, message_hash.to_vec()).await?;
        Ok(sha3_256_n([&sig, partial_key]))
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

    pub fn get_setting_info(
        caller: &Principal,
        spk: &SettingPathKey,
    ) -> Result<SettingInfo, String> {
        with(&spk.0, |ns| {
            let setting = ns
                .check_and_get_setting(caller, spk)
                .ok_or_else(|| format!("setting {} not found or no permission", spk))?;

            Ok(setting.to_info(spk.2, spk.3.clone()))
        })
    }

    pub fn get_setting(caller: &Principal, spk: &SettingPathKey) -> Result<SettingInfo, String> {
        with(&spk.0, |ns| {
            let setting = ns
                .check_and_get_setting(caller, spk)
                .ok_or_else(|| format!("setting {} not found or no permission", spk))?;

            let payload = if spk.4 > 0 && spk.4 < setting.version {
                PAYLOADS_STORE.with(|r| {
                    let m = r.borrow();
                    let payload = m
                        .get(spk)
                        .ok_or_else(|| format!("setting {} payload not found", spk))?;
                    Ok::<ByteBuf, String>(ByteBuf::from(payload))
                })?
            } else {
                setting.payload.clone()
            };

            let mut res = setting.to_info(spk.2, spk.3.clone());
            res.payload = Some(payload);
            Ok(res)
        })
    }

    pub fn create_setting(
        caller: &Principal,
        spk: &SettingPathKey,
        input: CreateSettingInput,
        now_ms: u64,
    ) -> Result<CreateSettingOutput, String> {
        with_mut(&spk.0, |ns| {
            if !ns.can_write_setting(caller, spk) {
                Err("no permission".to_string())?;
            }

            if spk.4 != 0 {
                Err("version mismatch".to_string())?;
            }

            match input.dek {
                Some(ref dek) => {
                    if input.payload.len() as u64 > ns.max_payload_size {
                        Err("payload size exceeds the limit".to_string())?;
                    }
                    // should be valid COSE encrypt0 dek
                    try_decode_encrypt0(dek)?;
                    // should be valid COSE encrypt0 payload
                    try_decode_encrypt0(&input.payload)?;
                }
                None => {
                    // try to validate plain payload
                    try_decode_payload(ns.max_payload_size, &input.payload)?;
                }
            }

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
                    payload: input.payload.clone(),
                    dek: input.dek.clone(),
                    version: 1,
                    ..Default::default()
                },
            ) {
                Err(format!("setting {} already exists", spk))?;
            }

            if let Some(dek) = input.dek {
                // save dek to 0 key for future use
                PAYLOADS_STORE.with(|r| {
                    r.borrow_mut().insert(spk.clone(), dek.into_vec());
                });
            }

            Ok(output)
        })
    }

    pub fn update_setting_payload(
        caller: &Principal,
        spk: &SettingPathKey,
        input: UpdateSettingPayloadInput,
        now_ms: u64,
    ) -> Result<UpdateSettingOutput, String> {
        with_mut(&spk.0, |ns| {
            if !ns.can_write_setting(caller, spk) {
                Err("no permission".to_string())?;
            }

            let max_payload_size = ns.max_payload_size;
            let setting = ns
                .get_setting_mut(spk)
                .ok_or_else(|| format!("setting {} not found", spk))?;
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

            PAYLOADS_STORE.with(|r| {
                r.borrow_mut()
                    .insert(spk.clone(), setting.payload.clone().into_vec());
            });

            if let Some(status) = input.status {
                setting.status = status;
            }
            setting.version = setting.version.saturating_add(1);
            setting.payload = input.payload;
            setting.updated_at = now_ms;

            Ok(UpdateSettingOutput {
                created_at: setting.created_at,
                updated_at: setting.updated_at,
                version: setting.version,
            })
        })
    }

    pub fn update_setting_info(
        caller: &Principal,
        spk: &SettingPathKey,
        input: UpdateSettingInfoInput,
        now_ms: u64,
    ) -> Result<UpdateSettingOutput, String> {
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
