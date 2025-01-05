use candid::Principal;
use ciborium::{from_reader, into_writer};
use ic_cose_types::types::object_store::Attribute;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    DefaultMemoryImpl, StableBTreeMap, StableCell, Storable,
};
use object_store::path::Path;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap},
};

type Memory = VirtualMemory<DefaultMemoryImpl>;

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct State {
    pub name: String,
    pub managers: BTreeSet<Principal>,
    pub auditors: BTreeSet<Principal>,
    pub governance_canister: Option<Principal>,
    pub locations: BTreeMap<String, (u64, bool)>, // path -> (etag, completed)
    pub next_etag: u64,
}

/// The metadata that describes an object.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ObjectMetadata {
    /// The last modified time, unix timestamp in milliseconds
    #[serde(rename = "m")]
    last_modified: u64,
    /// The size in bytes of the object
    #[serde(rename = "s")]
    size: usize,
    // /// The unique identifier for the object
    // ///
    // /// <https://datatracker.ietf.org/doc/html/rfc9110#name-etag>
    // #[serde(rename = "e")]
    // e_tag: Option<String>,
    #[serde(rename = "t")]
    tags: String,
    #[serde(rename = "a")]
    attributes: BTreeMap<Attribute, String>,
    /// A version indicator for this object
    #[serde(rename = "v")]
    version: Option<String>,
}

impl Storable for ObjectMetadata {
    const BOUND: Bound = Bound::Unbounded;

    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        into_writer(self, &mut buf).expect("failed to encode ObjectMetadata data");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        from_reader(&bytes[..]).expect("failed to decode ObjectMetadata data")
    }
}

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const OBJECT_META_MEMORY_ID: MemoryId = MemoryId::new(1);
const OBJECT_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
    static MULTIPART_UPLOAD : RefCell<HashMap<u64, Vec<Option<ByteBuf>>>> = RefCell::new(HashMap::new());

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static STATE_STORE: RefCell<StableCell<Vec<u8>, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(STATE_MEMORY_ID)),
            Vec::new()
        ).expect("failed to init STATE_STORE store")
    );

    static OBJECT_META: RefCell<StableBTreeMap<u64, ObjectMetadata, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(OBJECT_META_MEMORY_ID)),
        )
    );

    static OBJECT_DATA: RefCell<StableBTreeMap<u64, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(OBJECT_DATA_MEMORY_ID)),
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
        STATE.with_borrow(|s| {
            s.governance_canister
                .as_ref()
                .map_or(false, |p| p == caller)
        })
    }

    pub fn is_writer(caller: &Principal) -> bool {
        STATE.with_borrow(|s| s.managers.contains(caller))
    }

    pub fn is_reader(caller: &Principal) -> bool {
        STATE.with_borrow(|s| s.managers.contains(caller) || s.auditors.contains(caller))
    }

    pub fn load() {
        STATE_STORE.with_borrow(|r| {
            STATE.with_borrow_mut(|h| {
                let v: State =
                    from_reader(&r.get()[..]).expect("failed to decode STATE_STORE data");
                *h = v;
            });
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

pub mod object {
    use super::*;
    use ic_cose_types::types::object_store::*;

    pub fn put_opts(
        path: String,
        payload: ByteBuf,
        opts: PutOptions,
        now_ms: u64,
    ) -> Result<PutResult> {
        STATE.with_borrow_mut(|s| {
            let mut meta = ObjectMetadata {
                last_modified: now_ms,
                size: payload.len(),
                tags: opts.tags,
                attributes: opts.attributes,
                version: None,
            };

            let etag = match opts.mode {
                PutMode::Overwrite => {
                    let (etag, _) = s.locations.entry(path).or_insert((s.next_etag, true));
                    if etag == &s.next_etag {
                        s.next_etag += 1;
                    }
                    OBJECT_META.with_borrow_mut(|om| om.insert(*etag, meta));
                    OBJECT_DATA.with_borrow_mut(|od| od.insert(*etag, payload.into_vec()));
                    *etag
                }
                PutMode::Create => {
                    if s.locations.contains_key(&path) {
                        return Err(Error::AlreadyExists { path });
                    }

                    let etag = s.next_etag;
                    s.locations.insert(path, (etag, true));
                    s.next_etag += 1;
                    OBJECT_META.with_borrow_mut(|om| om.insert(etag, meta));
                    OBJECT_DATA.with_borrow_mut(|od| od.insert(etag, payload.into_vec()));
                    etag
                }
                PutMode::Update(v) => match s.locations.get(&path) {
                    None => Err(Error::Precondition {
                        path,
                        error: "object not found".into(),
                    })?,
                    Some((etag, _)) => {
                        let existing = etag.to_string();
                        let expected = v.e_tag.ok_or(Error::Generic {
                            error: "e_tag required for conditional update".to_string(),
                        })?;
                        if existing != expected {
                            Err(Error::Precondition {
                                path,
                                error: format!("{existing} does not match {expected}"),
                            })?;
                        }
                        meta.version = v.version;
                        OBJECT_META.with_borrow_mut(|om| om.insert(*etag, meta));
                        OBJECT_DATA.with_borrow_mut(|od| od.insert(*etag, payload.into_vec()));
                        *etag
                    }
                },
            };

            Ok(PutResult {
                e_tag: Some(etag.to_string()),
                version: None,
            })
        })
    }

    pub fn delete(path: String) -> Result<()> {
        STATE.with_borrow_mut(|s| {
            if let Some((etag, _)) = s.locations.remove(&path) {
                MULTIPART_UPLOAD.with_borrow_mut(|m| m.remove(&etag));
                OBJECT_META.with_borrow_mut(|om| om.remove(&etag));
                OBJECT_DATA.with_borrow_mut(|od| od.remove(&etag));
            }
            Ok(())
        })
    }

    pub fn copy(from: String, to: String) -> Result<()> {
        STATE.with_borrow_mut(|s| {
            let from = {
                let (etag, completed) = s
                    .locations
                    .get(&from)
                    .ok_or(Error::NotFound { path: from.clone() })?;
                if !completed {
                    return Err(Error::Precondition {
                        path: from,
                        error: "upload not completed".to_string(),
                    });
                }
                *etag
            };

            let (etag, _) = s.locations.entry(to).or_insert((s.next_etag, true));
            if etag == &s.next_etag {
                s.next_etag += 1;
            }
            OBJECT_META.with_borrow_mut(|om| om.insert(*etag, om.get(&from).unwrap()));
            OBJECT_DATA.with_borrow_mut(|od| od.insert(*etag, od.get(&from).unwrap()));
            Ok(())
        })
    }

    pub fn copy_if_not_exists(from: String, to: String) -> Result<()> {
        STATE.with_borrow_mut(|s| {
            if s.locations.contains_key(&to) {
                return Err(Error::AlreadyExists { path: to });
            }

            let from = {
                let (etag, completed) = s
                    .locations
                    .get(&from)
                    .ok_or(Error::NotFound { path: from.clone() })?;
                if !completed {
                    return Err(Error::Precondition {
                        path: from,
                        error: "upload not completed".to_string(),
                    });
                }
                *etag
            };

            let etag = s.next_etag;
            s.next_etag += 1;
            s.locations.insert(to, (etag, true));

            OBJECT_META.with_borrow_mut(|om| om.insert(etag, om.get(&from).unwrap()));
            OBJECT_DATA.with_borrow_mut(|od| od.insert(etag, od.get(&from).unwrap()));
            Ok(())
        })
    }

    pub fn rename(from: String, to: String) -> Result<()> {
        STATE.with_borrow_mut(|s| {
            {
                let (_, completed) = s
                    .locations
                    .get(&from)
                    .ok_or(Error::NotFound { path: from.clone() })?;
                if !completed {
                    return Err(Error::Precondition {
                        path: from,
                        error: "upload not completed".to_string(),
                    });
                }
            };

            let from = s.locations.remove(&from).unwrap();
            let (etag, _) = s.locations.entry(to).or_insert(from);
            if etag != &from.0 {
                OBJECT_META.with_borrow_mut(|om| om.remove(etag));
                OBJECT_DATA.with_borrow_mut(|od| od.remove(etag));
                *etag = from.0;
            }
            Ok(())
        })
    }

    pub fn rename_if_not_exists(from: String, to: String) -> Result<()> {
        STATE.with_borrow_mut(|s| {
            if s.locations.contains_key(&to) {
                return Err(Error::AlreadyExists { path: to });
            }
            {
                let (_, completed) = s
                    .locations
                    .get(&from)
                    .ok_or(Error::NotFound { path: from.clone() })?;
                if !completed {
                    return Err(Error::Precondition {
                        path: from,
                        error: "upload not completed".to_string(),
                    });
                }
            };

            let etag = s.locations.remove(&from).unwrap();
            s.locations.insert(to, etag);
            Ok(())
        })
    }

    pub fn create_multipart(
        path: String,
        opts: PutMultipartOpts,
        now_ms: u64,
    ) -> Result<MultipartId> {
        STATE.with_borrow_mut(|s| {
            if s.locations.contains_key(&path) {
                return Err(Error::AlreadyExists { path });
            }

            let meta = ObjectMetadata {
                last_modified: now_ms,
                size: 0,
                tags: opts.tags,
                attributes: opts.attributes,
                version: None,
            };

            let etag = s.next_etag;
            s.locations.insert(path, (etag, false));
            s.next_etag += 1;
            OBJECT_META.with_borrow_mut(|om| om.insert(etag, meta));
            Ok(etag.to_string())
        })
    }

    pub fn put_part(
        path: String,
        id: MultipartId,
        part_idx: usize,
        payload: ByteBuf,
    ) -> Result<PartId> {
        STATE.with_borrow_mut(|s| {
            let (etag, completed) = s
                .locations
                .get(&path)
                .ok_or(Error::NotFound { path: path.clone() })?;
            if etag.to_string() != id {
                return Err(Error::Precondition {
                    path,
                    error: "upload not found".to_string(),
                });
            }
            if *completed {
                return Err(Error::Precondition {
                    path,
                    error: "upload already completed".to_string(),
                });
            }

            MULTIPART_UPLOAD.with_borrow_mut(|m| {
                let parts = m.entry(*etag).or_default();
                if parts.len() <= part_idx {
                    parts.resize(part_idx + 1, None);
                }
                parts[part_idx] = Some(payload);
            });

            Ok(PartId {
                content_id: format!("{}-{}", id, part_idx),
            })
        })
    }

    pub fn complete_multipart(path: String, id: MultipartId) -> Result<PutResult> {
        STATE.with_borrow_mut(|s| {
            let etag = {
                let (etag, completed) = s
                    .locations
                    .get(&path)
                    .ok_or(Error::NotFound { path: path.clone() })?;
                if etag.to_string() != id {
                    return Err(Error::Precondition {
                        path,
                        error: "upload not found".to_string(),
                    });
                }
                if *completed {
                    return Err(Error::Precondition {
                        path,
                        error: "upload already completed".to_string(),
                    });
                }
                *etag
            };

            let parts = MULTIPART_UPLOAD.with_borrow_mut(|m| {
                m.remove(&etag).ok_or(Error::Precondition {
                    path: path.clone(),
                    error: "upload parts not found".to_string(),
                })
            })?;

            let mut cap = 0;
            for (idx, part) in parts.iter().enumerate() {
                match part {
                    Some(p) => cap += p.len(),
                    None => {
                        return Err(Error::Precondition {
                            path: path.clone(),
                            error: format!("missing part at index: {idx}"),
                        });
                    }
                }
            }

            let mut payload = Vec::with_capacity(cap);
            {
                for part in parts {
                    payload.extend_from_slice(&part.unwrap());
                }
            }

            OBJECT_META.with_borrow_mut(|om| {
                let meta = om.get(&etag).unwrap().clone();
                om.insert(
                    etag,
                    ObjectMetadata {
                        size: payload.len(),
                        ..meta
                    },
                )
            });
            OBJECT_DATA.with_borrow_mut(|od| od.insert(etag, payload));
            s.locations.insert(path, (etag, true));
            Ok(PutResult {
                e_tag: Some(etag.to_string()),
                version: None,
            })
        })
    }

    pub fn abort_multipart(path: String, id: MultipartId) -> Result<()> {
        STATE.with_borrow_mut(|s| {
            let etag = {
                let (etag, completed) = s
                    .locations
                    .get(&path)
                    .ok_or(Error::NotFound { path: path.clone() })?;
                if etag.to_string() != id {
                    return Err(Error::Precondition {
                        path,
                        error: "upload not found".to_string(),
                    });
                }
                if *completed {
                    return Err(Error::Precondition {
                        path,
                        error: "upload already completed".to_string(),
                    });
                }
                *etag
            };

            MULTIPART_UPLOAD.with_borrow_mut(|m| m.remove(&etag));
            s.locations.remove(&path);
            Ok(())
        })
    }

    pub fn get_opts(path: String, opts: GetOptions) -> Result<GetResult> {
        STATE.with_borrow(|s| {
            let (etag, completed) = s
                .locations
                .get(&path)
                .ok_or(Error::NotFound { path: path.clone() })?;
            if !completed {
                return Err(Error::Precondition {
                    path,
                    error: "upload not completed".to_string(),
                });
            }
            let me = OBJECT_META.with_borrow(|om| om.get(etag).unwrap());
            let meta = ObjectMeta {
                location: path.clone(),
                last_modified: me.last_modified,
                size: me.size,
                e_tag: Some(etag.to_string()),
                version: me.version,
            };
            opts.check_preconditions(&meta)?;

            let data = OBJECT_DATA.with_borrow(|od| od.get(etag).unwrap());
            let (range, payload) = match opts.range {
                Some(range) => {
                    let r = range
                        .into_range(data.len())
                        .map_err(|error| Error::Precondition { path, error })?;
                    ((r.start, r.end), data[r].to_vec())
                }
                None => ((0, data.len()), data),
            };
            Ok(GetResult {
                range,
                meta,
                attributes: me.attributes,
                payload: ByteBuf::from(payload),
            })
        })
    }

    pub fn get_ranges(path: String, ranges: Vec<(usize, usize)>) -> Result<Vec<ByteBuf>> {
        STATE.with_borrow(|s| {
            let (etag, completed) = s
                .locations
                .get(&path)
                .ok_or(Error::NotFound { path: path.clone() })?;
            if !completed {
                return Err(Error::Precondition {
                    path,
                    error: "upload not completed".to_string(),
                });
            }
            let data = OBJECT_DATA.with_borrow(|od| od.get(etag).unwrap());
            ranges
                .into_iter()
                .map(|(start, end)| {
                    let r = GetRange::Bounded(start, end)
                        .into_range(data.len())
                        .map_err(|error| Error::Precondition {
                            path: path.clone(),
                            error,
                        })?;
                    Ok(ByteBuf::from(data[r].to_vec()))
                })
                .collect()
        })
    }

    pub fn head(path: String) -> Result<ObjectMeta> {
        STATE.with_borrow(|s| {
            let (etag, completed) = s
                .locations
                .get(&path)
                .ok_or(Error::NotFound { path: path.clone() })?;
            if !completed {
                return Err(Error::Precondition {
                    path,
                    error: "upload not completed".to_string(),
                });
            }
            let me = OBJECT_META.with_borrow(|om| om.get(etag).unwrap());
            Ok(ObjectMeta {
                location: path.clone(),
                last_modified: me.last_modified,
                size: me.size,
                e_tag: Some(etag.to_string()),
                version: me.version,
            })
        })
    }

    const MAX_LIST_LIMIT: usize = 1000;
    pub fn list(prefix: Option<Path>) -> Result<Vec<ObjectMeta>> {
        STATE.with_borrow(|s| {
            OBJECT_META.with_borrow(|om| {
                let start: String = prefix.clone().map(|p| p.into()).unwrap_or_default();
                let prefix = prefix.unwrap_or_default();
                let mut objects = vec![];
                for (path, (etag, completed)) in s.locations.range(start.clone()..) {
                    if !path.starts_with(&start) {
                        break;
                    }
                    if *completed {
                        let key: Path = path.clone().into();
                        if key
                            .prefix_match(&prefix)
                            .map(|mut x| x.next().is_some())
                            .unwrap_or(false)
                        {
                            let me = om.get(etag).unwrap();
                            objects.push(ObjectMeta {
                                location: path.clone(),
                                last_modified: me.last_modified,
                                size: me.size,
                                e_tag: Some(etag.to_string()),
                                version: me.version,
                            });
                            if objects.len() >= MAX_LIST_LIMIT {
                                break;
                            }
                        }
                    }
                }
                Ok(objects)
            })
        })
    }

    pub fn list_with_offset(prefix: Option<Path>, offset: Path) -> Result<Vec<ObjectMeta>> {
        STATE.with_borrow(|s| {
            OBJECT_META.with_borrow(|om| {
                let start: String = prefix.clone().map(|p| p.into()).unwrap_or_default();
                let prefix = prefix.unwrap_or_default();
                let offset = offset;
                let mut objects = vec![];
                for (path, (etag, completed)) in s.locations.range(start.clone()..) {
                    if !path.starts_with(&start) {
                        break;
                    }

                    if *completed {
                        let key: Path = path.clone().into();
                        if key
                            .prefix_match(&prefix)
                            .map(|mut x| x.next().is_some())
                            .unwrap_or(false)
                        {
                            if key < offset {
                                continue;
                            }
                            let me = om.get(etag).unwrap();
                            objects.push(ObjectMeta {
                                location: path.clone(),
                                last_modified: me.last_modified,
                                size: me.size,
                                e_tag: Some(etag.to_string()),
                                version: me.version,
                            });
                            if objects.len() >= MAX_LIST_LIMIT {
                                break;
                            }
                        }
                    }
                }
                Ok(objects)
            })
        })
    }

    pub fn list_with_delimiter(prefix: Option<Path>) -> Result<ListResult> {
        STATE.with_borrow(|s| {
            OBJECT_META.with_borrow(|om| {
                let start: String = prefix.clone().map(|p| p.into()).unwrap_or_default();
                let prefix = prefix.unwrap_or_default();
                let mut common_prefixes: BTreeSet<String> = BTreeSet::new();

                // Only objects in this base level should be returned in the
                // response. Otherwise, we just collect the common prefixes.
                let mut objects = vec![];
                for (path, (etag, completed)) in s.locations.range(start.clone()..) {
                    if !path.starts_with(&start) {
                        break;
                    }

                    if *completed {
                        let key: Path = path.clone().into();
                        let mut parts = match key.prefix_match(&prefix) {
                            Some(parts) => parts,
                            None => continue,
                        };

                        // Pop first element
                        let common_prefix = match parts.next() {
                            Some(p) => p,
                            // Should only return children of the prefix
                            None => continue,
                        };

                        if parts.next().is_some() {
                            common_prefixes.insert(prefix.child(common_prefix).into());
                        } else {
                            let me = om.get(etag).unwrap();
                            objects.push(ObjectMeta {
                                location: path.clone(),
                                last_modified: me.last_modified,
                                size: me.size,
                                e_tag: Some(etag.to_string()),
                                version: me.version,
                            });
                            if objects.len() >= MAX_LIST_LIMIT {
                                break;
                            }
                        }
                    }
                }

                Ok(ListResult {
                    objects,
                    common_prefixes: common_prefixes.into_iter().collect(),
                })
            })
        })
    }
}
