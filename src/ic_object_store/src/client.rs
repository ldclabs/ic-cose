use aes_gcm::{aead::KeyInit, AeadInPlace, Aes256Gcm, Key, Nonce, Tag};
use async_trait::async_trait;
use candid::Principal;
use chrono::DateTime;
use futures::{stream::BoxStream, StreamExt, TryStreamExt};
use ic_agent::Agent;
use ic_cose_types::types::object_store::*;
use object_store::{path::Path, MultipartUpload, ObjectStore};
use serde_bytes::{ByteArray, ByteBuf, Bytes};
use std::{collections::BTreeSet, ops::Range, sync::Arc};

use crate::{
    agent::{query_call, update_call},
    rand_bytes,
};

pub static STORE_NAME: &str = "ICObjectStore";

#[derive(Clone)]
pub struct Client {
    agent: Arc<Agent>,
    canister: Principal,
    cipher: Option<Arc<Aes256Gcm>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:Client({})", STORE_NAME, self.canister)
    }
}

impl Client {
    pub fn new(agent: Arc<Agent>, canister: Principal, aes_secret: Option<[u8; 32]>) -> Client {
        let cipher = aes_secret.map(|secret| {
            let key = Key::<Aes256Gcm>::from(secret);
            Arc::new(Aes256Gcm::new(&key))
        });

        Client {
            agent,
            canister,
            cipher,
        }
    }

    pub async fn get_state(&self) -> Result<StateInfo, String> {
        query_call(&self.agent, &self.canister, "get_state", ()).await?
    }

    /// the caller of agent should be canister controller
    pub async fn admin_add_managers(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        update_call(&self.agent, &self.canister, "admin_add_managers", (args,)).await?
    }

    /// the caller of agent should be canister controller
    pub async fn admin_remove_managers(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "admin_remove_managers",
            (args,),
        )
        .await?
    }

    /// the caller of agent should be canister controller
    pub async fn admin_add_auditors(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        update_call(&self.agent, &self.canister, "admin_add_auditors", (args,)).await?
    }

    /// the caller of agent should be canister controller
    pub async fn admin_remove_auditors(&self, args: &BTreeSet<Principal>) -> Result<(), String> {
        update_call(
            &self.agent,
            &self.canister,
            "admin_remove_auditors",
            (args,),
        )
        .await?
    }

    pub async fn put_opts(
        &self,
        path: &Path,
        payload: &Bytes,
        mut opts: PutOptions,
    ) -> Result<PutResult> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(Error::Precondition {
                path: path.as_ref().to_string(),
                error: format!(
                    "payload size {} exceeds max size {}",
                    payload.len(),
                    MAX_PAYLOAD_SIZE
                ),
            });
        }

        let res = if let Some(cipher) = &self.cipher {
            let nonce: [u8; 12] = rand_bytes();
            let mut data = payload.to_vec();
            let mut aes_tags: Vec<ByteArray<16>> = Vec::new();
            for chunk in data.chunks_mut(CHUNK_SIZE) {
                let tag = aes256_gcm_encrypt_in(cipher, &nonce, chunk)?;
                aes_tags.push(tag.into());
            }
            opts.aes_nonce = Some(nonce.into());
            opts.aes_tags = Some(aes_tags);
            update_call(
                &self.agent,
                &self.canister,
                "put_opts",
                (path.as_ref(), Bytes::new(&data), opts),
            )
            .await
        } else {
            update_call(
                &self.agent,
                &self.canister,
                "put_opts",
                (path.as_ref(), payload, opts),
            )
            .await
        };

        res.map_err(|error| Error::Generic { error })?
    }

    pub async fn delete(&self, path: &Path) -> Result<()> {
        update_call(&self.agent, &self.canister, "delete", (path.as_ref(),))
            .await
            .map_err(|error| Error::Generic { error })?
    }

    pub async fn copy(&self, from: &Path, to: &Path) -> Result<()> {
        update_call(
            &self.agent,
            &self.canister,
            "copy",
            (from.as_ref(), to.as_ref()),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn copy_if_not_exists(&self, from: &Path, to: &Path) -> Result<()> {
        update_call(
            &self.agent,
            &self.canister,
            "copy_if_not_exists",
            (from.as_ref(), to.as_ref()),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        update_call(
            &self.agent,
            &self.canister,
            "rename",
            (from.as_ref(), to.as_ref()),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn rename_if_not_exists(&self, from: &Path, to: &Path) -> Result<()> {
        update_call(
            &self.agent,
            &self.canister,
            "rename_if_not_exists",
            (from.as_ref(), to.as_ref()),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn create_multipart(&self, path: &Path) -> Result<MultipartId> {
        update_call(
            &self.agent,
            &self.canister,
            "create_multipart",
            (path.as_ref(),),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn put_part(
        &self,
        path: &Path,
        id: &MultipartId,
        part_idx: usize,
        payload: &Bytes,
    ) -> Result<PartId> {
        update_call(
            &self.agent,
            &self.canister,
            "put_part",
            (path.as_ref(), id, part_idx, payload),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn complete_multipart(
        &self,
        path: &Path,
        id: &MultipartId,
        opts: &PutMultipartOpts,
    ) -> Result<PutResult> {
        update_call(
            &self.agent,
            &self.canister,
            "complete_multipart",
            (path.as_ref(), id, opts),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn abort_multipart(&self, path: &Path, id: &MultipartId) -> Result<()> {
        update_call(
            &self.agent,
            &self.canister,
            "abort_multipart",
            (path.as_ref(), id),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn get_part(&self, path: &Path, part_idx: usize) -> Result<ByteBuf> {
        query_call(
            &self.agent,
            &self.canister,
            "get_part",
            (path.as_ref(), part_idx),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn get_opts(&self, path: &Path, mut opts: GetOptions) -> Result<GetResult> {
        if let Some(cipher) = &self.cipher {
            let range = opts.range.clone();
            opts.range = None;
            // use head to get metadata for decryption
            opts.head = true;
            let res: Result<GetResult> = query_call(
                &self.agent,
                &self.canister,
                "get_opts",
                (path.as_ref(), opts),
            )
            .await
            .map_err(|error| Error::Generic { error })?;

            let mut res = res?;
            if res.meta.size == 0 {
                return Ok(res);
            }

            let r = match range {
                Some(r) => r
                    .into_range(res.meta.size)
                    .map_err(|error| Error::Precondition {
                        path: path.as_ref().to_string(),
                        error,
                    })?,
                None => 0..res.meta.size,
            };
            let nonce = res.meta.aes_nonce.as_ref().ok_or_else(|| Error::Generic {
                error: "missing AES256 nonce".to_string(),
            })?;
            let tags = res.meta.aes_tags.as_ref().ok_or_else(|| Error::Generic {
                error: "missing AES256 tags".to_string(),
            })?;
            let mut chunk_cache: Option<(u32, Vec<u8>)> = None; // cache the last chunk read
            let mut buf = Vec::with_capacity(r.end - r.start);

            // Calculate the chunk indices we need to read
            let start_chunk = (r.start / CHUNK_SIZE) as u32;
            let end_chunk = ((r.end - 1) / CHUNK_SIZE) as u32;

            for idx in start_chunk..=end_chunk {
                // Calculate the byte range within this chunk
                let chunk_start = if idx == start_chunk {
                    r.start % CHUNK_SIZE
                } else {
                    0
                };

                let chunk_end = if idx == end_chunk {
                    (r.end - 1) % CHUNK_SIZE + 1
                } else {
                    CHUNK_SIZE
                };

                match &chunk_cache {
                    Some((cached_idx, cached_chunk)) if *cached_idx == idx => {
                        buf.extend_from_slice(&cached_chunk[chunk_start..chunk_end]);
                    }
                    _ => {
                        let chunk = self.get_part(path, idx as usize).await?;
                        let mut chunk = chunk.into_vec();
                        aes256_gcm_decrypt_in(cipher, nonce, &tags[idx as usize], &mut chunk)?;
                        buf.extend_from_slice(&chunk[chunk_start..chunk_end]);
                        chunk_cache = Some((idx, chunk));
                    }
                }
            }

            res.payload = buf.into();
            res.range = (r.start, r.end);
            return Ok(res);
        }

        query_call(
            &self.agent,
            &self.canister,
            "get_opts",
            (path.as_ref(), opts),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn get_ranges(&self, path: &Path, ranges: &[(usize, usize)]) -> Result<Vec<ByteBuf>> {
        if ranges.is_empty() {
            return Ok(Vec::new());
        }

        if let Some(cipher) = &self.cipher {
            let meta = self.head(path).await?;
            let nonce = meta.aes_nonce.as_ref().ok_or_else(|| Error::Generic {
                error: "missing AES256 nonce".to_string(),
            })?;
            let tags = meta.aes_tags.as_ref().ok_or_else(|| Error::Generic {
                error: "missing AES256 tags".to_string(),
            })?;

            let mut result = Vec::with_capacity(ranges.len());
            let mut chunk_cache: Option<(u32, Vec<u8>)> = None; // cache the last chunk read
            for &(start, end) in ranges {
                let mut buf = Vec::with_capacity(end - start);

                // Calculate the chunk indices we need to read
                let start_chunk = (start / CHUNK_SIZE) as u32;
                let end_chunk = ((end - 1) / CHUNK_SIZE) as u32;

                for idx in start_chunk..=end_chunk {
                    // Calculate the byte range within this chunk
                    let chunk_start = if idx == start_chunk {
                        start % CHUNK_SIZE
                    } else {
                        0
                    };

                    let chunk_end = if idx == end_chunk {
                        (end - 1) % CHUNK_SIZE + 1
                    } else {
                        CHUNK_SIZE
                    };

                    match &chunk_cache {
                        Some((cached_idx, cached_chunk)) if *cached_idx == idx => {
                            buf.extend_from_slice(&cached_chunk[chunk_start..chunk_end]);
                        }
                        _ => {
                            let chunk = self.get_part(path, idx as usize).await?;
                            let mut chunk = chunk.into_vec();
                            aes256_gcm_decrypt_in(cipher, nonce, &tags[idx as usize], &mut chunk)?;
                            buf.extend_from_slice(&chunk[chunk_start..chunk_end]);
                            chunk_cache = Some((idx, chunk));
                        }
                    }
                }
                result.push(ByteBuf::from(buf));
            }

            return Ok(result);
        }

        query_call(
            &self.agent,
            &self.canister,
            "get_ranges",
            (path.as_ref(), ranges),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn head(&self, path: &Path) -> Result<ObjectMeta> {
        query_call(&self.agent, &self.canister, "head", (path.as_ref(),))
            .await
            .map_err(|error| Error::Generic { error })?
    }

    pub async fn list(&self, prefix: Option<Path>) -> Result<Vec<ObjectMeta>> {
        query_call(
            &self.agent,
            &self.canister,
            "list",
            (prefix.map(String::from),),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn list_with_offset(
        &self,
        prefix: Option<Path>,
        offset: &Path,
    ) -> Result<Vec<ObjectMeta>> {
        query_call(
            &self.agent,
            &self.canister,
            "list_with_offset",
            (prefix.map(String::from), offset.as_ref()),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }

    pub async fn list_with_delimiter(&self, prefix: Option<Path>) -> Result<ListResult> {
        query_call(
            &self.agent,
            &self.canister,
            "list_with_delimiter",
            (prefix.map(String::from),),
        )
        .await
        .map_err(|error| Error::Generic { error })?
    }
}

#[derive(Debug)]
pub struct MultipartUploader {
    part_idx: usize,
    parts_cache: Vec<u8>,
    opts: PutMultipartOpts,
    state: Arc<UploadState>,
}

struct UploadState {
    client: Arc<Client>,
    path: Path,
    id: MultipartId,
}

impl std::fmt::Debug for UploadState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:UploadState({}, {})", STORE_NAME, self.path, self.id)
    }
}

#[async_trait]
impl MultipartUpload for MultipartUploader {
    fn put_part(&mut self, payload: object_store::PutPayload) -> object_store::UploadPart {
        let payload = bytes::Bytes::from(payload);
        self.parts_cache.extend_from_slice(&payload);
        if self.parts_cache.len() < CHUNK_SIZE {
            return Box::pin(futures::future::ready(Ok(())));
        }

        let mut part = Vec::with_capacity(CHUNK_SIZE);
        part.extend_from_slice(self.parts_cache.drain(..CHUNK_SIZE).as_slice());

        if let Some(cipher) = &self.state.client.cipher {
            let tag =
                aes256_gcm_encrypt_in(cipher, self.opts.aes_nonce.as_ref().unwrap(), &mut part);
            match tag {
                Ok(tag) => {
                    self.opts.aes_tags.as_mut().unwrap().push(tag.into());
                }
                Err(err) => {
                    return Box::pin(futures::future::ready(Err(from_error(err))));
                }
            }
        }

        let part_idx = self.part_idx;
        self.part_idx += 1;
        let state = self.state.clone();
        Box::pin(async move {
            let _ = state
                .client
                .put_part(&state.path, &state.id, part_idx, Bytes::new(&part))
                .await
                .map_err(from_error)?;
            Ok(())
        })
    }

    async fn complete(&mut self) -> object_store::Result<object_store::PutResult> {
        for part in self.parts_cache.chunks_mut(CHUNK_SIZE) {
            let part_idx = self.part_idx;
            self.part_idx += 1;

            if let Some(cipher) = &self.state.client.cipher {
                let tag =
                    aes256_gcm_encrypt_in(cipher, self.opts.aes_nonce.as_ref().unwrap(), part);
                match tag {
                    Ok(tag) => {
                        self.opts.aes_tags.as_mut().unwrap().push(tag.into());
                    }
                    Err(err) => {
                        return Err(from_error(err));
                    }
                }
            }

            let _ = self
                .state
                .client
                .put_part(&self.state.path, &self.state.id, part_idx, Bytes::new(part))
                .await
                .map_err(from_error)?;
        }

        self.parts_cache.clear();
        let res = self
            .state
            .client
            .complete_multipart(&self.state.path, &self.state.id, &self.opts)
            .await
            .map_err(from_error)?;
        Ok(object_store::PutResult {
            e_tag: res.e_tag,
            version: res.version,
        })
    }

    async fn abort(&mut self) -> object_store::Result<()> {
        self.state
            .client
            .abort_multipart(&self.state.path, &self.state.id)
            .await
            .map_err(from_error)
    }
}

pub struct ObjectStoreClient {
    client: Arc<Client>,
}

impl ObjectStoreClient {
    pub fn new(client: Arc<Client>) -> ObjectStoreClient {
        ObjectStoreClient { client }
    }
}

impl std::fmt::Display for ObjectStoreClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:ObjectStoreClient", STORE_NAME)
    }
}

impl std::fmt::Debug for ObjectStoreClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:ObjectStoreClient", STORE_NAME)
    }
}

#[async_trait]
impl ObjectStore for ObjectStoreClient {
    async fn put_opts(
        &self,
        path: &Path,
        payload: object_store::PutPayload,
        opts: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        let data = bytes::Bytes::from(payload);
        let opts = to_put_options(&opts);
        let res = self
            .client
            .put_opts(path, Bytes::new(&data), opts)
            .await
            .map_err(from_error)?;
        Ok(object_store::PutResult {
            e_tag: res.e_tag,
            version: res.version,
        })
    }

    async fn put_multipart_opts(
        &self,
        path: &Path,
        opts: object_store::PutMultipartOpts,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        let upload_id = self
            .client
            .create_multipart(path)
            .await
            .map_err(from_error)?;
        let mut opts = PutMultipartOpts {
            tags: opts.tags.encoded().to_string(),
            attributes: opts
                .attributes
                .iter()
                .map(|(k, v)| (to_attribute(k), v.to_string()))
                .collect(),
            ..Default::default()
        };

        if self.client.cipher.is_some() {
            opts.aes_nonce = Some(rand_bytes().into());
            opts.aes_tags = Some(Vec::new());
        }

        Ok(Box::new(MultipartUploader {
            part_idx: 0,
            parts_cache: Vec::new(),
            opts,
            state: Arc::new(UploadState {
                client: self.client.clone(),
                path: path.clone(),
                id: upload_id,
            }),
        }))
    }

    async fn get_opts(
        &self,
        location: &Path,
        opts: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        let res = self
            .client
            .get_opts(
                location,
                GetOptions {
                    if_match: opts.if_match,
                    if_none_match: opts.if_none_match,
                    if_modified_since: opts.if_modified_since.map(|v| v.timestamp_millis() as u64),
                    if_unmodified_since: opts
                        .if_unmodified_since
                        .map(|v| v.timestamp_millis() as u64),
                    range: opts.range.map(to_get_range),
                    version: opts.version,
                    head: opts.head,
                },
            )
            .await
            .map_err(from_error)?;

        let data = bytes::Bytes::from(res.payload.into_vec());
        let stream = futures::stream::once(futures::future::ready(Ok(data)));
        let res = object_store::GetResult {
            payload: object_store::GetResultPayload::Stream(stream.boxed()),
            meta: from_object_meta(res.meta),
            range: res.range.0..res.range.1,
            attributes: res
                .attributes
                .into_iter()
                .map(|(k, v)| (from_attribute(k), v))
                .collect(),
        };
        Ok(res)
    }

    async fn get_range(
        &self,
        path: &Path,
        range: Range<usize>,
    ) -> object_store::Result<bytes::Bytes> {
        let mut res = self.get_ranges(path, &[range.start..range.end]).await?;
        res.pop().ok_or_else(|| object_store::Error::NotFound {
            path: path.as_ref().to_string(),
            source: "get_ranges result should not be empty".into(),
        })
    }

    async fn get_ranges(
        &self,
        location: &Path,
        ranges: &[Range<usize>],
    ) -> object_store::Result<Vec<bytes::Bytes>> {
        let ranges: Vec<(usize, usize)> = ranges.iter().map(|r| (r.start, r.end)).collect();
        let res = self
            .client
            .get_ranges(location, &ranges)
            .await
            .map_err(from_error)?;

        Ok(res
            .into_iter()
            .map(|v| bytes::Bytes::from(v.into_vec()))
            .collect())
    }

    async fn head(&self, location: &Path) -> object_store::Result<object_store::ObjectMeta> {
        let res = self.client.head(location).await.map_err(from_error)?;
        Ok(from_object_meta(res))
    }

    async fn delete(&self, location: &Path) -> object_store::Result<()> {
        self.client.delete(location).await.map_err(from_error)
    }

    fn list(
        &self,
        prefix: Option<&Path>,
    ) -> BoxStream<'_, object_store::Result<object_store::ObjectMeta>> {
        let prefix = prefix.cloned();
        futures::stream::once(async move {
            let res = self.client.list(prefix).await;
            let values: Vec<object_store::Result<object_store::ObjectMeta, object_store::Error>> =
                match res {
                    Ok(res) => res.into_iter().map(|v| Ok(from_object_meta(v))).collect(),
                    Err(err) => vec![Err(from_error(err))],
                };

            Ok::<_, object_store::Error>(futures::stream::iter(values))
        })
        .try_flatten()
        .boxed()
    }

    fn list_with_offset(
        &self,
        prefix: Option<&Path>,
        offset: &Path,
    ) -> BoxStream<'_, object_store::Result<object_store::ObjectMeta>> {
        let prefix = prefix.cloned();
        let offset = offset.clone();
        futures::stream::once(async move {
            let res = self.client.list_with_offset(prefix, &offset).await;
            let values: Vec<object_store::Result<object_store::ObjectMeta, object_store::Error>> =
                match res {
                    Ok(res) => res.into_iter().map(|v| Ok(from_object_meta(v))).collect(),
                    Err(err) => vec![Err(from_error(err))],
                };

            Ok::<_, object_store::Error>(futures::stream::iter(values))
        })
        .try_flatten()
        .boxed()
    }

    async fn list_with_delimiter(
        &self,
        prefix: Option<&Path>,
    ) -> object_store::Result<object_store::ListResult> {
        let res = self
            .client
            .list_with_delimiter(prefix.cloned())
            .await
            .map_err(from_error)?;

        Ok(object_store::ListResult {
            objects: res.objects.into_iter().map(from_object_meta).collect(),
            common_prefixes: res.common_prefixes.into_iter().map(Path::from).collect(),
        })
    }

    async fn copy(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.client.copy(from, to).await.map_err(from_error)
    }

    async fn copy_if_not_exists(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.client
            .copy_if_not_exists(from, to)
            .await
            .map_err(from_error)
    }

    async fn rename(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.client.rename(from, to).await.map_err(from_error)
    }

    async fn rename_if_not_exists(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.client
            .rename_if_not_exists(from, to)
            .await
            .map_err(from_error)
    }
}

pub fn from_error(err: Error) -> object_store::Error {
    match err {
        Error::Generic { error } => object_store::Error::Generic {
            store: STORE_NAME,
            source: error.into(),
        },
        Error::NotFound { ref path } => object_store::Error::NotFound {
            path: path.clone(),
            source: Box::new(err),
        },
        Error::InvalidPath { path } => object_store::Error::InvalidPath {
            source: object_store::path::Error::InvalidPath { path: path.into() },
        },
        Error::NotSupported { error } => object_store::Error::NotSupported {
            source: error.into(),
        },
        Error::AlreadyExists { ref path } => object_store::Error::AlreadyExists {
            path: path.clone(),
            source: err.into(),
        },
        Error::Precondition { path, error } => object_store::Error::Precondition {
            path,
            source: error.into(),
        },
        Error::NotModified { path, error } => object_store::Error::NotModified {
            path,
            source: error.into(),
        },
        Error::NotImplemented => object_store::Error::NotImplemented,
        Error::PermissionDenied { path, error } => object_store::Error::PermissionDenied {
            path,
            source: error.into(),
        },
        Error::Unauthenticated { path, error } => object_store::Error::Unauthenticated {
            path,
            source: error.into(),
        },
        Error::UnknownConfigurationKey { key } => object_store::Error::UnknownConfigurationKey {
            store: STORE_NAME,
            key,
        },
        _ => object_store::Error::Generic {
            store: STORE_NAME,
            source: Box::new(err),
        },
    }
}

pub fn from_object_meta(val: ObjectMeta) -> object_store::ObjectMeta {
    object_store::ObjectMeta {
        location: val.location.into(),
        last_modified: DateTime::from_timestamp_millis(val.last_modified as i64)
            .expect("invalid timestamp"),
        size: val.size,
        e_tag: val.e_tag,
        version: val.version,
    }
}

pub fn to_get_range(val: object_store::GetRange) -> GetRange {
    match val {
        object_store::GetRange::Bounded(v) => GetRange::Bounded(v.start, v.end),
        object_store::GetRange::Offset(v) => GetRange::Offset(v),
        object_store::GetRange::Suffix(v) => GetRange::Suffix(v),
    }
}

pub fn from_attribute(val: Attribute) -> object_store::Attribute {
    match val {
        Attribute::ContentDisposition => object_store::Attribute::ContentDisposition,
        Attribute::ContentEncoding => object_store::Attribute::ContentEncoding,
        Attribute::ContentLanguage => object_store::Attribute::ContentLanguage,
        Attribute::ContentType => object_store::Attribute::ContentType,
        Attribute::CacheControl => object_store::Attribute::CacheControl,
        Attribute::Metadata(v) => object_store::Attribute::Metadata(v.into()),
    }
}

pub fn to_attribute(val: &object_store::Attribute) -> Attribute {
    match val {
        object_store::Attribute::ContentDisposition => Attribute::ContentDisposition,
        object_store::Attribute::ContentEncoding => Attribute::ContentEncoding,
        object_store::Attribute::ContentLanguage => Attribute::ContentLanguage,
        object_store::Attribute::ContentType => Attribute::ContentType,
        object_store::Attribute::CacheControl => Attribute::CacheControl,
        object_store::Attribute::Metadata(v) => Attribute::Metadata(v.to_string()),
        _ => panic!("unexpected attribute"),
    }
}

pub fn to_put_options(opts: &object_store::PutOptions) -> PutOptions {
    let mode: PutMode = match opts.mode {
        object_store::PutMode::Overwrite => PutMode::Overwrite,
        object_store::PutMode::Create => PutMode::Create,
        object_store::PutMode::Update(ref v) => PutMode::Update(UpdateVersion {
            e_tag: v.e_tag.clone(),
            version: v.version.clone(),
        }),
    };
    PutOptions {
        mode,
        tags: opts.tags.encoded().to_string(),
        attributes: opts
            .attributes
            .iter()
            .map(|(k, v)| (to_attribute(k), v.to_string()))
            .collect(),
        ..Default::default()
    }
}

fn aes256_gcm_encrypt_in(
    cipher: &Arc<Aes256Gcm>,
    nonce: &[u8; 12],
    buf: &mut [u8],
) -> Result<[u8; 16]> {
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), &[], buf)
        .map_err(|err| Error::Generic {
            error: format!("AES256 encrypt failed: {}", err),
        })?;
    Ok(tag.into())
}

fn aes256_gcm_decrypt_in(
    cipher: &Arc<Aes256Gcm>,
    nonce: &[u8; 12],
    tag: &[u8; 16],
    data: &mut [u8],
) -> Result<()> {
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), &[], data, Tag::from_slice(tag))
        .map_err(|err| Error::Generic {
            error: format!("AES256 decrypt failed: {}", err),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::build_agent;
    use ed25519_consensus::SigningKey;
    use ic_agent::{identity::BasicIdentity, Identity};
    use ic_cose_types::cose::sha3_256;

    #[tokio::test(flavor = "current_thread")]
    #[ignore]
    async fn test_client() {
        let secret = [8u8; 32];
        let canister = Principal::from_text("6at64-oyaaa-aaaap-anvza-cai").unwrap();
        let sk = SigningKey::from(secret);
        let id = BasicIdentity::from_signing_key(sk);
        println!("id: {:?}", id.sender().unwrap().to_text());
        // jjn6g-sh75l-r3cxb-wxrkl-frqld-6p6qq-d4ato-wske5-op7s5-n566f-bqe

        let agent = build_agent("http://localhost:4943", Arc::new(id))
            .await
            .unwrap();
        let cli = Arc::new(Client::new(Arc::new(agent), canister, Some(secret)));
        let oc = ObjectStoreClient::new(cli.clone());

        let path = Path::from("test/hello.txt");
        let payload = "Hello Anda!".as_bytes().to_vec();
        let res = oc
            .put_opts(&path, payload.clone().into(), Default::default())
            .await
            .unwrap();
        println!("put result: {:?}", res);

        let res = oc.get_opts(&path, Default::default()).await.unwrap();
        println!("get result: {:?}", res);
        assert_eq!(res.meta.size, payload.len());
        let res = match res.payload {
            object_store::GetResultPayload::Stream(mut stream) => {
                let mut buf = Vec::new();
                while let Some(data) = stream.next().await {
                    buf.extend_from_slice(&data.unwrap());
                }
                buf
            }
            _ => panic!("unexpected payload"),
        };
        assert_eq!(res, payload);

        let res = cli.get_opts(&path, Default::default()).await.unwrap();
        println!("get result: {:?}", res);
        assert_eq!(res.meta.size, payload.len());
        assert_eq!(&res.payload, &payload);
        let aes_nonce = res.meta.aes_nonce.unwrap();
        assert_eq!(aes_nonce.len(), 12);
        let aes_tags = res.meta.aes_tags.unwrap();
        assert_eq!(aes_tags.len(), 1);

        let now = chrono::Utc::now();
        let path = Path::from(format!("test/{}.bin", now.timestamp_millis()));
        let count = 20000usize;
        let len = count * 32;
        let mut payload = Vec::with_capacity(len);
        {
            let mut uploder = oc
                .put_multipart_opts(&path, Default::default())
                .await
                .unwrap();

            for i in 0..count {
                let data = sha3_256(&i.to_be_bytes()).to_vec();
                payload.extend_from_slice(&data);
                uploder
                    .put_part(object_store::PutPayload::from(data))
                    .await
                    .unwrap();
            }

            uploder.complete().await.unwrap();
        }
        let res = oc.get_opts(&path, Default::default()).await.unwrap();
        assert_eq!(res.meta.size, payload.len());
        let res = match res.payload {
            object_store::GetResultPayload::Stream(mut stream) => {
                let mut buf = Vec::new();
                while let Some(data) = stream.next().await {
                    buf.extend_from_slice(&data.unwrap());
                }
                buf
            }
            _ => panic!("unexpected payload"),
        };
        assert_eq!(res, payload);

        let res = cli.get_opts(&path, Default::default()).await.unwrap();
        assert_eq!(res.meta.size, payload.len());
        assert_eq!(&res.payload, &payload);
        let aes_nonce = res.meta.aes_nonce.unwrap();
        assert_eq!(aes_nonce.len(), 12);
        let aes_tags = res.meta.aes_tags.unwrap();
        assert_eq!(aes_tags.len(), len.div_ceil(CHUNK_SIZE));

        let ranges = vec![
            (0usize, 1000),
            (100usize, 100000),
            (len - CHUNK_SIZE - 1, len),
        ];

        let rt = cli.get_ranges(&path, &ranges).await.unwrap();
        assert_eq!(rt.len(), ranges.len());
        for (i, (start, end)) in ranges.into_iter().enumerate() {
            let res = cli
                .get_opts(
                    &path,
                    GetOptions {
                        range: Some(GetRange::Bounded(start, end)),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(rt[i], &res.payload);
            assert_eq!(&res.payload, &payload[start..end]);
            assert_eq!(res.meta.location, path.as_ref());
            assert_eq!(res.meta.size, payload.len());
        }
    }
}