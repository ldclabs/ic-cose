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
    if let Some(expected_hash) = expected_hash {
        if hash != expected_hash {
            return Err(format!(
                "artifact hash {} does not match the declared {}",
                hex::encode(hash.as_ref()),
                hex::encode(expected_hash.as_ref())
            ));
        }
    }
    if ARTIFACT_META_STORE.with_borrow(|m| m.contains_key(&*hash)) {
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
    let current_module_hash = module_hash_from_artifact(&args.wasm, hash, encoding)?;
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

pub fn get_latest_metadata(name: &str) -> Result<(ByteArray<32>, WasmMetadata), String> {
    let hash = LATEST_STORE
        .with_borrow(|r| r.get(&name.to_string()).map(ByteArray::from))
        .ok_or_else(|| format!("NotFound: {} not found", name))?;
    Ok((hash, get_metadata(&hash)?))
}

fn artifact_metadata(hash: &ByteArray<32>) -> Result<ArtifactMetadata, String> {
    ARTIFACT_META_STORE
        .with_borrow(|r| r.get(&**hash))
        .ok_or_else(|| "NotFound: wasm not found".to_string())
}

/// Assembles the complete artifact bytes in heap memory.
pub fn get_wasm(hash: &ByteArray<32>) -> Result<Vec<u8>, String> {
    let metadata = artifact_metadata(hash)?;
    let mut bytes = Vec::with_capacity(metadata.wasm_size as usize);
    for index in 0..metadata.chunks {
        bytes.extend_from_slice(&storage_chunk(hash, index)?);
    }
    if bytes.len() as u64 != metadata.wasm_size {
        return Err("artifact chunks do not add up to its size".to_string());
    }
    Ok(bytes)
}

pub fn get_metadata(hash: &ByteArray<32>) -> Result<WasmMetadata, String> {
    artifact_metadata(hash).map(|metadata| metadata.public(*hash))
}

pub fn module_hash(hash: &ByteArray<32>) -> Result<ByteArray<32>, String> {
    artifact_metadata(hash).map(|metadata| metadata.module_hash)
}

pub fn get_chunk(hash: &ByteArray<32>, offset: usize, take: usize) -> Result<Vec<u8>, String> {
    let metadata = artifact_metadata(hash)?;
    let size = usize::try_from(metadata.wasm_size)
        .map_err(|_| "artifact size exceeds usize".to_string())?;
    if offset > size {
        return Err("offset exceeds artifact size".to_string());
    }
    let end = offset.saturating_add(take).min(size);
    let mut out = Vec::with_capacity(end - offset);
    let mut cursor = offset;
    while cursor < end {
        let index = cursor / ARTIFACT_STORAGE_CHUNK_BYTES;
        let within = cursor % ARTIFACT_STORAGE_CHUNK_BYTES;
        let chunk = storage_chunk(hash, index as u32)?;
        if within >= chunk.len() {
            return Err("artifact chunk is truncated".to_string());
        }
        let count = (chunk.len() - within).min(end - cursor);
        out.extend_from_slice(&chunk[within..within + count]);
        cursor += count;
    }
    Ok(out)
}

/// Number of stored chunks, each at most [`ARTIFACT_STORAGE_CHUNK_BYTES`].
pub fn storage_chunk_count(hash: &ByteArray<32>) -> Result<u32, String> {
    artifact_metadata(hash).map(|metadata| metadata.chunks)
}

/// Reads one stored chunk directly, as `upload_chunk` expects it.
pub fn storage_chunk(hash: &ByteArray<32>, index: u32) -> Result<Vec<u8>, String> {
    ARTIFACT_CHUNK_STORE
        .with_borrow(|r| r.get(&ArtifactChunkKey(**hash, index)))
        .ok_or_else(|| "artifact chunk is missing".to_string())
}

pub fn validate_remove_wasm(hash: &ByteArray<32>) -> Result<(), String> {
    artifact_metadata(hash)?;
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
    if DEPLOYED_STORE.with_borrow(|r| r.iter().any(|entry| entry.value().artifact_hash == *hash)) {
        return Err("cannot remove an artifact referenced by a deployment".to_string());
    }
    if REQUEST_STORE.with_borrow(|r| r.iter().any(|entry| entry.value().artifact_hash == *hash)) {
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
    let hash = RELEASE_PATH_STORE
        .with_borrow(|r| r.get(&ReleaseKey(name.to_string(), prev_hash)))
        .map(ByteArray::from)
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
    INSTALL_LOGS.with_borrow(|logs| {
        let prev = prev.unwrap_or(logs.len());
        if take == 0 || prev == 0 || prev > logs.len() {
            return vec![];
        }
        LOG_INDEX_STORE.with_borrow(|index| {
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
        })
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
