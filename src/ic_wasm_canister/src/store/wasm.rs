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
    if WASM_STORE.with_borrow(|m| m.contains_key(&hash))
        || ARTIFACT_META_STORE.with_borrow(|m| m.contains_key(&*hash))
    {
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
    let current_module_hash = match encoding {
        WasmEncoding::Raw => {
            if args.wasm.len() > MAX_ARTIFACT_BYTES {
                return Err(format!("artifact exceeds the limit {MAX_ARTIFACT_BYTES}"));
            }
            validate_wasm_module(&args.wasm, "raw artifact")?;
            hash
        }
        WasmEncoding::Gzip => module_hash_from_artifact(&args.wasm, encoding)?,
    };
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

#[cfg(test)]
pub fn get_latest(name: &str) -> Result<(ByteArray<32>, Wasm), String> {
    let hash = LATEST_STORE
        .with_borrow(|r| r.get(&name.to_string()).map(ByteArray::from))
        .ok_or_else(|| format!("NotFound: {} not found", name))?;
    get_wasm(&hash)
        .map(|wasm| (hash, wasm))
        .ok_or_else(|| "NotFound: latest wasm not found".to_string())
}

pub fn get_latest_metadata(name: &str) -> Result<(ByteArray<32>, WasmMetadata), String> {
    let hash = LATEST_STORE
        .with_borrow(|r| r.get(&name.to_string()).map(ByteArray::from))
        .ok_or_else(|| format!("NotFound: {} not found", name))?;
    Ok((hash, get_metadata(&hash)?))
}

pub fn get_wasm(hash: &ByteArray<32>) -> Option<Wasm> {
    if let Some(metadata) = ARTIFACT_META_STORE.with_borrow(|r| r.get(&**hash)) {
        let mut bytes = Vec::with_capacity(metadata.wasm_size as usize);
        for index in 0..metadata.chunks {
            let chunk =
                ARTIFACT_CHUNK_STORE.with_borrow(|r| r.get(&ArtifactChunkKey(**hash, index)))?;
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() as u64 != metadata.wasm_size {
            return None;
        }
        return Some(Wasm {
            name: metadata.name,
            created_at: metadata.created_at,
            created_by: metadata.created_by,
            description: metadata.description,
            wasm: ByteBuf::from(bytes),
            encoding: metadata.encoding,
            module_hash: Some(metadata.module_hash),
        });
    }
    WASM_STORE.with_borrow(|r| r.get(hash)).map(|mut wasm| {
        wasm.encoding = wasm.effective_encoding();
        wasm
    })
}

pub fn get_metadata(hash: &ByteArray<32>) -> Result<WasmMetadata, String> {
    if let Some(metadata) = ARTIFACT_META_STORE.with_borrow(|r| r.get(&**hash)) {
        return Ok(metadata.public(*hash));
    }
    WASM_STORE
        .with_borrow(|r| r.get(hash))
        .ok_or_else(|| "NotFound: wasm not found".to_string())?
        .metadata(*hash)
}

pub fn is_legacy_artifact(hash: &ByteArray<32>) -> bool {
    !ARTIFACT_META_STORE.with_borrow(|store| store.contains_key(&**hash))
        && WASM_STORE.with_borrow(|store| store.contains_key(hash))
}

pub fn module_hash(hash: &ByteArray<32>) -> Result<ByteArray<32>, String> {
    if let Some(metadata) = ARTIFACT_META_STORE.with_borrow(|r| r.get(&**hash)) {
        return Ok(metadata.module_hash);
    }
    let wasm = WASM_STORE
        .with_borrow(|r| r.get(hash))
        .ok_or_else(|| "NotFound: wasm not found".to_string())?;
    wasm.effective_module_hash(hash)
}

pub fn get_chunk(hash: &ByteArray<32>, offset: usize, take: usize) -> Result<Vec<u8>, String> {
    if let Some(metadata) = ARTIFACT_META_STORE.with_borrow(|r| r.get(&**hash)) {
        let size = usize::try_from(metadata.wasm_size)
            .map_err(|_| "artifact size exceeds usize".to_string())?;
        if offset > size {
            return Err("offset exceeds artifact size".to_string());
        }
        let end = offset.saturating_add(take).min(size);
        let mut out = Vec::with_capacity(end.saturating_sub(offset));
        let mut cursor = offset;
        while cursor < end {
            let index = cursor / ARTIFACT_STORAGE_CHUNK_BYTES;
            let within = cursor % ARTIFACT_STORAGE_CHUNK_BYTES;
            let chunk = ARTIFACT_CHUNK_STORE
                .with_borrow(|r| r.get(&ArtifactChunkKey(**hash, index as u32)))
                .ok_or_else(|| "artifact chunk is missing".to_string())?;
            if within >= chunk.len() {
                return Err("artifact chunk is truncated".to_string());
            }
            let available = chunk.len().saturating_sub(within);
            let count = available.min(end - cursor);
            out.extend_from_slice(&chunk[within..within + count]);
            cursor += count;
        }
        return Ok(out);
    }
    let wasm = WASM_STORE
        .with_borrow(|r| r.get(hash))
        .ok_or_else(|| "NotFound: wasm not found".to_string())?;
    if offset > wasm.wasm.len() {
        return Err("offset exceeds artifact size".to_string());
    }
    let end = offset.saturating_add(take).min(wasm.wasm.len());
    Ok(wasm.wasm[offset..end].to_vec())
}

pub fn storage_chunk_count(hash: &ByteArray<32>) -> Result<u32, String> {
    let metadata = get_metadata(hash)?;
    Ok((metadata.wasm_size as usize).div_ceil(ARTIFACT_STORAGE_CHUNK_BYTES) as u32)
}

pub fn storage_chunk(hash: &ByteArray<32>, index: u32) -> Result<Vec<u8>, String> {
    let offset = (index as usize)
        .checked_mul(ARTIFACT_STORAGE_CHUNK_BYTES)
        .ok_or_else(|| "artifact chunk offset overflowed".to_string())?;
    get_chunk(hash, offset, ARTIFACT_STORAGE_CHUNK_BYTES)
}

pub fn list_legacy_artifacts(prev: Option<ByteArray<32>>, take: usize) -> Vec<ByteArray<32>> {
    WASM_STORE.with_borrow(|r| {
        let lower = prev
            .map(|hash| std::ops::Bound::Excluded(*hash))
            .unwrap_or(std::ops::Bound::Unbounded);
        r.keys_range((lower, std::ops::Bound::Unbounded))
            .take(take)
            .map(ByteArray::from)
            .collect()
    })
}

pub fn migrate_legacy_artifact(hash: &ByteArray<32>) -> Result<bool, String> {
    if ARTIFACT_META_STORE.with_borrow(|r| r.contains_key(&**hash)) {
        return Ok(false);
    }
    let legacy = WASM_STORE
        .with_borrow(|r| r.get(hash))
        .ok_or_else(|| "NotFound: legacy artifact not found".to_string())?;
    let module_hash = legacy.effective_module_hash(hash)?;
    let encoding = legacy.effective_encoding();
    let wasm = legacy.wasm.into_vec();
    let chunks = wasm.len().div_ceil(ARTIFACT_STORAGE_CHUNK_BYTES) as u32;
    ARTIFACT_CHUNK_STORE.with_borrow_mut(|store| {
        for (index, chunk) in wasm.chunks(ARTIFACT_STORAGE_CHUNK_BYTES).enumerate() {
            store.insert(ArtifactChunkKey(**hash, index as u32), chunk.to_vec());
        }
    });
    ARTIFACT_META_STORE.with_borrow_mut(|store| {
        store.insert(
            **hash,
            ArtifactMetadata {
                name: legacy.name,
                created_at: legacy.created_at,
                created_by: legacy.created_by,
                description: legacy.description,
                encoding,
                module_hash,
                wasm_size: wasm.len() as u64,
                chunks,
            },
        );
    });
    WASM_STORE.with_borrow_mut(|store| {
        store.remove(hash);
    });
    Ok(true)
}

pub fn validate_remove_wasm(hash: &ByteArray<32>) -> Result<(), String> {
    if get_metadata(hash).is_err() {
        return Err("NotFound: wasm not found".to_string());
    }
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
    } else {
        WASM_STORE.with_borrow_mut(|r| {
            r.remove(hash);
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
    let key = ReleaseKey(name.to_string(), prev_hash);
    let hash = RELEASE_PATH_STORE
        .with_borrow(|r| r.get(&key).map(ByteArray::from))
        .or_else(|| {
            if *prev_hash != [0u8; 32] {
                return None;
            }
            // The legacy global zero edge lost all but one wasm family.
            // Recover the first release deterministically from artifact
            // metadata and keep future publications on the v2 path.
            WASM_STORE.with_borrow(|r| {
                r.iter()
                    .filter(|entry| entry.value().name == name)
                    .min_by_key(|entry| (entry.value().created_at, *entry.key()))
                    .map(|entry| ByteArray::from(*entry.key()))
            })
        })
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

pub fn rebuild_log_index(start: u64, take: usize) -> Result<u64, String> {
    let len = INSTALL_LOGS.with_borrow(|logs| logs.len());
    if start > len {
        return Err("log rebuild cursor exceeds log length".to_string());
    }
    let end = start.saturating_add(take as u64).min(len);
    for id in start..end {
        if let Some(log) = INSTALL_LOGS.with_borrow(|logs| logs.get(id)) {
            LOG_INDEX_STORE.with_borrow_mut(|index| {
                index.insert(LogKey(log.name, id), id);
            });
        }
    }
    Ok(end)
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
    INSTALL_LOGS.with(|r| {
        let logs = r.borrow();
        let latest = logs.len();
        if latest == 0 || take == 0 {
            return vec![];
        }

        let prev = prev.unwrap_or(latest);
        if prev > latest || prev == 0 {
            return vec![];
        }

        if LOG_INDEX_STORE.with_borrow(|index| index.len()) == latest {
            return LOG_INDEX_STORE.with_borrow(|index| {
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
            });
        }

        let mut idx = prev.saturating_sub(1);
        let mut res: Vec<DeploymentInfo> = Vec::with_capacity(take);
        while let Some(log) = logs.get(idx) {
            // entries for other wasm names are skipped, but the cursor must
            // still move or the loop never terminates
            if log.name == name {
                res.push(deployment_info_with_args(idx, log));

                if res.len() >= take {
                    break;
                }
            }

            if idx == 0 {
                break;
            }
            idx -= 1;
        }
        res
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
