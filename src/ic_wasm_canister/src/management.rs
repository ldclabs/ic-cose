//! Cycle-conscious management-canister operations.
//!
//! The upstream bindings intentionally expose complete management-canister
//! records. Most deployment paths need only a few fields, though, and decoding
//! the complete records repeatedly is expensive. This module is the internal
//! seam that keeps those projections and the zero-copy install encoding in one
//! place.

use candid::{CandidType, Nat, Principal};
use ic_cdk::call::{Call, Error};
use ic_cdk_management_canister as mgt;
use ic_cose_types::format_error;
use num_traits::ToPrimitive;
use serde::Deserialize;
use serde_bytes::ByteArray;

/// Keep direct install payloads comfortably below the 2 MiB inter-canister
/// message limit, including Candid framing and init/upgrade arguments.
const MAX_DIRECT_INSTALL_PAYLOAD_BYTES: usize = 1_500_000;
/// The management-canister chunk limit is 1 MiB.
const UPLOAD_CHUNK_BYTES: usize = 1024 * 1024;

/// The narrow projection used by deployment checks.
///
/// Candid record width subtyping lets the management canister return its full
/// `canister_info` record while this canister decodes only these two fields.
#[derive(CandidType, Deserialize)]
struct CanisterInfoProjection {
    module_hash: Option<Vec<u8>>,
    controllers: Vec<Principal>,
}

/// The narrow projection used by batch top-up.
#[derive(CandidType, Deserialize)]
struct CanisterCyclesProjection {
    cycles: Nat,
}

/// Complete `create_canister` input including the optimistic sender version.
#[derive(CandidType)]
struct CreateCanisterArgs {
    settings: Option<mgt::CanisterSettings>,
    sender_canister_version: Option<u64>,
}

#[derive(Debug)]
pub struct CanisterInfo {
    pub module_hash: Option<ByteArray<32>>,
    pub controllers: Vec<Principal>,
}

/// Creates a canister with exactly `creation_budget` cycles attached.
///
/// Unlike `create_canister_with_extra_cycles`, this does not add the subnet's
/// creation fee on top. The fee is deducted from the attached budget, matching
/// the CMC path used when a template pins another subnet.
pub async fn create_canister(
    settings: mgt::CanisterSettings,
    creation_budget: u128,
) -> Result<Principal, Error> {
    let response = Call::unbounded_wait(Principal::management_canister(), "create_canister")
        .with_arg(CreateCanisterArgs {
            settings: Some(settings),
            sender_canister_version: Some(ic_cdk::api::canister_version()),
        })
        .with_cycles(creation_budget)
        .await?;
    let result: mgt::CreateCanisterResult = response.candid().map_err(Error::from)?;
    Ok(result.canister_id)
}

/// Complete `install_code` input including the optimistic sender version.
/// Borrowing the byte slices avoids the extra full-module clone performed by
/// the convenience binding before it Candid-encodes the request.
#[derive(CandidType)]
struct InstallCodeArgs<'a> {
    mode: mgt::CanisterInstallMode,
    canister_id: Principal,
    wasm_module: &'a [u8],
    arg: &'a [u8],
    sender_canister_version: Option<u64>,
}

/// Complete `upload_chunk` input borrowing the source chunk.
#[derive(CandidType)]
struct UploadChunkArgs<'a> {
    canister_id: Principal,
    chunk: &'a [u8],
}

/// Complete `install_chunked_code` input including the sender version.
#[derive(CandidType)]
struct InstallChunkedCodeArgs<'a> {
    mode: mgt::CanisterInstallMode,
    target_canister: Principal,
    store_canister: Option<Principal>,
    chunk_hashes_list: &'a [mgt::ChunkHash],
    wasm_module_hash: &'a [u8],
    arg: &'a [u8],
    sender_canister_version: Option<u64>,
}

/// Reads only the module hash and controllers of a canister.
///
/// `canister_info` is sufficient for install/upgrade safety checks and lets us
/// avoid decoding and allocating the many unused `canister_status` metrics.
pub async fn canister_info(canister: Principal) -> Result<CanisterInfo, String> {
    let response = Call::bounded_wait(Principal::management_canister(), "canister_info")
        .with_arg(mgt::CanisterInfoArgs {
            canister_id: canister,
            num_requested_changes: None,
        })
        .await
        .map_err(format_error)?;
    let info: CanisterInfoProjection = response.candid().map_err(format_error)?;
    let module_hash = info
        .module_hash
        .map(|hash| {
            let hash: [u8; 32] = hash
                .try_into()
                .map_err(|_| "module_hash is not 32 bytes".to_string())?;
            Ok::<_, String>(ByteArray::from(hash))
        })
        .transpose()?;
    Ok(CanisterInfo {
        module_hash,
        controllers: info.controllers,
    })
}

/// Reads and decodes only the cycle balance field of `canister_status`.
pub async fn cycle_balance(canister: Principal) -> Result<u128, String> {
    let response = Call::bounded_wait(Principal::management_canister(), "canister_status")
        .with_arg(mgt::CanisterStatusArgs {
            canister_id: canister,
        })
        .await
        .map_err(format_error)?;
    let status: CanisterCyclesProjection = response.candid().map_err(format_error)?;
    status
        .cycles
        .0
        .to_u128()
        .ok_or_else(|| "canister cycle balance exceeds u128".to_string())
}

/// Installs one exact stored artifact, using chunked installation only when the
/// combined direct payload would be too large.
///
/// `artifact_hash` is the SHA-256 key under which `wasm_module` was loaded. It
/// is also the hash required by `install_chunked_code`, so the caller does not
/// need to hash a multi-megabyte artifact again on every deployment.
pub async fn install_code(
    canister: Principal,
    mode: mgt::CanisterInstallMode,
    wasm_module: &[u8],
    artifact_hash: ByteArray<32>,
    arg: &[u8],
) -> Result<(), String> {
    if use_direct_install(wasm_module.len(), arg.len()) {
        let response = Call::unbounded_wait(Principal::management_canister(), "install_code")
            .with_arg(InstallCodeArgs {
                mode,
                canister_id: canister,
                wasm_module,
                arg,
                sender_canister_version: Some(ic_cdk::api::canister_version()),
            })
            .await
            .map_err(format_error)?;
        return response.candid().map_err(format_error);
    }

    install_chunked_code(canister, mode, wasm_module, artifact_hash, arg).await
}

fn use_direct_install(wasm_bytes: usize, arg_bytes: usize) -> bool {
    wasm_bytes.saturating_add(arg_bytes) <= MAX_DIRECT_INSTALL_PAYLOAD_BYTES
}

async fn install_chunked_code(
    canister: Principal,
    mode: mgt::CanisterInstallMode,
    wasm_module: &[u8],
    artifact_hash: ByteArray<32>,
    arg: &[u8],
) -> Result<(), String> {
    let clear_args = mgt::ClearChunkStoreArgs {
        canister_id: canister,
    };
    mgt::clear_chunk_store(&clear_args)
        .await
        .map_err(format_error)?;

    let install_result = async {
        let mut chunk_hashes = Vec::with_capacity(wasm_module.len().div_ceil(UPLOAD_CHUNK_BYTES));
        for chunk in wasm_module.chunks(UPLOAD_CHUNK_BYTES) {
            let response = Call::unbounded_wait(Principal::management_canister(), "upload_chunk")
                .with_arg(UploadChunkArgs {
                    canister_id: canister,
                    chunk,
                })
                .await
                .map_err(format_error)?;
            let hash: mgt::UploadChunkResult = response.candid().map_err(format_error)?;
            chunk_hashes.push(hash);
        }

        let response =
            Call::unbounded_wait(Principal::management_canister(), "install_chunked_code")
                .with_arg(InstallChunkedCodeArgs {
                    mode,
                    target_canister: canister,
                    store_canister: None,
                    chunk_hashes_list: &chunk_hashes,
                    wasm_module_hash: artifact_hash.as_ref(),
                    arg,
                    sender_canister_version: Some(ic_cdk::api::canister_version()),
                })
                .await
                .map_err(format_error)?;
        response.candid().map_err(format_error)
    }
    .await;

    // The chunks are billed as target-canister memory and are not needed after
    // the install attempt. Cleanup is best effort because a successful install
    // must not be reported as failed solely due to cleanup.
    let _ = mgt::clear_chunk_store(&clear_args).await;
    install_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_canister_args_include_the_sender_version() {
        #[derive(CandidType, Deserialize)]
        struct CanonicalCreateCanisterArgs {
            settings: Option<mgt::CanisterSettings>,
            sender_canister_version: Option<u64>,
        }

        let bytes = candid::encode_one(CreateCanisterArgs {
            settings: Some(mgt::CanisterSettings::default()),
            sender_canister_version: Some(17),
        })
        .unwrap();
        let decoded: CanonicalCreateCanisterArgs = candid::decode_one(&bytes).unwrap();
        assert!(decoded.settings.is_some());
        assert_eq!(decoded.sender_canister_version, Some(17));
    }

    #[test]
    fn direct_install_limit_accounts_for_arguments() {
        assert!(use_direct_install(MAX_DIRECT_INSTALL_PAYLOAD_BYTES, 0));
        assert!(use_direct_install(
            MAX_DIRECT_INSTALL_PAYLOAD_BYTES - 10,
            10
        ));
        assert!(!use_direct_install(MAX_DIRECT_INSTALL_PAYLOAD_BYTES, 1));
        assert!(!use_direct_install(usize::MAX, usize::MAX));
    }

    #[test]
    fn canister_info_projection_accepts_the_full_record_shape() {
        #[derive(CandidType)]
        struct FullCanisterInfo {
            total_num_changes: u64,
            recent_changes: Vec<()>,
            module_hash: Option<Vec<u8>>,
            controllers: Vec<Principal>,
        }

        let controller = Principal::from_slice(&[1, 2, 3]);
        let bytes = candid::encode_one(FullCanisterInfo {
            total_num_changes: 7,
            recent_changes: vec![],
            module_hash: Some(vec![9; 32]),
            controllers: vec![controller],
        })
        .unwrap();
        let projected: CanisterInfoProjection = candid::decode_one(&bytes).unwrap();
        assert_eq!(projected.module_hash, Some(vec![9; 32]));
        assert_eq!(projected.controllers, vec![controller]);
    }
}
