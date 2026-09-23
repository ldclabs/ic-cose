# `ic_wasm_canister` Integration Guide

[English](README.md) · [简体中文](README.zh-CN.md)

`ic_wasm_canister` is a WASM artifact repository and canister deployment management service on the Internet Computer. It provides module publishing, version lineage tracking, canister creation and upgrades, batch calls, and cycles replenishment, supporting crash-resilient provisioning workflows backed by immutable templates and pre-created canister pools.

This document serves as a technical reference for frontend, backend, governance, and canister developers integrating against the current implementation in this repository. Definitive Candid interfaces are defined in [ic_wasm_canister.did](ic_wasm_canister.did), and runtime behaviors follow [src/api.rs](src/api.rs), [src/api_admin.rs](src/api_admin.rs), [src/api_provision.rs](src/api_provision.rs), and [src/store/mod.rs](src/store/mod.rs). Deployed instances may run different versions; always verify the target canister's Candid interface before integrating.

## Table of Contents

- [`ic_wasm_canister` Integration Guide](#ic_wasm_canister-integration-guide)
  - [Table of Contents](#table-of-contents)
  - [1. Integration Endpoints and Protocol Conventions](#1-integration-endpoints-and-protocol-conventions)
  - [2. Deployment and Minimal Workflow](#2-deployment-and-minimal-workflow)
    - [2.1 Deploying the Manager Canister](#21-deploying-the-manager-canister)
    - [2.2 Publishing a Minimal Installable Module](#22-publishing-a-minimal-installable-module)
    - [2.3 Assigning Roles](#23-assigning-roles)
  - [3. Roles and Permission Boundaries](#3-roles-and-permission-boundaries)
  - [4. WASM Publishing and Version Lineage](#4-wasm-publishing-and-version-lineage)
    - [4.1 Artifact Hash vs. Module Hash](#41-artifact-hash-vs-module-hash)
    - [4.2 Publishing Endpoints](#42-publishing-endpoints)
    - [4.3 Version Lineage is Not Semver](#43-version-lineage-is-not-semver)
  - [5. Classic Creation and Deployment Endpoints](#5-classic-creation-and-deployment-endpoints)
  - [6. Provisioning Templates and Pre-Created Canister Pool](#6-provisioning-templates-and-pre-created-canister-pool)
    - [6.1 Template Fields and Hashing](#61-template-fields-and-hashing)
    - [6.2 Template and Pool Endpoints](#62-template-and-pool-endpoints)
    - [6.3 Pool Refill and Reconciliation](#63-pool-refill-and-reconciliation)
  - [7. Reservation, Installation, and Release](#7-reservation-installation-and-release)
    - [7.1 Request IDs and Expiry Windows](#71-request-ids-and-expiry-windows)
    - [7.2 Reservation](#72-reservation)
    - [7.3 Installation](#73-installation)
    - [7.4 Receipts and Recovery](#74-receipts-and-recovery)
    - [7.5 Release](#75-release)
  - [8. Exact Upgrades and Retries](#8-exact-upgrades-and-retries)
  - [9. Querying Logs and Runtime Operations](#9-querying-logs-and-runtime-operations)
    - [9.1 Query Endpoints](#91-query-endpoints)
    - [9.2 Batch Calls](#92-batch-calls)
    - [9.3 Cycles Top-Up](#93-cycles-top-up)
  - [10. Client Integration Examples](#10-client-integration-examples)
    - [10.1 TypeScript: Chunked Upload](#101-typescript-chunked-upload)
    - [10.2 TypeScript: Reservation and Installation](#102-typescript-reservation-and-installation)
    - [10.3 Rust: Computing Template Hashes Before Approval](#103-rust-computing-template-hashes-before-approval)
  - [11. Governance Validation and Canister Upgrades](#11-governance-validation-and-canister-upgrades)
    - [11.1 Validation Methods](#111-validation-methods)
    - [11.2 Upgrading the Manager Canister Itself](#112-upgrading-the-manager-canister-itself)
  - [12. Error Handling and Integration Constraints](#12-error-handling-and-integration-constraints)
  - [License](#license)

## 1. Integration Endpoints and Protocol Conventions

| Resource                                                              | Purpose                                                                             |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| [ic_wasm_canister.did](ic_wasm_canister.did)                          | Complete method signatures, record types, and query annotations                     |
| [src/declarations/ic_wasm_canister](../declarations/ic_wasm_canister) | JavaScript IDL and TypeScript types; regenerate via `make bindings` |
| [Rust Types](../ic_cose_types/src/types/wasm.rs)                      | Template structures, hashing helpers, requests, and receipt types                   |
| [src/management.rs](src/management.rs)                                | Canister creation, status inspection, and direct / chunked code installation        |
| [dfx.json](../../dfx.json)                                            | Workspace build and local deployment configuration                                  |

Integration requires a network host, the management service's canister ID, and an authenticated caller identity. The target canister ID and the manager canister ID are distinct entities. In this guide, "controller" refers to the IC controller of the management service or its configured `governance_canister`; target canister controllers determine whether management operations succeed.

Business methods return Candid `variant { Ok : T; Err : text }`, or `variant { Ok; Err : text }` when no payload is returned. This document denotes them as `Result<T>` and `Result<()>`. Candid identifiers such as `Result_1` are autogenerated aliases rather than protocol error codes.

| Candid Type                 | TypeScript / Calling Convention                                                   |
| --------------------------- | --------------------------------------------------------------------------------- |
| `opt T`                     | `[]` for empty, `[value]` for present; never JavaScript `null`                    |
| `blob`                      | Raw bytes `Uint8Array` or `number[]`; never a hex or base64 string                |
| Hashes, `request_id`        | Declared as Candid `blob`, but Rust fixed-size types require exactly **32 bytes** |
| `principal`                 | `Principal` instance                                                              |
| `nat`, `nat64`              | `bigint`; cycle quantities are represented internally as `u128`                   |
| `nat16`, `nat32`            | `number`                                                                          |
| `WasmEncoding`              | `{ Raw: null }` or `{ Gzip: null }` (case-sensitive)                              |
| `vec record { text; blob }` | `[string, Uint8Array                                                              | number[]][]` |
| `Result<T>`                 | `{ Ok: value }` or `{ Err: message }`                                             |

Timestamp conventions:
- Operational timestamps (`expires_at`, `deploy_at`, `created_at`, `updated_at`, `reserved_at`, `released_at`) are Unix **milliseconds**.
- `freezing_threshold` in `CanisterSettings` and `ProvisionSettings` is measured in **seconds**.
- `topup_threshold` and `topup_amount` in `InitArgs` are measured in **cycles**.

The `args` and `init_args` fields represent **Candid binary encoded parameter sequences** consumed by target canisters. Empty arguments `()` encode to the 6-byte sequence hex `4449444c0000`, not an empty blob and not the string `"()"`. Classic deployment endpoints interpret `args = null` as this default empty encoding; provisioning endpoints require explicit byte sequences.

In addition to business `Err` results, clients must handle network failures, guard rejections, management canister rejects, and traps. Queries return without consensus; receipts are service state records rather than third-party financial settlement proofs.

## 2. Deployment and Minimal Workflow

### 2.1 Deploying the Manager Canister

Run the following from the workspace root with Rust, the `wasm32-unknown-unknown` target, and `dfx` installed:

```bash
rustup target add wasm32-unknown-unknown
dfx start --background

RUSTFLAGS='--cfg=getrandom_backend="custom"' dfx deploy ic_wasm_canister --argument '(opt variant { Init = record {
  name = "Local WASM Manager";
  topup_threshold = 1_000_000_000_000;
  topup_amount = 5_000_000_000_000;
  governance_canister = null;
}})'

dfx canister call ic_wasm_canister get_state '()'
dfx canister call ic_wasm_canister get_canister_status '(null)'
```

Initial installation requires `opt variant { Init = ... }`. Passing `null` traps with an initialization error. `name` is an administrative display label. Top-up parameters configure manual `admin_batch_topup` executions; **they do not run automatic background timers**. Top-up must either be disabled with zeroes for both values or satisfy `topup_amount > topup_threshold > 0`. A configured `governance_canister` principal must be non-anonymous; it receives application-level controller permissions without modifying IC canister controllers.

### 2.2 Publishing a Minimal Installable Module

The following command publishes a minimal 8-byte WASM binary (standard WASM header with no code or exports) to verify local publishing and creation flows. Run this as the canister controller:

```bash
dfx canister call ic_wasm_canister admin_add_wasm '(record {
  name = "demo";
  description = "Minimal module for local integration";
  encoding = opt variant { Raw };
  wasm = blob "\00\61\73\6d\01\00\00\00";
}, null)'

dfx canister call ic_wasm_canister get_state '()'

# Resolves latest for "demo" and creates target; returns target principal on success.
dfx canister call ic_wasm_canister admin_create_canister '("demo", null, null)'

dfx canister call ic_wasm_canister get_deployed_canisters '()'
dfx canister call ic_wasm_canister get_deployed_canisters_info '()'
dfx canister call ic_wasm_canister deployment_logs '("demo", null, opt 10)'
```

Creation debits a fixed 2T cycles from the management canister balance (inclusive of the subnet creation fee). Attempting to publish identical artifact bytes returns `wasm already exists`. Inspect `get_state.latest_version` or query `get_wasm` using the artifact hash to verify whether a module has already been published.

### 2.3 Assigning Roles

```bash
export MYID=$(dfx identity get-principal)
dfx canister call ic_wasm_canister admin_add_managers "(vec { principal \"$MYID\" })"
dfx canister call ic_wasm_canister admin_add_committers "(vec { principal \"$MYID\" })"
dfx canister call ic_wasm_canister admin_add_provisioners "(vec { principal \"$MYID\" })"
```

These commands demonstrate role assignment endpoints. Controllers already possess all operational permissions; application canisters usually require only the provisioner role.

## 3. Roles and Permission Boundaries

| Operation                                                  | Controller / Governance | Manager | Committer | Provisioner      | Public |
| ---------------------------------------------------------- | ----------------------- | ------- | --------- | ---------------- | ------ |
| Manage managers / committers / provisioners                | Yes                     | No      | No        | No               | No     |
| Publish WASM, upload / commit / clear chunks               | Yes                     | Yes     | Yes       | No               | No     |
| Classic create, `admin_deploy`, update target settings     | Yes                     | No      | No        | No               | No     |
| Batch call / top-up, status, deployment logs, pool listing | Yes                     | Yes     | No        | No               | No     |
| Add / remove templates, reconcile pool creation            | Yes                     | No      | No        | No               | No     |
| `admin_refill_pool`                                        | Yes                     | Yes     | No        | No               | No     |
| Reserve, install, release, `ensure_deployment`             | Yes                     | No      | No        | Yes              | No     |
| State summary, WASM, deployed summaries, templates         | Yes                     | Yes     | Yes       | Yes              | Yes    |
| Provisioning request receipts                              | Yes                     | No      | No        | Bound owner only | No     |
| `validate_admin_*`                                         | Yes                     | No      | No        | No               | No     |

Roles are strictly disjoint and do not inherit privileges. For instance, managers cannot invoke `reserve_canister`, and provisioners cannot invoke `get_canister_status`. Role modification inputs must be non-empty, deduplicated, and contain no anonymous principals.

Important implementation boundaries:
- `request_id` shares a **global namespace across the canister**, but the first request durably binds the caller principal as `owner` alongside the original `expires_at`. Other provisioners cannot inspect, install, or release that request. Legacy records missing owner data bind to the caller upon their first valid retry.
- Provisioner initial installations are restricted by approved templates; however, `ensure_deployment` allows upgrading deployed targets to **any published artifact under the matching `wasm_name`**, without requiring a dedicated template for that target artifact. Publishing rights therefore influence the scope of available upgrade artifacts.
- `admin_batch_call` allows managers to invoke arbitrary methods on deployed targets using the management canister's identity without method whitelisting; this extends beyond read-only operational capabilities.
- WASM artifacts, templates, and summaries are publicly readable. Receipts are restricted to the request owner or controller. Modern deployment logs store only the SHA-256 digest and byte length of arguments, omitting plaintext arguments; legacy logs may still return up to 8 KiB of historical arguments to controllers and managers.

Role endpoints are updates returning `Result<()>`: `admin_add_managers`, `admin_remove_managers`, `admin_add_committers`, `admin_remove_committers`, `admin_add_provisioners`, `admin_remove_provisioners`.

## 4. WASM Publishing and Version Lineage

### 4.1 Artifact Hash vs. Module Hash

| Identifier                        | Definition                                                                                                                                   |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `artifact_hash` / `WasmInfo.hash` | SHA-256 digest calculated over stored and transmitted artifact bytes                                                                         |
| `expected_module_hash`            | Module hash expected to be reported by the IC management canister post-installation                                                          |
| `ProvisionReceipt.module_hash`    | Actual module hash verified and recorded from the management canister                                                                        |
| `DeploymentInfo.wasm_hash`        | Artifact hash of the deployed artifact                                                                                                       |
| `DeploymentInfo.prev_hash`        | Classic deployment: verified previous module hash; `ensure_deployment`: declared `expected_prev_module_hash`; initial install: 32 zero bytes |

For Raw artifacts, the artifact hash matches the installed module hash. For Gzip artifacts, the artifact hash covers the compressed archive; **it does not equal the uncompressed module hash installed in the canister**. Always pin reproducible build artifacts and verify the uncompressed module hash reported by the IC runtime.

Publishing validates name and description boundaries, verifies that Raw or decompressed Gzip bytes parse as valid WebAssembly headers, and computes both artifact and module hashes. Gzip decompression is capped at 100 MiB; artifact uploads are capped at 64 MiB.

### 4.2 Publishing Endpoints

| Method                               | Mode                           | Signature (`Input → Ok`)                                                              |
| ------------------------------------ | ------------------------------ | ------------------------------------------------------------------------------------- |
| `admin_add_wasm`                     | update                         | `(AddWasmInput, opt blob force_prev_hash) → ()`                                       |
| `admin_add_wasm_chunk`               | update                         | `(blob chunk) → blob` (Returns chunk SHA-256)                                         |
| `admin_commit_wasm_chunks`           | update                         | `(CommitWasmChunksInput, opt blob force_prev_hash) → blob` (Returns artifact SHA-256) |
| `admin_clear_wasm_chunks`            | update                         | `() → nat64` (Returns count of deleted chunks)                                        |
| `admin_remove_wasm`                  | update / controller            | `(blob artifact_hash) → ()` (Only unreferenced, non-latest artifacts)                 |
| `get_wasm`                           | query                          | `(blob artifact_hash) → WasmInfo` (Compatible reads for artifacts <= 1.5 MB)          |
| `get_wasm_metadata`                  | query                          | `(blob artifact_hash) → WasmMetadata`                                                 |
| `get_wasm_chunk`                     | query                          | `(blob artifact_hash, nat64 offset, nat32 take) → blob` (Max 1 MiB per call)          |
| `list_latest_wasm_versions`          | query                          | `(opt text, opt nat32) → vec record { text; blob }`                                   |
| `get_next_wasm_version`              | query                          | `(text, blob previous_module_hash) → WasmMetadata`                                    |
| `list_legacy_wasm_artifacts`         | query / controller or manager  | `(opt blob, opt nat32) → vec blob`                                                    |
| `admin_migrate_legacy_wasm_artifact` | update / controller or manager | `(blob) → bool` (Migrates one legacy monolithic artifact)                             |

`AddWasmInput = { name : text; description : text; wasm : blob; encoding : opt WasmEncoding }`. `encoding` defaults to Raw when omitted. `WasmInfo` and `WasmMetadata` return `hash`, `module_hash`, and `wasm_size`.

Artifacts are globally deduplicated by `artifact_hash`: identical byte sequences cannot be republished under another name or description. Successful publishing updates `latest_version[name]`. Safe deletion verifies that an artifact is not latest, has no outgoing lineage edges, and is unreferenced by templates, active deployments, or requests.

Chunked Upload Workflow:

1. Slice the artifact into contiguous chunks between **1 and 1,048,576 bytes (1 MiB)**. Invoke `admin_add_wasm_chunk` sequentially using the same identity.
2. Save the returned 32-byte chunk hashes. Uploading an identical chunk from the same caller returns the existing hash without allocating duplicate storage.
3. Call `admin_commit_wasm_chunks({ name; description; encoding; chunk_hashes; artifact_hash }, force_prev_hash)`, where `chunk_hashes` preserves original slicing order and `artifact_hash = SHA-256(full_artifact_bytes)`.
4. The canister stitches chunks, validates the aggregated hash, checks deduplication, and updates lineage records.
5. On successful commit, **all staged chunks for that caller are cleared**, including chunks not referenced in the commit. Chunks remain on failure to allow retry. Use `admin_clear_wasm_chunks` to abort an upload.

Each caller may stage up to 64 chunks, supporting artifacts up to **67,108,864 bytes (64 MiB)**. Do not run concurrent upload pipelines with the same caller identity, as a commit or clear call from one task will flush chunks belonging to another. The artifact staging store is completely independent of target canister management chunk stores.

Large artifacts must be downloaded via metadata and chunk endpoints. Storage is organized into 1 MiB stable blocks; code installations stream directly from stable storage to prevent allocating duplicate 64 MiB buffers on the Wasm heap.

### 4.3 Version Lineage is Not Semver

Publishing establishes a transition edge `(wasm_name, previous_module_hash) → new_artifact_hash`. The previous hash is derived from the current latest module hash for that name; the initial release under a name uses an all-zero hash. The new artifact hash is then recorded as latest.

`force_prev_hash` serves as an optimistic CAS lock on the artifact's latest pointer. When provided, it must match the current latest artifact hash for that name (all-zeros for initial publish), and existing lineage edges are protected against overwrite. Publishing an artifact whose module hash matches an existing or historical module hash under the same name (including recompressed variants) is rejected to prevent cyclic dependency loops.

Lineage is partitioned by `wasm_name`; independent modules starting from all-zero hashes do not conflict. Legacy monolithic artifacts without explicit encodings are identified via Gzip magic headers during incremental migration to preserve exact artifact bytes and calculate uncompressed module hashes.

## 5. Classic Creation and Deployment Endpoints

| Method                           | Signature (`Input → Ok`)                                                              | Description                                                             |
| -------------------------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `admin_create_canister`          | `(text wasm_name, opt CanisterSettings, opt blob args) → principal`                   | Creates canister on local subnet and installs latest module             |
| `admin_create_on`                | `(principal subnet, text wasm_name, opt CanisterSettings, opt blob args) → principal` | Creates canister on specified subnet via CMC and installs latest module |
| `admin_deploy`                   | `(DeployWasmInput, opt blob ignore_prev_hash) → ()`                                   | Installs code on empty canister or upgrades existing module             |
| `admin_update_canister_settings` | `(UpdateSettingsArgs) → ()`                                                           | Updates settings on registered target canisters                         |
| `admin_handoff_canister`         | `(UpdateSettingsArgs) → ()`                                                           | Relinquishes control to new controllers and unregisters target          |
| `admin_reconcile_deployment`     | `(principal, text, blob artifact_hash) → ()`                                          | Reconciles registration after verifying module and controller status    |

All endpoints require controller or governance privileges. `DeployWasmInput = { name : text; canister : principal; args : opt blob }`. `UpdateSettingsArgs = { canister_id : principal; settings : CanisterSettings }`.

Creation automatically appends the **management canister itself** to target controllers, preserving explicitly supplied controllers. Passing empty settings leaves the target under exclusive control of the management service. Each creation attaches a fixed **2,000,000,000,000 cycles (2T)** (inclusive of the subnet creation fee); the target receives the remaining balance. `admin_create_on` routes through the Cycles Minting Canister (CMC), which may not be available on local development replicas.

`CanisterSettings` supports configuring `controllers`, `compute_allocation`, `memory_allocation`, `freezing_threshold`, `reserved_cycles_limit`, `wasm_memory_limit`, `wasm_memory_threshold`, `log_visibility`, `log_memory_limit`, and `environment_variables`. Standard settings updates reject anonymous or duplicate controllers and force retention of the management canister; transferring full ownership requires calling `admin_handoff_canister`.

`admin_deploy` requires the second argument to specify the expected current module hash (all-zeros for empty targets); passing `null` is rejected. Pre-checks, installation, and post-install hash verification run under a per-canister mutex. When deploying a specific artifact or requiring idempotent replays, use `ensure_deployment`.

Classic endpoints do not use `request_id`. If a response is lost during creation, the assigned canister ID cannot be retrieved via request parameters. If creation succeeds but code installation fails, the error returns `canister <id> created, but install failed: ...` and records an audit log. Do not re-run creation; inspect the returned ID and retry installation via `admin_deploy`. Only canisters with confirmed installations enter `deployed_list`.

All installation routines clear the target's management chunk store before proceeding. If `wasm_size + args_size <= 1,500,000 bytes`, code is installed directly via `install_code`; larger binaries stream from stable storage in 1 MiB blocks and install via `install_chunked_code`. Target chunk stores are cleaned up on a best-effort basis post-install. While the manager synchronizes operations internally, external controllers should not manipulate the target's chunk store concurrently.

## 6. Provisioning Templates and Pre-Created Canister Pool

Provisioning isolates potentially non-deterministic canister creation inside a pre-created pool. Client workflows bind to pre-registered canisters:

```text
Publish artifact → Approve immutable template → admin_refill_pool (1 per call)
                                                   ↓ Available
reserve_canister(request_id) → Reserved
                                 ├─ ensure_install → Installed
                                 └─ release_reservation → Available + Released receipt
```

The management canister does not verify end-user payments, bill custom prices, or automatically trigger refills based on order volume. Integrating systems are responsible for approving templates, mapping payment orders to request IDs, tracking inventory, and executing recovery workflows.

### 6.1 Template Fields and Hashing

| `ProvisionTemplate` Field | Type / Constraint                                                                    |
| ------------------------- | ------------------------------------------------------------------------------------ |
| `id`, `wasm_name`         | `text`, 1–64 bytes, matching `^[a-z0-9_]+$`                                          |
| `artifact_hash`           | 32-byte SHA-256 digest of published artifact                                         |
| `expected_module_hash`    | 32-byte expected post-install module hash                                            |
| `encoding`                | `Raw` or `Gzip`, matching published artifact metadata                                |
| `settings`                | Fixed `ProvisionSettings` (see below)                                                |
| `subnet`                  | `opt principal`; `null` creates on local subnet, specified principal routes via CMC  |
| `initial_cycles`          | `nat` (internally `u128`, > 0); total creation budget, **inclusive of creation fee** |
| `max_init_args_bytes`     | `nat32`, 1–262,144 bytes                                                             |
| `pool_size`               | `nat16`, 1–32; target `Available` threshold for refills, not a lifetime ceiling      |

`ProvisionSettings` specifies `controllers : vec principal`, along with optional `compute_allocation`, `memory_allocation`, `freezing_threshold`, `wasm_memory_limit` (`nat64`), and `reserved_cycles_limit` (`nat`).

The `controllers` vector must contain exactly two distinct, non-anonymous principals ordered canonically, including the management canister itself and `governance_canister` (if configured).

`admin_add_provision_template(ProvisionTemplate) → Result<ProvisionTemplateInfo>` validates constraints, confirms artifact existence, verifies name/encoding alignment, and asserts that `expected_module_hash` matches the module hash calculated during publishing. Template IDs are immutable; updates require adding a new template ID.

`ProvisionTemplateInfo` returns the original template along with `hash`, `settings_hash`, `subnet_policy_hash`, `created_at`, `created_by`, `pool_status`, and counters for `available`, `reserved`, `installed`, and `tombstones`.

Hashes follow the formula `SHA-256(canonical_CBOR([domain, value]))`, using deterministic CBOR encoding defined in [ic_cose_types](../ic_cose_types/src/lib.rs):

| Hash Field           | Domain Separator                     | Target Value                 |
| -------------------- | ------------------------------------ | ---------------------------- |
| `hash`               | `ic-cose:provision-template:v1`      | Complete `ProvisionTemplate` |
| `settings_hash`      | `ic-cose:provision-settings:v1`      | Complete `ProvisionSettings` |
| `subnet_policy_hash` | `ic-cose:provision-subnet-policy:v1` | `template.subnet`            |

Do not substitute JSON or Candid hashes. Array ordering affects output; changing controller ordering alters the template hash. In Rust, call `template.hash()`, `template.settings.hash()`, or `template.subnet_policy_hash()`. Production workflows should verify fixed approved hashes rather than blindly accepting query results.

### 6.2 Template and Pool Endpoints

| Method                            | Mode / Privilege               | Signature (`Input → Ok`)                                  |
| --------------------------------- | ------------------------------ | --------------------------------------------------------- |
| `admin_add_provision_template`    | update / controller            | `(ProvisionTemplate) → ProvisionTemplateInfo`             |
| `admin_remove_provision_template` | update / controller            | `(text id) → ()`                                          |
| `get_provision_template`          | query / public                 | `(text id) → ProvisionTemplateInfo`                       |
| `list_provision_templates`        | query / public                 | `() → vec ProvisionTemplateInfo`                          |
| `list_provision_templates_v2`     | query / public                 | `(opt text, opt nat32) → vec ProvisionTemplateInfo`       |
| `admin_refill_pool`               | update / controller or manager | `(text id) → principal`                                   |
| `admin_reconcile_pool`            | update / controller            | `(text id, opt principal found) → ()`                     |
| `list_provision_pool`             | query / controller or manager  | `(text id) → vec PoolCanisterInfo`                        |
| `list_provision_pool_v2`          | query / controller or manager  | `(text, opt principal, opt nat32) → vec PoolCanisterInfo` |

Template deletion requires that `available + reserved == 0` and `pool_status == Idle`. Canisters transition out of the pool upon successful installation; historical `installed` counts do not prevent template deletion. Legacy list methods exceeding 1000 records reject calls and require switching to v2 pagination.

`PoolCanisterInfo` returns `canister`, `state`, `created_at`, and `request_id`. `created_at` records pool insertion time and is not overwritten upon reservation.

### 6.3 Pool Refill and Reconciliation

Refill cycles are debited from the management canister's balance; reservation and installation endpoints do not transfer `initial_cycles` on a per-order basis.

`admin_refill_pool` **creates exactly one canister per invocation**. It persists a `CreatePending` state before dispatching calls to the IC management canister or CMC. Execution is allowed only when `available < pool_size` and `pool_status == Idle`.

| `pool_status` / Creation Outcome | State Semantics & Recovery                                                                                |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `Idle`                           | No creation in progress; refills permitted when inventory is below `pool_size`                            |
| `CreatePending`                  | Canister creation in flight; concurrent refill calls for this template are rejected                       |
| Successful Creation              | Registers target as `Available` and returns status to `Idle`                                              |
| Confirmed Failure                | Returns status to `Idle` with an error (e.g., insufficient cycles, budget below subnet fee, CMC Refunded) |
| `CreateUnknown`                  | Creation dispatched but response lost or indeterminate; refills are circuit-broken                        |

Under `CreateUnknown`, operators investigate the outcome out-of-band and invoke `admin_reconcile_pool(id, found)`. Passing `found = opt principal` admits the discovered canister as `Available`; passing `null` records the creation as lost and resets the pool status to `Idle`.

When `found` is provided, reconciliation verifies that the canister has no code installed, controllers match the template, and the principal is not already tracked in another pool or deployment index. Reconciliation cannot cryptographically prove that the canister was the result of that specific lost call; operators must verify ownership before admitting principals. Passing `null` resets the pool status without destroying orphaned canisters on the subnet.

## 7. Reservation, Installation, and Release

### 7.1 Request IDs and Expiry Windows

`reserve_canister`, `ensure_install`, and `ensure_deployment` require:

```text
current_time < expires_at <= current_time + 3,600,000 ms (1 hour)
```

Expiry is validated upon method entry even if the request has completed. Once expired, owners or controllers can still query records via `get_provision_receipt`. The canister does not automatically purge expired reservations; operators can inspect them via `list_expired_reservations` and clean them up via `admin_release_expired_reservation` after verifying that the target remains uninstalled.

The original `expires_at` and `owner` are durably bound on the initial call; retries cannot extend expiration or switch caller identities. `Released` records are retained in a bounded tombstone table; `Installed` records can be compacted into permanent request-id tombstones after at least 30 days. Integrating systems must persist and never reuse `request_id` values.

If an installation or upgrade encounters network failure or lost responses, owners or controllers can call `reconcile_provision_request(request_id) → Result<ProvisionReceipt>`. This recovery method is not restricted by the original request's `expires_at`. It queries target state without reinstalling code, mutating bindings, or altering expiration. If the target runs the expected module, the receipt marks completion; if the canister remains empty (for install) or runs the previous module (for upgrade), the receipt is marked `Failed`. In-flight operations holding locks are rejected.

### 7.2 Reservation

`reserve_canister(ReserveRequest) → Result<ReservationReceipt>` executes synchronously as an update without inter-canister calls.

| `ReserveRequest` Field    | Description                                         |
| ------------------------- | --------------------------------------------------- |
| `request_id`              | Globally unique 32-byte identifier chosen by caller |
| `provision_template_id`   | Target approved template ID                         |
| `provision_template_hash` | Exact SHA-256 hash of the target template           |
| `expires_at`              | Expiration timestamp in Unix milliseconds           |

The initial call claims an `Available` canister from the pool and records the binding. If no canisters are available, it returns `no available canister...`. Replaying the same `request_id` and template returns the assigned canister without consuming additional inventory. Changing templates is rejected, and `Released` requests cannot be reused while tombstones persist.

`ReservationReceipt` returns the bound `owner` and `expires_at`. The `initial_cycles` field reflects the template's **total creation budget** rather than the target's current live balance.

### 7.3 Installation

`ensure_install(InstallRequest) → Result<ProvisionReceipt>` parameters:

| Field                                              | Verification Rules                                                         |
| -------------------------------------------------- | -------------------------------------------------------------------------- |
| `request_id`, `canister`                           | Must match reservation bindings                                            |
| `provision_template_id`, `provision_template_hash` | Must match reserved template parameters                                    |
| `expected_module_hash`                             | Must match template's approved module hash                                 |
| `init_args`                                        | Target initialization Candid bytes, within template byte limits            |
| `init_args_hash`                                   | Must match `SHA-256(init_args)`                                            |
| `provision_spec_hash`                              | Arbitrary 32-byte business spec digest; stored verbatim without evaluation |
| `expires_at`                                       | Active request time window                                                 |

The first installation attempt binds `init_args_hash` and `provision_spec_hash`; retries cannot modify these arguments. The canister sets the request stage to `InstallPending`, verifies target controllers against the template, and proceeds:
- If the canister is empty, code is installed.
- If the target already runs `expected_module_hash`, it converges as successful.
- If the target runs an unexpected module, the call is rejected.
After installation, the canister re-queries the target's module hash to verify convergence.

This workflow verifies that the deployed canister runs the approved binary; it does not prove execution semantics of `init_args`. If external controllers modify code out-of-band, matching module hashes cannot be treated as proof that specific arguments were processed.

### 7.4 Receipts and Recovery

`get_provision_receipt(blob request_id) → Result<ProvisionReceipt>` is a query endpoint restricted to the bound owner and canister controllers. Receipt fields include:

- `request_id`, `owner`, `expires_at`, `stage`, `canister`, `wasm_name`, `created_at`, `updated_at`, `error`.
- `artifact_hash` and verified `module_hash`.
- `provision_template_id` and `provision_template_hash` (present for install, empty for upgrade).
- `args_hash` and `provision_spec_hash` (bound after initial attempt; upgrade omits spec hash).
- `prev_module_hash` (present for upgrade, empty for initial install).

| Stage            | Caller Remediation                                                          |
| ---------------- | --------------------------------------------------------------------------- |
| `Reserved`       | Target bound; installation not yet attempted. May call install or release   |
| `InstallPending` | Installation attempt in progress or awaiting reconciliation. Do not release |
| `Installed`      | Installation confirmed and indexed. Persist canister ID and hashes          |
| `Failed`         | Failure recorded with error details. Does not guarantee canister is empty   |
| `Released`       | Reservation returned to pool. Do not reuse this request ID                  |

On timeouts or errors, query the receipt first. Replaying `ensure_install` on an `Installed` request re-validates the target module hash and repairs missing deployment indexes.

### 7.5 Release

`release_reservation(blob request_id, principal canister) → Result<ReleaseReceipt>` returns `{ request_id; canister; released_at }`. It requires provisioner permissions and performs:

1. Resolves the associated template and inspects the target's live controllers and module hash.
2. Asserts that the target is still empty and controllers have not drifted.
3. Rejects `Installed` or `InstallPending` requests, confirming the bound canister ID.
4. Returns the target to the pool's `Available` set, marks the request as `Released`, and records a tombstone.

Requests in the `Failed` stage may also be released if the target remains empty and properly controlled. Canisters in the `Installed` stage cannot be returned to the pool. Replays on successfully released requests return the original release receipt.

Released tombstones are retained per template: TTL is **24 hours**, capacity limit is **4096 records**, and cleanup occurs incrementally during subsequent releases (up to 64 records per invocation). Exceeding capacity limits may evict records early. Applications must permanently avoid reusing request IDs.

Expired reservations can be discovered via `list_expired_reservations(opt request_id, opt take)` and cleaned up by controllers via `admin_release_expired_reservation(request_id)`.

## 8. Exact Upgrades and Retries

`ensure_deployment(DeploymentRequest) → Result<ProvisionReceipt>` is an update method for provisioners and controllers targeting canisters already registered in `deployed_list`. It does not require prior reservation.

| `DeploymentRequest` Field   | Description                                                           |
| --------------------------- | --------------------------------------------------------------------- |
| `request_id`                | Unique 32-byte identifier for this upgrade                            |
| `canister`                  | Target canister registered in deployment index                        |
| `wasm_name`                 | Must match the target's registered module family name                 |
| `artifact_hash`             | Published artifact hash under this `wasm_name`                        |
| `expected_module_hash`      | Expected post-upgrade module hash                                     |
| `expected_prev_module_hash` | Expected module hash currently running on target                      |
| `args`, `args_hash`         | Upgrade Candid argument bytes and `SHA-256(args)` (max 262,144 bytes) |
| `expires_at`                | Valid window within 1 hour                                            |

The canister binds request parameters to `request_id` and acquires the target mutex. If the request is already `Installed`, it verifies module convergence and repairs missing indexes. Otherwise, it inspects the target's running module hash:

- Matches `expected_module_hash`: Assumes upgrade converged; returns success without re-executing upgrade hooks.
- Matches `expected_prev_module_hash`: Dispatches `upgrade` call, then verifies post-upgrade module hash.
- Any other value or empty canister: Rejects the call to prevent upgrading from unexpected states.

Canister, artifact, expected before/after module hashes, and argument hashes are immutable for a given `request_id`. Unlike provisioning, templates are not re-evaluated, but the management service must retain controller privileges over the target.

The canister applies a unified per-canister mutex covering classic deployments, provisioning installations, upgrades, releases, batch calls, and settings modifications. Mutexes persist across `await` points and do not expire via wall clocks. Transient locks clear across upgrades, while persistent attempt counters reject late callbacks. Out-of-band modifications by external controllers cannot be prevented; post-upgrade module hash verification is mandatory.

Idempotency checks evaluate whether the target runs `expected_module_hash`. The canister **does not re-execute upgrade hooks** if the target is already running the target module hash, even if different arguments are passed.

## 9. Querying Logs and Runtime Operations

### 9.1 Query Endpoints

| Method                           | Mode / Privilege               | Signature (`Input → Ok`)                                       |
| -------------------------------- | ------------------------------ | -------------------------------------------------------------- |
| `get_state`                      | query / public                 | `() → StateInfo`                                               |
| `get_deployed_canisters`         | query / public                 | `() → vec principal`                                           |
| `get_deployed_canisters_info`    | query / public                 | `() → vec DeploymentInfo`                                      |
| `get_deployed_canisters_v2`      | query / public                 | `(opt principal, opt nat32) → vec principal`                   |
| `get_deployed_canisters_info_v2` | query / public                 | `(opt principal, opt nat32) → vec DeploymentInfo`              |
| `get_canister_status`            | update / controller or manager | `(opt principal) → CanisterStatusResult`                       |
| `deployment_logs`                | query / controller or manager  | `(text name, opt nat prev, opt nat take) → vec DeploymentInfo` |

`StateInfo` returns name, roles, top-up settings, latest version summaries (with truncation flags), entity counts, governance principal, and low-memory indicators.

`get_canister_status(null)` inspects the management canister itself; passing a target principal requires that target to be registered in `deployed_list`. This update call queries the IC management canister to fetch live execution status, controllers, settings, cycles balance, module hash, memory usage, and query statistics.

`get_deployed_canisters_info` returns registered deployment summaries with `args` and `args_hash` omitted; it reflects recorded state rather than live subnet probes. Legacy methods exceeding 1000 items reject calls and require switching to v2 pagination.

`deployment_logs` paginates in descending order over `(name, log_id)` keys. `prev` serves as an exclusive cursor, and `take` defaults to 10 (max 100). The `log_id` of the last record can be passed as `prev` for subsequent pages.

### 9.2 Batch Calls

`admin_batch_call(vec principal canisters, text method, opt blob args) → Result<vec blob>`:

- Passing an empty canister list targets **all registered canisters**; non-empty lists must contain only registered canisters.
- Invocations execute sequentially ordered by principal, sending identical method names and raw arguments.
- Returns raw Candid response bytes per target. Application errors returned within target response payloads are treated as successful replies by the management canister.
- Limits: up to 100 targets, arguments up to 256 KiB, reply up to 64 KiB per target, and aggregated responses up to ~1.5 MB.
- `admin_batch_call_v2` returns structured results `{ canister; reply; error }`. The legacy endpoint aborts on first failure and returns target failure details; prior side effects are not rolled back. Non-idempotent batch calls should not be blindly retried.

### 9.3 Cycles Top-Up

`admin_batch_topup() → Result<nat>` is manually triggered by controllers or managers, returning cumulative cycles transferred. `admin_batch_topup_v2` returns per-canister results; deployments exceeding 100 canisters should use `admin_batch_topup_page(cursor, take)`.

- Disabled when `topup_threshold` or `topup_amount` is 0; fails if no canisters are deployed.
- Scans `deployed_list` in concurrent batches of up to 7 canisters. If a target balance is **less than or equal to `topup_threshold`**, a transfer of `topup_amount` is dispatched.
- The canister inspects page balances and verifies `liquid_balance >= threshold + amount * targets_to_refill` before dispatching transfers.
- Cycles are debited from the management canister balance. Available or reserved pool canisters are not evaluated.
- A global top-up lock prevents reentrancy. Each canister reports status independently.

## 10. Client Integration Examples

### 10.1 TypeScript: Chunked Upload

The following helper uploads artifacts in 1 MiB slices using `@icp-sdk/core/agent`. The actor must be authenticated with controller, manager, or committer privileges.

```typescript
import { createHash } from 'node:crypto';
import type { _SERVICE } from '../declarations/ic_wasm_canister/ic_wasm_canister.did';

function unwrap<T>(result: { Ok: T } | { Err: string }): T {
  if ('Err' in result) throw new Error(result.Err);
  return result.Ok;
}

const sha256 = (bytes: Uint8Array): Uint8Array =>
  new Uint8Array(createHash('sha256').update(bytes).digest());

export async function publish(
  actor: _SERVICE,
  name: string,
  artifact: Uint8Array,
  gzip = false,
) {
  if (artifact.length === 0 || artifact.length > 64 * 1024 * 1024) {
    throw new Error('artifact must be between 1 byte and 64 MiB');
  }

  const hashes: Uint8Array[] = [];
  for (let offset = 0; offset < artifact.length; offset += 1024 * 1024) {
    const chunk = artifact.slice(offset, offset + 1024 * 1024);
    hashes.push(new Uint8Array(unwrap(await actor.admin_add_wasm_chunk(chunk))));
  }

  const expected = sha256(artifact);
  const stored = unwrap(await actor.admin_commit_wasm_chunks({
    name,
    description: 'Published by integration client',
    encoding: [gzip ? { Gzip: null } : { Raw: null }],
    chunk_hashes: hashes,
    artifact_hash: expected,
  }, []));

  return new Uint8Array(stored);
}
```

If a commit response is lost, query the artifact hash before retrying; staged chunks are cleared upon successful commit.

Actor Connection Pattern:

```typescript
import { Actor, HttpAgent, type Identity } from '@icp-sdk/core/agent';
import { idlFactory } from '../declarations/ic_wasm_canister/ic_wasm_canister.did.js';
import type { _SERVICE } from '../declarations/ic_wasm_canister/ic_wasm_canister.did';

export async function connect(
  host: string, canisterId: string, identity: Identity, localReplica = false,
) {
  const agent = await HttpAgent.create({ host, identity });
  if (localReplica) await agent.fetchRootKey(); // Local replica only
  return Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
}
```

### 10.2 TypeScript: Reservation and Installation

Prerequisites: Governance has published the module, approved the template, and refilled the pool. The actor must hold the provisioner role. `requestId`, `approvedTemplateHash`, and `provisionSpecHash` must be persisted by the application.

```typescript
import type { _SERVICE } from '../declarations/ic_wasm_canister/ic_wasm_canister.did';

const sameBytes = (a: Uint8Array | number[], b: Uint8Array | number[]) =>
  a.length === b.length && Array.from(a).every((value, i) => value === b[i]);

export async function provision(
  actor: _SERVICE,
  templateId: string,
  approvedTemplateHash: Uint8Array,
  requestId: Uint8Array,
  provisionSpecHash: Uint8Array,
  initArgs: Uint8Array,
) {
  const info = unwrap(await actor.get_provision_template(templateId));
  if (!sameBytes(info.hash, approvedTemplateHash)) {
    throw new Error('template hash mismatch');
  }

  const expiresAt = BigInt(Date.now() + 10 * 60 * 1000);
  const reservation = unwrap(await actor.reserve_canister({
    request_id: requestId,
    provision_template_id: templateId,
    provision_template_hash: approvedTemplateHash,
    expires_at: expiresAt,
  }));

  // Persist reservation before calling ensure_install.
  const receipt = unwrap(await actor.ensure_install({
    request_id: requestId,
    canister: reservation.canister,
    provision_template_id: templateId,
    provision_template_hash: approvedTemplateHash,
    expected_module_hash: info.template.expected_module_hash,
    init_args: initArgs,
    init_args_hash: sha256(initArgs),
    provision_spec_hash: provisionSpecHash,
    expires_at: expiresAt,
  }));

  if (!('Installed' in receipt.stage) || receipt.module_hash.length !== 1 ||
      !sameBytes(receipt.module_hash[0], info.template.expected_module_hash)) {
    throw new Error('installation was not confirmed');
  }

  return receipt;
}
```

For canisters with no init arguments, `initArgs` should be `Uint8Array.from([0x44, 0x49, 0x44, 0x4c, 0, 0])`. For canisters taking arguments, serialize using target Candid definitions; do not compute hashes over JSON or Candid text strings.

### 10.3 Rust: Computing Template Hashes Before Approval

The `ic_cose_types::types::wasm` crate exports template structures and hashing methods:

```rust
use candid::Principal;
use ic_cose_types::types::wasm::{ProvisionSettings, ProvisionTemplate, WasmEncoding};

pub fn template(
    manager: Principal,
    governance: Principal,
    artifact_hash: [u8; 32],
    module_hash: [u8; 32],
) -> Result<ProvisionTemplate, String> {
    let template = ProvisionTemplate {
        id: "demo_v1".into(),
        wasm_name: "demo".into(),
        artifact_hash: artifact_hash.into(),
        expected_module_hash: module_hash.into(),
        encoding: WasmEncoding::Raw,
        settings: ProvisionSettings {
            controllers: vec![manager, governance],
            ..Default::default()
        },
        subnet: None,
        initial_cycles: 2_000_000_000_000,
        max_init_args_bytes: 262_144,
        pool_size: 2,
    };
    template.validate()?;
    let _approved_hash = template.hash()?; // Persist to governance / audit record
    Ok(template)
}
```

Here `manager` is the WASM manager canister ID and `governance` is a separate governance canister principal; passing identical principals is rejected.

## 11. Governance Validation and Canister Upgrades

### 11.1 Validation Methods

All `validate_admin_*` endpoints are controller/governance updates that accept the same parameters as their execution counterparts and return human-readable summaries without applying changes. Validation success does not guarantee future execution if state mutates in the interim.

| Validation Endpoint                                                      | Verification Scope                                                     |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| `validate_admin_add_managers` / `validate_admin_remove_managers`         | Non-empty, non-anonymous principal sets                                |
| `validate_admin_add_committers` / `validate_admin_remove_committers`     | Non-empty, non-anonymous principal sets                                |
| `validate_admin_add_provisioners` / `validate_admin_remove_provisioners` | Non-empty, non-anonymous principal sets                                |
| `validate_admin_add_wasm`                                                | WASM/gzip structure, hash, deduplication, and latest CAS               |
| `validate_admin_create_canister` / `validate_admin_create_on`            | Latest module, controllers, and argument size (does not create target) |
| `validate_admin_deploy`                                                  | Target controllers, explicit prev_hash, latest module, and args size   |
| `validate_admin_batch_call`                                              | Targets, method name, and argument sizes (does not call targets)       |
| `validate_admin_batch_topup`                                             | Top-up configuration and presence of deployed canisters                |
| `validate_admin_update_canister_settings`                                | Target, mutex locks, and controller retention policy                   |
| `validate_admin_add_provision_template`                                  | Complete template, artifact/name/encoding/module hash, and controllers |
| `validate_admin_remove_provision_template`                               | Template references and pool status                                    |
| `validate_admin_reconcile_pool`                                          | Pool status and live target module/controllers                         |

Chunked upload, commit, clear, refill, and ensure methods do not have separate validate endpoints.

### 11.2 Upgrading the Manager Canister Itself

Deploying takes `Init`; upgrades accept `opt variant { Upgrade = record { ... } }` or `null`. `token_expiration` is a reserved field; passing any non-empty value is rejected to prevent silent configuration ignore.

```bash
RUSTFLAGS='--cfg=getrandom_backend="custom"' dfx deploy ic_wasm_canister --mode upgrade --argument '(opt variant { Upgrade = record {
  name = null;
  topup_threshold = opt 1_000_000_000_000;
  topup_amount = opt 5_000_000_000_000;
  governance_canister = null;
  clear_governance_canister = null;
  token_expiration = null;
}})'
```

Omitted fields retain previous values. Clearing governance requires `clear_governance_canister = opt true` while leaving `governance_canister` null. Top-up must either be zeroes or satisfy `amount > threshold > 0`.

Artifact metadata, chunks, version lineage, deployment indexes, log indexes, templates, pools, requests, tombstones, and staged chunks are stored in stable storage. Upgrades convert lingering `CreatePending` statuses to `CreateUnknown` and clear transient target/topup locks, allowing persistent request attempts to recover via real target inspection. An upgrade is not a reinstall.

`admin_handoff_canister` and `admin_forget_deployment` persist unmanaged markers; receipt retries cannot re-adopt unmanaged targets. Retaking control requires explicit controller re-adoption via `admin_deploy`, `admin_reconcile_deployment`, or `admin_reconcile_pool`.

Run PocketIC regression tests across upgrades: execute `make build-wasm`, export `POCKET_IC_BIN` to local PocketIC 16 server binary, and run `cargo test -p ic_wasm_canister --test canister_runtime -- --ignored`. Set `CANISTER_WASM_DIR` to test wasm64 release builds.

## 12. Error Handling and Integration Constraints

| Error / Message                                             | Cause and Remediation                                                       |
| ----------------------------------------------------------- | --------------------------------------------------------------------------- |
| `user is not a controller/manager/...`                      | Caller lacks required role for the invoked method                           |
| `wasm already exists`                                       | Artifact is globally deduplicated; inspect existing record                  |
| `force_prev_hash is stale`                                  | CAS latest pointer does not match current latest module; re-read and rebase |
| `no next version`                                           | No lineage transition exists for `(name, previous_module_hash)`             |
| `artifact hash ... does not match the declared ...`         | Chunk ordering, source bytes, or expected digest mismatch                   |
| `chunk ... not staged`                                      | Caller mismatch, chunks cleared/committed, or missing chunk                 |
| `provision template ... hash mismatch`                      | Pinned template hash does not match current template state                  |
| `no available canister in the pool ...`                     | Refill pool inventory; reservation does not create canisters                |
| `a pool create is already in flight`                        | Template status is `CreatePending`; await completion                        |
| `pool refill is circuit-broken ...`                         | Template status is `CreateUnknown`; requires `admin_reconcile_pool`         |
| `request epoch has expired` / `... more than 3600000ms ...` | Validate timestamp against system clock; query existing receipt             |
| `request id already bound ...`                              | Request ID was previously bound to another template, target, or arguments   |
| `init_args_hash does not match init_args`                   | Argument digest does not match uploaded Candid bytes                        |
| `canister controllers no longer match the template`         | Target controllers have drifted from template configuration                 |
| `prev module hash mismatch ...`                             | Target running module does not match `expected_prev_module_hash`            |
| `installed module hash ... does not match the approved ...` | Target post-install hash does not match template                            |
| `canister is not empty and cannot be released`              | Cannot return initialized canister to pool; query target status             |
| `an install is in flight for this request`                  | Status is `InstallPending`; await recovery before releasing                 |
| `canister topup is disabled` / `no canister deployed`       | Top-up values are 0 or no deployed canisters exist                          |
| `balance ... is less than threshold ...`                    | Management canister balance insufficient for batch top-up                   |

The interface does not return numeric error codes; avoid relying on strict string matching for critical business logic.

Integration constraints:
- Request idempotency recovers bindings across lost responses; it does not substitute for application-level payment authorization or initialization validation.
- Target controllers and state may be altered out-of-band by external controllers; queries and cached receipts do not actively poll target subnets.
- Pagination endpoints are provided for large artifacts, latest listings, pools, templates, and deployed canisters; compatibility methods reject calls exceeding 1000 items.
- Successful requests can be compacted into request-id tombstones after 30 days; deployment logs are retained permanently.
- When low memory triggers, creation and publishing endpoints reject calls; release, cleanup, and administrative recovery endpoints remain operational.
- Direct publishing, chunk commits, and template approvals do not guarantee target deployment success; verify ensure receipts and application-level health endpoints.

### Bounded request maintenance

`list_expired_reservations_page(prev, scan_limit)` and `admin_archive_completed_requests_page(before_ms, prev, scan_limit)` return `{ items; next_cursor }`. Each call scans at most 1000 records, including non-matches. Continue until next_cursor is empty, even if items is empty; an archive page returns the archived request IDs. The 30-day retention rule is unchanged. Legacy scan endpoints require the paginated methods above 1000 requests.

Run `make build-did` to extract interfaces and regenerate both canonical and example bindings with the maintained actor factory. Actor creation preserves a supplied agent's root key; local development must explicitly await `agent.fetchRootKey()` first.


### Storage cycle measurements

The ignored `storage_operations_report_cycle_costs` test reports cycles for 256 KiB / 1 MiB setting creation, update and deletion, and single-member ACL changes at 100 / 3999 members. Run it with `POCKET_IC_BIN=/path/to/pocket-ic-16 cargo test -p ic_wasm_canister --test canister_runtime storage_operations_report_cycle_costs -- --ignored --nocapture`. Set `CANISTER_WASM_DIR` to a separately built baseline to compare the same workload.

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT License](../../LICENSE-MIT) at your option.
