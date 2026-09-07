import type { Principal } from '@icp-sdk/core/principal';
import type { ActorMethod } from '@icp-sdk/core/agent';
import type { IDL } from '@icp-sdk/core/candid';

export interface AddWasmInput {
  /**
   * Defaults to [`WasmEncoding::Raw`] when omitted.
   */
  'encoding' : [] | [WasmEncoding],
  'name' : string,
  'wasm' : Uint8Array | number[],
  'description' : string,
}
export interface BatchCallResult {
  'error' : [] | [string],
  'canister' : Principal,
  'reply' : [] | [Uint8Array | number[]],
}
/**
 * # Canister Settings
 * 
 * For arguments of [`create_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-create_canister),
 * [`update_settings`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-update_settings) and
 * [`provisional_create_canister_with_cycles`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-provisional_create_canister_with_cycles).
 * 
 * All fields are `Option` types, allowing selective settings/updates.
 */
export interface CanisterSettings {
  /**
   * Indicates a length of time in seconds.
   * A canister is considered frozen whenever the IC estimates that the canister would be depleted of cycles
   * before `freezing_threshold` seconds pass, given the canister's current size and the IC's current cost for storage.
   * 
   * Must be a number between 0 and 2<sup>64</sup>-1, inclusively.
   * 
   * Default value: `2_592_000` (approximately 30 days).
   */
  'freezing_threshold' : [] | [bigint],
  /**
   * Indicates the threshold on the remaining wasm memory size of the canister in bytes.
   * 
   * If the remaining wasm memory size of the canister is below the threshold, execution of the "on low wasm memory" hook is scheduled.
   * 
   * Must be a number between 0 and 2<sup>64</sup>-1, inclusively.
   * 
   * Default value: `0` (i.e., the "on low wasm memory" hook is never scheduled).
   */
  'wasm_memory_threshold' : [] | [bigint],
  /**
   * A list of environment variables.
   * 
   * These variables are accessible to the canister during execution
   * and can be used to configure canister behavior without code changes.
   * Each key must be unique.
   * 
   * Default value: `null` (i.e., no environment variables provided).
   */
  'environment_variables' : [] | [Array<EnvironmentVariable>],
  /**
   * A list of at most 10 principals.
   * 
   * The principals in this list become the *controllers* of the canister.
   * 
   * Default value: A list containing only the caller of the `create_canister` call.
   */
  'controllers' : [] | [Array<Principal>],
  /**
   * Indicates the upper limit on [`CanisterStatusResult::reserved_cycles`] of the canister.
   * 
   * Must be a number between 0 and 2<sup>128</sup>-1, inclusively.
   * 
   * Default value: `5_000_000_000_000` (5 trillion cycles).
   */
  'reserved_cycles_limit' : [] | [bigint],
  /**
   * Defines who is allowed to read the canister's logs.
   * 
   * Default value: [`LogVisibility::Controllers`].
   */
  'log_visibility' : [] | [LogVisibility],
  /**
   * Indicates the upper limit on the memory used for canister logs (bytes).
   * 
   * Default value: `4096`.
   */
  'log_memory_limit' : [] | [bigint],
  /**
   * Indicates the upper limit on the WASM heap memory (bytes) consumption of the canister.
   * 
   * Must be a number between 0 and 2<sup>48</sup>-1 (i.e 256TB), inclusively.
   * 
   * Default value: `3_221_225_472` (3 GiB).
   */
  'wasm_memory_limit' : [] | [bigint],
  /**
   * Indicates how much memory (bytes) the canister is allowed to use in total.
   * 
   * If the IC cannot provide the requested allocation,
   * for example because it is oversubscribed, the call will be **rejected**.
   * 
   * If set to 0, then memory growth of the canister will be best-effort and subject to the available memory on the IC.
   * 
   * Must be a number between 0 and 2<sup>48</sup> (i.e 256TB), inclusively.
   * 
   * Default value: `0`
   */
  'memory_allocation' : [] | [bigint],
  /**
   * Indicates how much compute power should be guaranteed to this canister,
   * expressed as a percentage of the maximum compute power that a single canister can allocate.
   * 
   * If the IC cannot provide the requested allocation,
   * for example because it is oversubscribed, the call will be **rejected**.
   * 
   * Must be a number between 0 and 100, inclusively.
   * 
   * Default value: `0`
   */
  'compute_allocation' : [] | [bigint],
}
/**
 * # Canister Status Result
 * 
 * Result type of [`canister_status`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-canister_status).
 */
export interface CanisterStatusResult {
  /**
   * The detailed metrics on the memory consumption of the canister.
   */
  'memory_metrics' : MemoryMetrics,
  /**
   * Status of the canister.
   */
  'status' : CanisterStatusType,
  /**
   * The memory size taken by the canister.
   */
  'memory_size' : bigint,
  /**
   * Indicates whether a stopped canister is ready to be migrated to another subnet
   * (i.e., whether it has empty queues and flushed streams).
   */
  'ready_for_migration' : boolean,
  /**
   * The canister version.
   */
  'version' : bigint,
  /**
   * The cycle balance of the canister.
   */
  'cycles' : bigint,
  /**
   * Canister settings in effect.
   */
  'settings' : DefiniteCanisterSettings,
  /**
   * Query statistics.
   */
  'query_stats' : QueryStats,
  /**
   * Amount of cycles burned per day.
   */
  'idle_cycles_burned_per_day' : bigint,
  /**
   * A SHA256 hash of the module installed on the canister. This is null if the canister is empty.
   */
  'module_hash' : [] | [Uint8Array | number[]],
  /**
   * The reserved cycles balance of the canister.
   * 
   * These are cycles that are reserved by the resource reservation mechanism on storage allocation.
   * See also the [`CanisterSettings::reserved_cycles_limit`] parameter in canister settings.
   */
  'reserved_cycles' : bigint,
}
/**
 * # Canister Status Type
 * 
 * Status of a canister.
 * 
 * See [`CanisterStatusResult::status`].
 */
export type CanisterStatusType = {
    /**
     * The canister is stopped.
     */
    'stopped' : null
  } |
  {
    /**
     * The canister is stopping.
     */
    'stopping' : null
  } |
  {
    /**
     * The canister is running.
     */
    'running' : null
  };
export type ChainArgs = { 'Upgrade' : UpgradeArgs } |
  { 'Init' : InitArgs };
/**
 * Assembles a wasm artifact from chunks staged with `admin_add_wasm_chunk`.
 * 
 * Lets a module larger than the 2 MiB ingress limit be published, which a
 * single `admin_add_wasm` call cannot do.
 */
export interface CommitWasmChunksInput {
  /**
   * Expected `SHA-256` of the assembled artifact.
   */
  'artifact_hash' : Uint8Array | number[],
  'encoding' : [] | [WasmEncoding],
  'name' : string,
  /**
   * Staged chunk hashes, in the order they concatenate.
   */
  'chunk_hashes' : Array<Uint8Array | number[]>,
  'description' : string,
}
/**
 * # Definite Canister Settings
 * 
 * Represents the actual settings in effect.
 * 
 * For return of [`canister_status`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-canister_status).
 */
export interface DefiniteCanisterSettings {
  /**
   * Time in seconds after which the canister is considered frozen.
   */
  'freezing_threshold' : bigint,
  /**
   * Threshold on the remaining wasm memory size of the canister in bytes.
   */
  'wasm_memory_threshold' : bigint,
  /**
   * A list of environment variables.
   */
  'environment_variables' : Array<EnvironmentVariable>,
  /**
   * Controllers of the canister.
   */
  'controllers' : Array<Principal>,
  /**
   * Upper limit on [`CanisterStatusResult::reserved_cycles`] of the canister.
   */
  'reserved_cycles_limit' : bigint,
  /**
   * Visibility of canister logs.
   */
  'log_visibility' : LogVisibility,
  /**
   * Upper limit on the memory used for canister logs (bytes).
   */
  'log_memory_limit' : bigint,
  /**
   * Upper limit on the WASM heap memory (bytes) consumption of the canister.
   */
  'wasm_memory_limit' : bigint,
  /**
   * Total memory (bytes) the canister is allowed to use.
   */
  'memory_allocation' : bigint,
  /**
   * Guaranteed compute allocation as a percentage of the maximum compute power that a single canister can allocate.
   */
  'compute_allocation' : bigint,
}
export interface DeployWasmInput {
  'args' : [] | [Uint8Array | number[]],
  'name' : string,
  'canister' : Principal,
}
export interface DeploymentInfo {
  'args_hash' : [] | [Uint8Array | number[]],
  'args_size' : bigint,
  'args' : [] | [Uint8Array | number[]],
  'name' : string,
  'prev_hash' : Uint8Array | number[],
  'log_id' : bigint,
  'error' : [] | [string],
  'deploy_at' : bigint,
  'canister' : Principal,
  'module_hash' : [] | [Uint8Array | number[]],
  'wasm_hash' : Uint8Array | number[],
}
/**
 * Upgrades an already deployed canister under an exact previous module hash.
 */
export interface DeploymentRequest {
  'request_id' : Uint8Array | number[],
  /**
   * `SHA-256(args)`.
   */
  'args_hash' : Uint8Array | number[],
  'artifact_hash' : Uint8Array | number[],
  'expected_module_hash' : Uint8Array | number[],
  /**
   * Compare-and-swap guard: the module hash the canister must currently run.
   */
  'expected_prev_module_hash' : Uint8Array | number[],
  'args' : Uint8Array | number[],
  'canister' : Principal,
  'expires_at' : bigint,
  'wasm_name' : string,
}
/**
 * # Environment Variable.
 */
export interface EnvironmentVariable {
  /**
   * Value of the environment variable.
   */
  'value' : string,
  /**
   * Name of the environment variable.
   */
  'name' : string,
}
export interface InitArgs {
  'governance_canister' : [] | [Principal],
  'name' : string,
  'topup_threshold' : bigint,
  'topup_amount' : bigint,
}
/**
 * Installs the template's module on the canister reserved for `request_id`.
 */
export interface InstallRequest {
  'request_id' : Uint8Array | number[],
  /**
   * Opaque binding computed by the caller over its own provisioning spec.
   * Recorded verbatim in the receipt so the caller can prove which spec was
   * installed; this canister never interprets it.
   */
  'provision_spec_hash' : Uint8Array | number[],
  /**
   * Module hash the caller committed to. Must equal the template's
   * `expected_module_hash`: an activation is paid for one exact hash, so
   * installing anything else would deliver something nobody bought.
   */
  'expected_module_hash' : Uint8Array | number[],
  'provision_template_hash' : Uint8Array | number[],
  'init_args' : Uint8Array | number[],
  'provision_template_id' : string,
  /**
   * Must equal the canister named by the reservation receipt.
   */
  'canister' : Principal,
  /**
   * `SHA-256(init_args)`.
   */
  'init_args_hash' : Uint8Array | number[],
  'expires_at' : bigint,
}
/**
 * # Log Visibility.
 */
export type LogVisibility = {
    /**
     * Controllers.
     */
    'controllers' : null
  } |
  {
    /**
     * Public.
     */
    'public' : null
  } |
  {
    /**
     * Allowed viewers.
     */
    'allowed_viewers' : Array<Principal>
  };
/**
 * # Memory Metrics
 * 
 * Memory metrics of a canister.
 * 
 * See [`CanisterStatusResult::memory_metrics`].
 */
export interface MemoryMetrics {
  /**
   * Represents the memory occupied by the Wasm binary that is currently installed on the canister.
   */
  'wasm_binary_size' : bigint,
  /**
   * Represents the memory used by the canister's log store.
   */
  'log_memory_store_size' : bigint,
  /**
   * Represents the memory used by the Wasm chunk store of the canister.
   */
  'wasm_chunk_store_size' : bigint,
  /**
   * Represents the memory used for storing the canister's history.
   */
  'canister_history_size' : bigint,
  /**
   * Represents the stable memory usage of the canister.
   */
  'stable_memory_size' : bigint,
  /**
   * Represents the memory consumed by all snapshots that belong to this canister.
   */
  'snapshots_size' : bigint,
  /**
   * Represents the Wasm memory usage of the canister, i.e. the heap memory used by the canister's WebAssembly code.
   */
  'wasm_memory_size' : bigint,
  /**
   * Represents the memory usage of the global variables that the canister is using.
   */
  'global_memory_size' : bigint,
  /**
   * Represents the memory used by custom sections defined by the canister.
   */
  'custom_sections_size' : bigint,
}
export interface PoolCanisterInfo {
  'request_id' : [] | [Uint8Array | number[]],
  'created_at' : bigint,
  'state' : PoolCanisterState,
  'canister' : Principal,
}
/**
 * State of one pre-created canister inside a template's pool.
 */
export type PoolCanisterState = {
    /**
     * Free to be claimed by a reservation.
     */
    'Available' : null
  } |
  {
    /**
     * Claimed by a request id, not installed yet.
     */
    'Reserved' : null
  } |
  {
    /**
     * Carries an installed module and never returns to the pool.
     */
    'Installed' : null
  };
/**
 * Whether a template's pool may currently create another canister.
 */
export type PoolStatus = {
    /**
     * A create returned an unknown outcome: a canister may exist without this
     * canister knowing its principal. Refill stays circuit-broken until
     * governance reconciles.
     */
    'CreateUnknown' : null
  } |
  {
    /**
     * No outstanding create; refill is allowed.
     */
    'Idle' : null
  } |
  {
    /**
     * A create call is in flight. At most one per template.
     */
    'CreatePending' : null
  };
/**
 * Queryable outcome of one `request_id`, durable across response loss.
 */
export interface ProvisionReceipt {
  'request_id' : Uint8Array | number[],
  'updated_at' : bigint,
  'args_hash' : [] | [Uint8Array | number[]],
  'artifact_hash' : Uint8Array | number[],
  'provision_spec_hash' : [] | [Uint8Array | number[]],
  'owner' : Principal,
  'provision_template_hash' : [] | [Uint8Array | number[]],
  'created_at' : bigint,
  'error' : [] | [string],
  'stage' : ProvisionStage,
  /**
   * Module hash the canister ran before an upgrade.
   */
  'prev_module_hash' : [] | [Uint8Array | number[]],
  /**
   * `None` for upgrades, which are not bound to a provisioning template.
   */
  'provision_template_id' : [] | [string],
  'canister' : Principal,
  /**
   * Module hash reported by the management canister after installation.
   */
  'module_hash' : [] | [Uint8Array | number[]],
  'expires_at' : bigint,
  'wasm_name' : string,
}
/**
 * Canister settings applied to every canister provisioned from a template.
 * 
 * Held immutably inside the template so a provisioner can never submit its own
 * controllers, allocations or limits.
 */
export interface ProvisionSettings {
  'freezing_threshold' : [] | [bigint],
  /**
   * Exactly [`PROVISION_CONTROLLERS`] principals: this canister and the
   * platform governance canister. The issuer never becomes a controller.
   */
  'controllers' : Array<Principal>,
  'reserved_cycles_limit' : [] | [bigint],
  'wasm_memory_limit' : [] | [bigint],
  'memory_allocation' : [] | [bigint],
  'compute_allocation' : [] | [bigint],
}
export type ProvisionStage = { 'Failed' : null } |
  { 'Reserved' : null } |
  { 'Released' : null } |
  { 'InstallPending' : null } |
  { 'Installed' : null };
/**
 * A governance-approved, immutable provisioning template.
 * 
 * A provisioner may only name an approved template by `id` and `hash`; every
 * other provisioning parameter is loaded from here, so approving a template is
 * the governance act that fixes which module, settings, controllers, subnet and
 * creation budget allocated to a provisioned canister.
 */
export interface ProvisionTemplate {
  'id' : string,
  /**
   * Total cycles attached to canister creation, including the subnet's
   * creation fee. The new canister receives the remainder.
   */
  'initial_cycles' : bigint,
  /**
   * Hash of the stored artifact bytes, as recorded by `add_wasm`.
   */
  'artifact_hash' : Uint8Array | number[],
  /**
   * Module hash the management canister must report after installation.
   */
  'expected_module_hash' : Uint8Array | number[],
  'encoding' : WasmEncoding,
  /**
   * How many `Available` canisters this template keeps pre-created.
   */
  'pool_size' : number,
  'settings' : ProvisionSettings,
  /**
   * Subnet to create pool canisters on; `None` uses the local subnet.
   */
  'subnet' : [] | [Principal],
  'max_init_args_bytes' : number,
  'wasm_name' : string,
}
export interface ProvisionTemplateInfo {
  'hash' : Uint8Array | number[],
  'installed' : number,
  'reserved' : number,
  'created_at' : bigint,
  'created_by' : Principal,
  'available' : number,
  'settings_hash' : Uint8Array | number[],
  'template' : ProvisionTemplate,
  'pool_status' : PoolStatus,
  'subnet_policy_hash' : Uint8Array | number[],
  /**
   * Release tombstones currently retained for this template.
   */
  'tombstones' : number,
}
/**
 * # Query Stats
 * 
 * Query statistics.
 * 
 * See [`CanisterStatusResult::query_stats`].
 */
export interface QueryStats {
  /**
   * Total number of payload bytes use for query call responses.
   */
  'response_payload_bytes_total' : bigint,
  /**
   * Total number of instructions executed by query calls.
   */
  'num_instructions_total' : bigint,
  /**
   * Total number of query calls.
   */
  'num_calls_total' : bigint,
  /**
   * Total number of payload bytes use for query call requests.
   */
  'request_payload_bytes_total' : bigint,
}
export interface ReleaseReceipt {
  'request_id' : Uint8Array | number[],
  'canister' : Principal,
  'released_at' : bigint,
}
export interface ReservationReceipt {
  'request_id' : Uint8Array | number[],
  /**
   * Creation budget committed by the template, inclusive of creation fee.
   */
  'initial_cycles' : bigint,
  'controllers' : Array<Principal>,
  'owner' : Principal,
  'provision_template_hash' : Uint8Array | number[],
  'provision_template_id' : string,
  'settings_hash' : Uint8Array | number[],
  'canister' : Principal,
  'reserved_at' : bigint,
  'subnet_policy_hash' : Uint8Array | number[],
  'expires_at' : bigint,
}
/**
 * Claims one pre-created canister for `request_id`.
 */
export interface ReserveRequest {
  'request_id' : Uint8Array | number[],
  'provision_template_hash' : Uint8Array | number[],
  'provision_template_id' : string,
  /**
   * Request epoch in milliseconds. Rejected once elapsed, so a request that
   * outlives its release tombstone can no longer be replayed.
   */
  'expires_at' : bigint,
}
export type Result = { 'Ok' : null } |
  { 'Err' : string };
export type Result_1 = { 'Ok' : ProvisionTemplateInfo } |
  { 'Err' : string };
export type Result_10 = { 'Ok' : ReleaseReceipt } |
  { 'Err' : string };
export type Result_11 = { 'Ok' : Array<DeploymentInfo> } |
  { 'Err' : string };
export type Result_12 = { 'Ok' : ProvisionReceipt } |
  { 'Err' : string };
export type Result_13 = { 'Ok' : CanisterStatusResult } |
  { 'Err' : string };
export type Result_14 = { 'Ok' : Array<Principal> } |
  { 'Err' : string };
export type Result_15 = { 'Ok' : WasmMetadata } |
  { 'Err' : string };
export type Result_16 = { 'Ok' : StateInfo } |
  { 'Err' : string };
export type Result_17 = { 'Ok' : WasmInfo } |
  { 'Err' : string };
export type Result_18 = { 'Ok' : Uint8Array | number[] } |
  { 'Err' : string };
export type Result_19 = { 'Ok' : Array<ProvisionReceipt> } |
  { 'Err' : string };
export type Result_2 = { 'Ok' : Uint8Array | number[] } |
  { 'Err' : string };
export type Result_20 = { 'Ok' : Array<[string, Uint8Array | number[]]> } |
  { 'Err' : string };
export type Result_21 = { 'Ok' : Array<PoolCanisterInfo> } |
  { 'Err' : string };
export type Result_22 = { 'Ok' : Array<ProvisionTemplateInfo> } |
  { 'Err' : string };
export type Result_23 = { 'Ok' : ReservationReceipt } |
  { 'Err' : string };
export type Result_24 = { 'Ok' : string } |
  { 'Err' : string };
export type Result_3 = { 'Ok' : bigint } |
  { 'Err' : string };
export type Result_4 = { 'Ok' : Array<Uint8Array | number[]> } |
  { 'Err' : string };
export type Result_5 = { 'Ok' : Array<BatchCallResult> } |
  { 'Err' : string };
export type Result_6 = { 'Ok' : bigint } |
  { 'Err' : string };
export type Result_7 = { 'Ok' : Array<TopupResult> } |
  { 'Err' : string };
export type Result_8 = { 'Ok' : Principal } |
  { 'Err' : string };
export type Result_9 = { 'Ok' : boolean } |
  { 'Err' : string };
export interface StateInfo {
  'provisioners' : Array<Principal>,
  'managers' : Array<Principal>,
  'governance_canister' : [] | [Principal],
  'name' : string,
  'low_wasm_memory' : boolean,
  'topup_threshold' : bigint,
  'latest_version_total' : bigint,
  'topup_amount' : bigint,
  'deployment_logs' : bigint,
  'deployed_total' : bigint,
  'wasm_total' : bigint,
  'latest_version_truncated' : boolean,
  'latest_version' : Array<[string, Uint8Array | number[]]>,
  'committers' : Array<Principal>,
}
export interface TopupResult {
  'deposited' : bigint,
  'balance_before' : [] | [bigint],
  'error' : [] | [string],
  'canister' : Principal,
}
/**
 * Argument type of [`update_settings`]
 * 
 * # Note
 * 
 * This type is a reduced version of [`ic_management_canister_types::UpdateSettingsArgs`].
 * 
 * The `sender_canister_version` field is removed as it is set automatically in [`update_settings`].
 */
export interface UpdateSettingsArgs {
  /**
   * Canister ID.
   */
  'canister_id' : Principal,
  /**
   * See [`CanisterSettings`].
   */
  'settings' : CanisterSettings,
}
export interface UpgradeArgs {
  'governance_canister' : [] | [Principal],
  'name' : [] | [string],
  'token_expiration' : [] | [bigint],
  'topup_threshold' : [] | [bigint],
  'topup_amount' : [] | [bigint],
  'clear_governance_canister' : [] | [boolean],
}
/**
 * How the stored wasm artifact bytes are encoded.
 * 
 * The distinction matters because `artifact_hash` covers the bytes this
 * canister stores and transfers, while `module_hash` covers what the management
 * canister reports as installed. For [`WasmEncoding::Gzip`] the two must never
 * be assumed equal.
 */
export type WasmEncoding = { 'Raw' : null } |
  { 'Gzip' : null };
export interface WasmInfo {
  /**
   * Encoding of `wasm`. For `Gzip`, `hash` is the artifact hash and must not
   * be assumed equal to the module hash reported once installed.
   */
  'encoding' : WasmEncoding,
  'hash' : Uint8Array | number[],
  'name' : string,
  'wasm' : Uint8Array | number[],
  'description' : string,
  'created_at' : bigint,
  'created_by' : Principal,
  /**
   * SHA-256 of the raw Wasm module after decoding `encoding`.
   */
  'module_hash' : Uint8Array | number[],
  'wasm_size' : bigint,
}
export interface WasmMetadata {
  'encoding' : WasmEncoding,
  'hash' : Uint8Array | number[],
  'name' : string,
  'description' : string,
  'created_at' : bigint,
  'created_by' : Principal,
  'module_hash' : Uint8Array | number[],
  'wasm_size' : bigint,
}
export interface _SERVICE {
  'admin_add_committers' : ActorMethod<[Array<Principal>], Result>,
  'admin_add_managers' : ActorMethod<[Array<Principal>], Result>,
  /**
   * Approves an immutable provisioning template.
   * 
   * This is the governance act that fixes which module, settings, controllers,
   * subnet and creation budget a provisioned canister gets: a provisioner can
   * afterwards only name the template by id and hash.
   */
  'admin_add_provision_template' : ActorMethod<[ProvisionTemplate], Result_1>,
  /**
   * Grants the least-privilege provisioning role.
   * 
   * A provisioner may only reserve, install and release canisters from approved
   * templates; it cannot manage roles, publish modules or deploy an arbitrary
   * wasm, so this can be granted to another canister without handing over the
   * repository.
   */
  'admin_add_provisioners' : ActorMethod<[Array<Principal>], Result>,
  'admin_add_wasm' : ActorMethod<
    [AddWasmInput, [] | [Uint8Array | number[]]],
    Result
  >,
  /**
   * Stages one chunk of a wasm artifact for the caller.
   * 
   * Publishing a module larger than the 2 MiB ingress limit is impossible in a
   * single `admin_add_wasm` call; chunks are staged here and assembled by
   * `admin_commit_wasm_chunks`.
   */
  'admin_add_wasm_chunk' : ActorMethod<[Uint8Array | number[]], Result_2>,
  /**
   * Compacts old successful request receipts into permanent request-id
   * tombstones. Callers should retain receipts externally before archiving.
   */
  'admin_archive_completed_requests' : ActorMethod<[bigint, number], Result_3>,
  'admin_batch_call' : ActorMethod<
    [Array<Principal>, string, [] | [Uint8Array | number[]]],
    Result_4
  >,
  'admin_batch_call_v2' : ActorMethod<
    [Array<Principal>, string, [] | [Uint8Array | number[]]],
    Result_5
  >,
  'admin_batch_topup' : ActorMethod<[], Result_6>,
  'admin_batch_topup_page' : ActorMethod<
    [[] | [Principal], [] | [number]],
    Result_7
  >,
  'admin_batch_topup_v2' : ActorMethod<[], Result_7>,
  'admin_clear_low_wasm_memory' : ActorMethod<[], Result>,
  /**
   * Drops the caller's staged chunks, e.g. after an abandoned upload.
   */
  'admin_clear_wasm_chunks' : ActorMethod<[], Result_3>,
  'admin_clear_wasm_chunks_for' : ActorMethod<[Principal], Result_3>,
  /**
   * Assembles the caller's staged chunks into one artifact and publishes it.
   */
  'admin_commit_wasm_chunks' : ActorMethod<
    [CommitWasmChunksInput, [] | [Uint8Array | number[]]],
    Result_2
  >,
  'admin_create_canister' : ActorMethod<
    [string, [] | [CanisterSettings], [] | [Uint8Array | number[]]],
    Result_8
  >,
  'admin_create_on' : ActorMethod<
    [Principal, string, [] | [CanisterSettings], [] | [Uint8Array | number[]]],
    Result_8
  >,
  'admin_deploy' : ActorMethod<
    [DeployWasmInput, [] | [Uint8Array | number[]]],
    Result
  >,
  'admin_forget_deployment' : ActorMethod<[Principal], Result_9>,
  /**
   * Explicitly transfers target control away from this canister and removes the
   * target from the managed deployment index after the settings call succeeds.
   */
  'admin_handoff_canister' : ActorMethod<[UpdateSettingsArgs], Result>,
  /**
   * Migrates one legacy monolithic artifact into the chunked stable layout.
   */
  'admin_migrate_legacy_wasm_artifact' : ActorMethod<
    [Uint8Array | number[]],
    Result_9
  >,
  /**
   * Incrementally builds the per-wasm deployment-log index for records written
   * by versions that only maintained the global stable log.
   */
  'admin_rebuild_log_index' : ActorMethod<[bigint, number], Result_3>,
  /**
   * Repairs the deployment index after a successful target install whose local
   * callback could not append its log. The target's live module hash is checked
   * against repository metadata before any record is written.
   */
  'admin_reconcile_deployment' : ActorMethod<
    [Principal, string, Uint8Array | number[]],
    Result
  >,
  /**
   * Clears a `CreateUnknown` breaker after governance has looked for the canister
   * a lost create may have produced.
   * 
   * `found` adopts that canister into the pool; `None` records the create as lost.
   */
  'admin_reconcile_pool' : ActorMethod<[string, [] | [Principal]], Result>,
  /**
   * Creates one more canister for a template's pool.
   * 
   * Deliberately separate from any paid flow: creation is the one step whose
   * response loss cannot be recovered, so it may only ever waste an unpaid pool
   * canister. An unknown outcome circuit-breaks further refills.
   */
  'admin_refill_pool' : ActorMethod<[string], Result_8>,
  'admin_release_expired_reservation' : ActorMethod<
    [Uint8Array | number[]],
    Result_10
  >,
  'admin_remove_committers' : ActorMethod<[Array<Principal>], Result>,
  'admin_remove_managers' : ActorMethod<[Array<Principal>], Result>,
  'admin_remove_provision_template' : ActorMethod<[string], Result>,
  'admin_remove_provisioners' : ActorMethod<[Array<Principal>], Result>,
  'admin_remove_wasm' : ActorMethod<[Uint8Array | number[]], Result>,
  'admin_update_canister_settings' : ActorMethod<[UpdateSettingsArgs], Result>,
  'deployment_logs' : ActorMethod<
    [string, [] | [bigint], [] | [bigint]],
    Result_11
  >,
  /**
   * Upgrades an already deployed canister to an exact module.
   * 
   * Restricted to canisters this canister deployed, and to the wasm name they
   * already run: a provisioner must not be able to push an arbitrary module onto
   * an arbitrary canister. Compare-and-swaps on `expected_prev_module_hash`, so a
   * stale request can never overwrite a module the caller did not expect to be
   * running, and the result is verified against `expected_module_hash`.
   */
  'ensure_deployment' : ActorMethod<[DeploymentRequest], Result_12>,
  /**
   * Installs the template's approved module onto the reserved canister.
   * 
   * Idempotent by `request_id`: a retry after a lost response converges on the
   * already-installed module instead of failing, and the module hash reported by
   * the management canister is verified against the hash the template pins.
   */
  'ensure_install' : ActorMethod<[InstallRequest], Result_12>,
  'get_canister_status' : ActorMethod<[[] | [Principal]], Result_13>,
  'get_deployed_canisters' : ActorMethod<[], Result_14>,
  'get_deployed_canisters_info' : ActorMethod<[], Result_11>,
  'get_deployed_canisters_info_v2' : ActorMethod<
    [[] | [Principal], [] | [number]],
    Result_11
  >,
  'get_deployed_canisters_v2' : ActorMethod<
    [[] | [Principal], [] | [number]],
    Result_14
  >,
  'get_next_wasm_version' : ActorMethod<
    [string, Uint8Array | number[]],
    Result_15
  >,
  /**
   * The durable outcome of a `request_id`, readable after any lost response.
   */
  'get_provision_receipt' : ActorMethod<[Uint8Array | number[]], Result_12>,
  /**
   * The approved template a provisioner must name by id and hash.
   */
  'get_provision_template' : ActorMethod<[string], Result_1>,
  'get_state' : ActorMethod<[], Result_16>,
  'get_wasm' : ActorMethod<[Uint8Array | number[]], Result_17>,
  'get_wasm_chunk' : ActorMethod<
    [Uint8Array | number[], bigint, number],
    Result_18
  >,
  'get_wasm_metadata' : ActorMethod<[Uint8Array | number[]], Result_15>,
  'list_expired_reservations' : ActorMethod<
    [[] | [Uint8Array | number[]], [] | [number]],
    Result_19
  >,
  'list_latest_wasm_versions' : ActorMethod<
    [[] | [string], [] | [number]],
    Result_20
  >,
  'list_legacy_wasm_artifacts' : ActorMethod<
    [[] | [Uint8Array | number[]], [] | [number]],
    Result_4
  >,
  /**
   * Recorded pool inventory of a template.
   * 
   * Governance watches this against the reservation churn: a pool that keeps
   * draining is the signal to rate-limit callers, not to raise the pool size.
   */
  'list_provision_pool' : ActorMethod<[string], Result_21>,
  'list_provision_pool_v2' : ActorMethod<
    [string, [] | [Principal], [] | [number]],
    Result_21
  >,
  'list_provision_templates' : ActorMethod<[], Result_22>,
  'list_provision_templates_v2' : ActorMethod<
    [[] | [string], [] | [number]],
    Result_22
  >,
  /**
   * Resolves an interrupted install or upgrade, including after its request
   * epoch expires. Only probes the target: this never installs or upgrades code.
   * An empty reserved target becomes Failed and may then be released normally.
   */
  'reconcile_provision_request' : ActorMethod<
    [Uint8Array | number[]],
    Result_12
  >,
  /**
   * Returns a reserved canister to the pool.
   * 
   * Only valid while the reservation never installed anything; the canister must
   * still be empty and still carry the template's controllers, so a released
   * canister cannot come back polluted.
   */
  'release_reservation' : ActorMethod<
    [Uint8Array | number[], Principal],
    Result_10
  >,
  /**
   * Claims one pre-created canister for `request_id`.
   * 
   * Idempotent and fully synchronous: the `request_id -> canister` binding is
   * committed together with the reply, so a caller that never sees the response
   * recovers the same canister by replaying the call or reading the receipt. It
   * never creates a canister, which is why a lost management-canister create can
   * only ever waste an unpaid pool canister.
   */
  'reserve_canister' : ActorMethod<[ReserveRequest], Result_23>,
  'validate_admin_add_committers' : ActorMethod<[Array<Principal>], Result_24>,
  'validate_admin_add_managers' : ActorMethod<[Array<Principal>], Result_24>,
  'validate_admin_add_provision_template' : ActorMethod<
    [ProvisionTemplate],
    Result_24
  >,
  'validate_admin_add_provisioners' : ActorMethod<
    [Array<Principal>],
    Result_24
  >,
  'validate_admin_add_wasm' : ActorMethod<
    [AddWasmInput, [] | [Uint8Array | number[]]],
    Result_24
  >,
  'validate_admin_batch_call' : ActorMethod<
    [Array<Principal>, string, [] | [Uint8Array | number[]]],
    Result_24
  >,
  'validate_admin_batch_topup' : ActorMethod<[], Result_24>,
  'validate_admin_create_canister' : ActorMethod<
    [string, [] | [CanisterSettings], [] | [Uint8Array | number[]]],
    Result_24
  >,
  'validate_admin_create_on' : ActorMethod<
    [Principal, string, [] | [CanisterSettings], [] | [Uint8Array | number[]]],
    Result_24
  >,
  'validate_admin_deploy' : ActorMethod<
    [DeployWasmInput, [] | [Uint8Array | number[]]],
    Result_24
  >,
  'validate_admin_reconcile_pool' : ActorMethod<
    [string, [] | [Principal]],
    Result_24
  >,
  'validate_admin_remove_committers' : ActorMethod<
    [Array<Principal>],
    Result_24
  >,
  'validate_admin_remove_managers' : ActorMethod<[Array<Principal>], Result_24>,
  'validate_admin_remove_provision_template' : ActorMethod<[string], Result_24>,
  'validate_admin_remove_provisioners' : ActorMethod<
    [Array<Principal>],
    Result_24
  >,
  'validate_admin_remove_wasm' : ActorMethod<
    [Uint8Array | number[]],
    Result_24
  >,
  'validate_admin_update_canister_settings' : ActorMethod<
    [UpdateSettingsArgs],
    Result_24
  >,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
