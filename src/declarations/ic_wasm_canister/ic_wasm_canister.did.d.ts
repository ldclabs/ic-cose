import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface AddWasmInput {
  'name' : string,
  'wasm' : Uint8Array | number[],
  'description' : string,
}
export interface CanisterSettings {
  'freezing_threshold' : [] | [bigint],
  'controllers' : [] | [Array<Principal>],
  'reserved_cycles_limit' : [] | [bigint],
  'log_visibility' : [] | [LogVisibility],
  'wasm_memory_limit' : [] | [bigint],
  'memory_allocation' : [] | [bigint],
  'compute_allocation' : [] | [bigint],
}
export interface CanisterStatusResponse {
  'status' : CanisterStatusType,
  'memory_size' : bigint,
  'cycles' : bigint,
  'settings' : DefiniteCanisterSettings,
  'query_stats' : QueryStats,
  'idle_cycles_burned_per_day' : bigint,
  'module_hash' : [] | [Uint8Array | number[]],
  'reserved_cycles' : bigint,
}
export type CanisterStatusType = { 'stopped' : null } |
  { 'stopping' : null } |
  { 'running' : null };
export type ChainArgs = { 'Upgrade' : UpgradeArgs } |
  { 'Init' : InitArgs };
export interface DefiniteCanisterSettings {
  'freezing_threshold' : bigint,
  'controllers' : Array<Principal>,
  'reserved_cycles_limit' : bigint,
  'log_visibility' : LogVisibility,
  'wasm_memory_limit' : bigint,
  'memory_allocation' : bigint,
  'compute_allocation' : bigint,
}
export interface DeployWasmInput {
  'args' : [] | [Uint8Array | number[]],
  'name' : string,
  'canister' : Principal,
}
export interface DeploymentInfo {
  'args' : [] | [Uint8Array | number[]],
  'name' : string,
  'prev_hash' : Uint8Array | number[],
  'error' : [] | [string],
  'deploy_at' : bigint,
  'canister' : Principal,
  'wasm_hash' : Uint8Array | number[],
}
export interface InitArgs {
  'governance_canister' : [] | [Principal],
  'name' : string,
  'topup_threshold' : bigint,
  'topup_amount' : bigint,
}
export type LogVisibility = { 'controllers' : null } |
  { 'public' : null } |
  { 'allowed_viewers' : Array<Principal> };
export interface QueryStats {
  'response_payload_bytes_total' : bigint,
  'num_instructions_total' : bigint,
  'num_calls_total' : bigint,
  'request_payload_bytes_total' : bigint,
}
export type Result = { 'Ok' : null } |
  { 'Err' : string };
export type Result_1 = { 'Ok' : Array<Uint8Array | number[]> } |
  { 'Err' : string };
export type Result_2 = { 'Ok' : bigint } |
  { 'Err' : string };
export type Result_3 = { 'Ok' : Principal } |
  { 'Err' : string };
export type Result_4 = { 'Ok' : Array<DeploymentInfo> } |
  { 'Err' : string };
export type Result_5 = { 'Ok' : CanisterStatusResponse } |
  { 'Err' : string };
export type Result_6 = { 'Ok' : Array<Principal> } |
  { 'Err' : string };
export type Result_7 = { 'Ok' : StateInfo } |
  { 'Err' : string };
export type Result_8 = { 'Ok' : WasmInfo } |
  { 'Err' : string };
export type Result_9 = { 'Ok' : string } |
  { 'Err' : string };
export interface StateInfo {
  'managers' : Array<Principal>,
  'governance_canister' : [] | [Principal],
  'name' : string,
  'deployment_logs' : bigint,
  'deployed_total' : bigint,
  'wasm_total' : bigint,
  'latest_version' : Array<[string, Uint8Array | number[]]>,
  'committers' : Array<Principal>,
}
export interface UpdateSettingsArgument {
  'canister_id' : Principal,
  'settings' : CanisterSettings,
}
export interface UpgradeArgs {
  'governance_canister' : [] | [Principal],
  'name' : [] | [string],
  'token_expiration' : [] | [bigint],
  'topup_threshold' : [] | [bigint],
  'topup_amount' : [] | [bigint],
}
export interface WasmInfo {
  'hash' : Uint8Array | number[],
  'name' : string,
  'wasm' : Uint8Array | number[],
  'description' : string,
  'created_at' : bigint,
  'created_by' : Principal,
}
export interface _SERVICE {
  'admin_add_committers' : ActorMethod<[Array<Principal>], Result>,
  'admin_add_managers' : ActorMethod<[Array<Principal>], Result>,
  'admin_add_wasm' : ActorMethod<
    [AddWasmInput, [] | [Uint8Array | number[]]],
    Result
  >,
  'admin_batch_call' : ActorMethod<
    [Array<Principal>, string, [] | [Uint8Array | number[]]],
    Result_1
  >,
  'admin_batch_topup' : ActorMethod<[], Result_2>,
  'admin_create_canister' : ActorMethod<
    [string, [] | [CanisterSettings], [] | [Uint8Array | number[]]],
    Result_3
  >,
  'admin_create_on' : ActorMethod<
    [Principal, string, [] | [CanisterSettings], [] | [Uint8Array | number[]]],
    Result_3
  >,
  'admin_deploy' : ActorMethod<
    [DeployWasmInput, [] | [Uint8Array | number[]]],
    Result
  >,
  'admin_remove_committers' : ActorMethod<[Array<Principal>], Result>,
  'admin_remove_managers' : ActorMethod<[Array<Principal>], Result>,
  'admin_update_canister_settings' : ActorMethod<
    [UpdateSettingsArgument],
    Result
  >,
  'deployment_logs' : ActorMethod<
    [string, [] | [bigint], [] | [bigint]],
    Result_4
  >,
  'get_canister_status' : ActorMethod<[[] | [Principal]], Result_5>,
  'get_deployed_canisters' : ActorMethod<[], Result_6>,
  'get_deployed_canisters_info' : ActorMethod<[], Result_4>,
  'get_state' : ActorMethod<[], Result_7>,
  'get_wasm' : ActorMethod<[Uint8Array | number[]], Result_8>,
  'validate_admin_add_committers' : ActorMethod<[Array<Principal>], Result_9>,
  'validate_admin_add_managers' : ActorMethod<[Array<Principal>], Result_9>,
  'validate_admin_add_wasm' : ActorMethod<
    [AddWasmInput, [] | [Uint8Array | number[]]],
    Result_9
  >,
  'validate_admin_batch_call' : ActorMethod<
    [Array<Principal>, string, [] | [Uint8Array | number[]]],
    Result_9
  >,
  'validate_admin_batch_topup' : ActorMethod<[], Result_9>,
  'validate_admin_create_canister' : ActorMethod<
    [string, [] | [CanisterSettings], [] | [Uint8Array | number[]]],
    Result_9
  >,
  'validate_admin_create_on' : ActorMethod<
    [Principal, string, [] | [CanisterSettings], [] | [Uint8Array | number[]]],
    Result_9
  >,
  'validate_admin_deploy' : ActorMethod<
    [DeployWasmInput, [] | [Uint8Array | number[]]],
    Result_9
  >,
  'validate_admin_remove_committers' : ActorMethod<
    [Array<Principal>],
    Result_9
  >,
  'validate_admin_remove_managers' : ActorMethod<[Array<Principal>], Result_9>,
  'validate_admin_update_canister_settings' : ActorMethod<
    [UpdateSettingsArgument],
    Result_9
  >,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
