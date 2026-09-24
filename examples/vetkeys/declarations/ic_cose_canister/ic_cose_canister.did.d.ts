import type { Principal } from '@icp-sdk/core/principal';
import type { ActorMethod } from '@icp-sdk/core/agent';
import type { IDL } from '@icp-sdk/core/candid';

export interface CreateNamespaceInput {
  'session_expires_in_ms' : [] | [bigint],
  'managers' : Array<Principal>,
  'desc' : [] | [string],
  'name' : string,
  'max_payload_size' : [] | [bigint],
  'auditors' : Array<Principal>,
  'users' : Array<Principal>,
  'visibility' : number,
}
export interface CreateSettingInput {
  'dek' : [] | [Uint8Array | number[]],
  'status' : [] | [number],
  'desc' : [] | [string],
  'tags' : [] | [Array<[string, string]>],
  'payload' : [] | [Uint8Array | number[]],
}
export interface CreateSettingOutput {
  'updated_at' : bigint,
  'created_at' : bigint,
  'version' : number,
}
/**
 * A delegation from one key to another.
 *
 * If key A signs a delegation containing key B, then key B may be used to
 * authenticate as key A's corresponding principal(s).
 */
export interface Delegation {
  /**
   * The kinds of requests this delegation permits.
   */
  'permissions' : [] | [DelegationPermissions],
  /**
   * The delegated-to key.
   */
  'pubkey' : Uint8Array | number[],
  /**
   * If present, this delegation only applies to requests sent to one of these canisters.
   */
  'targets' : [] | [Array<Principal>],
  /**
   * A nanosecond timestamp after which this delegation is no longer valid.
   */
  'expiration' : bigint,
}
/**
 * The kinds of requests a [`Delegation`] permits.
 */
export type DelegationPermissions = {
    /**
     * All request types are permitted.
     */
    'all' : null
  } |
  {
    /**
     * Only query calls and `read_state` requests are permitted.
     */
    'queries' : null
  };
export interface ECDHInput {
  'public_key' : Uint8Array | number[],
  'nonce' : Uint8Array | number[],
}
export interface ECDHOutput {
  'public_key' : Uint8Array | number[],
  'payload' : Uint8Array | number[],
}
export interface InitArgs {
  'freezing_threshold' : bigint,
  'ecdsa_key_name' : string,
  'governance_canister' : [] | [Principal],
  'name' : string,
  'vetkd_context_version' : [] | [number],
  'schnorr_key_name' : string,
  'allowed_apis' : Array<string>,
  'subnet_size' : bigint,
  'vetkd_key_name' : string,
}
export type InstallArgs = { 'Upgrade' : UpgradeArgs } |
  { 'Init' : InitArgs };
export interface NamespaceDelegatorsInput {
  'ns' : string,
  'delegators' : Array<Principal>,
  'name' : string,
}
export interface NamespaceInfo {
  'user_count' : number,
  'status' : number,
  'updated_at' : bigint,
  'session_expires_in_ms' : bigint,
  'manager_count' : number,
  'managers' : Array<Principal>,
  'payload_bytes_total' : bigint,
  'desc' : string,
  'name' : string,
  'max_payload_size' : bigint,
  'created_at' : bigint,
  'auditors' : Array<Principal>,
  'fixed_id_names' : Array<[string, Array<Principal>]>,
  'users' : Array<Principal>,
  'fixed_delegator_count' : number,
  'visibility' : number,
  'gas_balance' : bigint,
  'auditor_count' : number,
}
export interface PublicKeyInput {
  'ns' : string,
  'derivation_path' : Array<Uint8Array | number[]>,
}
export interface PublicKeyOutput {
  'public_key' : Uint8Array | number[],
  'chain_code' : Uint8Array | number[],
}
export type Result = { 'Ok' : null } |
  { 'Err' : string };
export type Result_1 = { 'Ok' : NamespaceInfo } |
  { 'Err' : string };
export type Result_10 = { 'Ok' : Array<string> } |
  { 'Err' : string };
export type Result_11 = { 'Ok' : Array<Principal> } |
  { 'Err' : string };
export type Result_12 = { 'Ok' : Array<[Principal, Uint8Array | number[]]> } |
  { 'Err' : string };
export type Result_13 = { 'Ok' : bigint } |
  { 'Err' : string };
export type Result_14 = { 'Ok' : SignInResponse } |
  { 'Err' : string };
export type Result_15 = { 'Ok' : bigint } |
  { 'Err' : string };
export type Result_16 = { 'Ok' : CreateSettingOutput } |
  { 'Err' : string };
export type Result_17 = { 'Ok' : SettingInfo } |
  { 'Err' : string };
export type Result_18 = { 'Ok' : SettingArchivedPayload } |
  { 'Err' : string };
export type Result_19 = { 'Ok' : StateInfo } |
  { 'Err' : string };
export type Result_2 = { 'Ok' : Array<NamespaceInfo> } |
  { 'Err' : string };
export type Result_20 = { 'Ok' : string } |
  { 'Err' : string };
export type Result_3 = { 'Ok' : ECDHOutput } |
  { 'Err' : string };
export type Result_4 = { 'Ok' : PublicKeyOutput } |
  { 'Err' : string };
export type Result_5 = { 'Ok' : Uint8Array | number[] } |
  { 'Err' : string };
export type Result_6 = { 'Ok' : SignedDelegation } |
  { 'Err' : string };
export type Result_7 = { 'Ok' : Array<Principal> } |
  { 'Err' : string };
export type Result_8 = { 'Ok' : Principal } |
  { 'Err' : string };
export type Result_9 = { 'Ok' : boolean } |
  { 'Err' : string };
/**
 * # Schnorr Algorithm.
 *
 * See [`SchnorrKeyId::algorithm`].
 */
export type SchnorrAlgorithm = {
    /**
     * ed25519.
     */
    'ed25519' : null
  } |
  {
    /**
     * BIP-340 secp256k1.
     */
    'bip340secp256k1' : null
  };
export interface SettingArchivedPayload {
  'dek' : [] | [Uint8Array | number[]],
  'version' : number,
  'deprecated' : boolean,
  'archived_at' : bigint,
  'payload' : [] | [Uint8Array | number[]],
}
export interface SettingInfo {
  'dek' : [] | [Uint8Array | number[]],
  'key' : Uint8Array | number[],
  'readers' : Array<Principal>,
  'status' : number,
  'updated_at' : bigint,
  'subject' : Principal,
  'desc' : string,
  'tags' : Array<[string, string]>,
  'created_at' : bigint,
  'version' : number,
  'payload' : [] | [Uint8Array | number[]],
}
export interface SettingPath {
  'ns' : string,
  'key' : Uint8Array | number[],
  'subject' : [] | [Principal],
  'version' : number,
  'user_owned' : boolean,
}
export interface SignDelegationInput {
  'ns' : string,
  'sig' : Uint8Array | number[],
  'name' : string,
  'pubkey' : Uint8Array | number[],
}
export interface SignIdentityInput { 'ns' : string, 'audience' : string }
export interface SignInResponse {
  /**
   * The user canister public key. This key is used to derive the user principal.
   */
  'user_key' : Uint8Array | number[],
  /**
   * The seed component used to derive the user key.
   */
  'seed' : Uint8Array | number[],
  /**
   * The session expiration time in nanoseconds since the UNIX epoch. This is the time at which
   * the delegation will no longer be valid.
   */
  'expiration' : bigint,
}
export interface SignInput {
  'ns' : string,
  'derivation_path' : Array<Uint8Array | number[]>,
  'message' : Uint8Array | number[],
}
/**
 * SignedDelegation is a [`Delegation`] that has been signed by an [`Identity`](https://docs.rs/ic-agent/latest/ic_agent/trait.Identity.html).
 */
export interface SignedDelegation {
  /**
   * The signature for the delegation.
   */
  'signature' : Uint8Array | number[],
  /**
   * The signed delegation.
   */
  'delegation' : Delegation,
}
export interface StateInfo {
  'freezing_threshold' : bigint,
  'ecdsa_key_name' : string,
  'managers' : Array<Principal>,
  'governance_canister' : [] | [Principal],
  'name' : string,
  'vetkd_context_version' : number,
  'low_wasm_memory' : boolean,
  'auditors' : Array<Principal>,
  'schnorr_secp256k1_public_key' : [] | [PublicKeyOutput],
  'ecdsa_public_key' : [] | [PublicKeyOutput],
  'schnorr_key_name' : string,
  'schnorr_ed25519_public_key' : [] | [PublicKeyOutput],
  'allowed_apis' : Array<string>,
  'subnet_size' : bigint,
  'namespace_total' : bigint,
  'vetkd_key_name' : string,
}
export interface UpdateNamespaceInput {
  'status' : [] | [number],
  'session_expires_in_ms' : [] | [bigint],
  'desc' : [] | [string],
  'name' : string,
  'max_payload_size' : [] | [bigint],
  'visibility' : [] | [number],
}
export interface UpdateSettingInfoInput {
  'status' : [] | [number],
  'desc' : [] | [string],
  'tags' : [] | [Array<[string, string]>],
}
export interface UpdateSettingPayloadInput {
  'dek' : [] | [Uint8Array | number[]],
  'status' : [] | [number],
  'deprecate_current' : [] | [boolean],
  'payload' : [] | [Uint8Array | number[]],
}
export interface UpgradeArgs {
  'freezing_threshold' : [] | [bigint],
  'governance_canister' : [] | [Principal],
  'name' : [] | [string],
  'vetkd_context_version' : [] | [number],
  'subnet_size' : [] | [bigint],
  'clear_governance_canister' : [] | [boolean],
  'vetkd_key_name' : [] | [string],
}
export interface _SERVICE {
  'admin_add_allowed_apis' : ActorMethod<[Array<string>], Result>,
  'admin_add_auditors' : ActorMethod<[Array<Principal>], Result>,
  'admin_add_managers' : ActorMethod<[Array<Principal>], Result>,
  'admin_clear_low_wasm_memory' : ActorMethod<[], Result>,
  'admin_create_namespace' : ActorMethod<[CreateNamespaceInput], Result_1>,
  'admin_list_namespace' : ActorMethod<
    [[] | [string], [] | [number]],
    Result_2
  >,
  'admin_recover_namespace_managers' : ActorMethod<
    [string, Array<Principal>],
    Result
  >,
  'admin_remove_allowed_apis' : ActorMethod<[Array<string>], Result>,
  'admin_remove_auditors' : ActorMethod<[Array<Principal>], Result>,
  'admin_remove_managers' : ActorMethod<[Array<Principal>], Result>,
  /**
   * ecdh_encrypted_cose_key returns a permanent partial KEK encrypted with ECDH.
   * It should be used with a local partial key to derive a full KEK.
   */
  'ecdh_cose_encrypted_key' : ActorMethod<[SettingPath, ECDHInput], Result_3>,
  'ecdsa_public_key' : ActorMethod<[[] | [PublicKeyInput]], Result_4>,
  'ecdsa_sign' : ActorMethod<[SignInput], Result_5>,
  'get_delegation' : ActorMethod<
    [Uint8Array | number[], Uint8Array | number[], bigint],
    Result_6
  >,
  'namespace_add_auditors' : ActorMethod<[string, Array<Principal>], Result>,
  'namespace_add_delegator' : ActorMethod<[NamespaceDelegatorsInput], Result_7>,
  'namespace_add_managers' : ActorMethod<[string, Array<Principal>], Result>,
  'namespace_add_users' : ActorMethod<[string, Array<Principal>], Result>,
  'namespace_delete' : ActorMethod<[string], Result>,
  'namespace_get_delegators' : ActorMethod<[string, string], Result_7>,
  'namespace_get_fixed_identity' : ActorMethod<[string, string], Result_8>,
  'namespace_get_info' : ActorMethod<[string], Result_1>,
  'namespace_get_info_v2' : ActorMethod<[string, boolean], Result_1>,
  'namespace_is_member' : ActorMethod<[string, string, Principal], Result_9>,
  'namespace_list_fixed_identity_names' : ActorMethod<
    [string, [] | [string], [] | [number]],
    Result_10
  >,
  'namespace_list_members' : ActorMethod<
    [string, string, [] | [Principal], [] | [number]],
    Result_11
  >,
  'namespace_list_setting_keys' : ActorMethod<
    [string, boolean, [] | [Principal]],
    Result_12
  >,
  'namespace_list_setting_keys_v2' : ActorMethod<
    [
      string,
      boolean,
      [] | [Principal],
      [] | [[Principal, Uint8Array | number[]]],
      [] | [number],
    ],
    Result_12
  >,
  'namespace_rebuild_payload_bytes' : ActorMethod<[string], Result_13>,
  'namespace_remove_auditors' : ActorMethod<[string, Array<Principal>], Result>,
  'namespace_remove_delegator' : ActorMethod<
    [NamespaceDelegatorsInput],
    Result
  >,
  'namespace_remove_managers' : ActorMethod<[string, Array<Principal>], Result>,
  'namespace_remove_users' : ActorMethod<[string, Array<Principal>], Result>,
  'namespace_sign_delegation' : ActorMethod<[SignDelegationInput], Result_14>,
  'namespace_top_up' : ActorMethod<[string, bigint], Result_15>,
  'namespace_update_info' : ActorMethod<[UpdateNamespaceInput], Result>,
  'schnorr_public_key' : ActorMethod<
    [SchnorrAlgorithm, [] | [PublicKeyInput]],
    Result_4
  >,
  'schnorr_sign' : ActorMethod<[SchnorrAlgorithm, SignInput], Result_5>,
  'schnorr_sign_identity' : ActorMethod<
    [SchnorrAlgorithm, SignIdentityInput],
    Result_5
  >,
  'setting_add_readers' : ActorMethod<[SettingPath, Array<Principal>], Result>,
  'setting_create' : ActorMethod<[SettingPath, CreateSettingInput], Result_16>,
  'setting_delete' : ActorMethod<[SettingPath], Result>,
  'setting_get' : ActorMethod<[SettingPath], Result_17>,
  'setting_get_archived_payload' : ActorMethod<[SettingPath], Result_18>,
  'setting_get_info' : ActorMethod<[SettingPath], Result_17>,
  'setting_remove_readers' : ActorMethod<
    [SettingPath, Array<Principal>],
    Result
  >,
  'setting_update_info' : ActorMethod<
    [SettingPath, UpdateSettingInfoInput],
    Result_16
  >,
  'setting_update_payload' : ActorMethod<
    [SettingPath, UpdateSettingPayloadInput],
    Result_16
  >,
  'state_get_info' : ActorMethod<[], Result_19>,
  'validate2_admin_add_allowed_apis' : ActorMethod<[Array<string>], Result_20>,
  'validate2_admin_add_auditors' : ActorMethod<[Array<Principal>], Result_20>,
  'validate2_admin_add_managers' : ActorMethod<[Array<Principal>], Result_20>,
  'validate2_admin_remove_allowed_apis' : ActorMethod<
    [Array<string>],
    Result_20
  >,
  'validate2_admin_remove_auditors' : ActorMethod<
    [Array<Principal>],
    Result_20
  >,
  'validate2_admin_remove_managers' : ActorMethod<
    [Array<Principal>],
    Result_20
  >,
  'validate_admin_add_allowed_apis' : ActorMethod<[Array<string>], Result>,
  'validate_admin_add_auditors' : ActorMethod<[Array<Principal>], Result>,
  'validate_admin_add_managers' : ActorMethod<[Array<Principal>], Result>,
  'validate_admin_remove_allowed_apis' : ActorMethod<[Array<string>], Result>,
  'validate_admin_remove_auditors' : ActorMethod<[Array<Principal>], Result>,
  'validate_admin_remove_managers' : ActorMethod<[Array<Principal>], Result>,
  'vetkd_encrypted_key' : ActorMethod<
    [SettingPath, Uint8Array | number[]],
    Result_5
  >,
  'vetkd_public_key' : ActorMethod<[SettingPath], Result_5>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
