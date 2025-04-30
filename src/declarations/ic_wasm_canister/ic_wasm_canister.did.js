export const idlFactory = ({ IDL }) => {
  const UpgradeArgs = IDL.Record({
    'governance_canister' : IDL.Opt(IDL.Principal),
    'name' : IDL.Opt(IDL.Text),
    'token_expiration' : IDL.Opt(IDL.Nat64),
    'topup_threshold' : IDL.Opt(IDL.Nat),
    'topup_amount' : IDL.Opt(IDL.Nat),
  });
  const InitArgs = IDL.Record({
    'governance_canister' : IDL.Opt(IDL.Principal),
    'name' : IDL.Text,
    'topup_threshold' : IDL.Nat,
    'topup_amount' : IDL.Nat,
  });
  const ChainArgs = IDL.Variant({ 'Upgrade' : UpgradeArgs, 'Init' : InitArgs });
  const Result = IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text });
  const AddWasmInput = IDL.Record({
    'name' : IDL.Text,
    'wasm' : IDL.Vec(IDL.Nat8),
    'description' : IDL.Text,
  });
  const Result_1 = IDL.Variant({
    'Ok' : IDL.Vec(IDL.Vec(IDL.Nat8)),
    'Err' : IDL.Text,
  });
  const Result_2 = IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : IDL.Text });
  const LogVisibility = IDL.Variant({
    'controllers' : IDL.Null,
    'public' : IDL.Null,
    'allowed_viewers' : IDL.Vec(IDL.Principal),
  });
  const CanisterSettings = IDL.Record({
    'freezing_threshold' : IDL.Opt(IDL.Nat),
    'wasm_memory_threshold' : IDL.Opt(IDL.Nat),
    'controllers' : IDL.Opt(IDL.Vec(IDL.Principal)),
    'reserved_cycles_limit' : IDL.Opt(IDL.Nat),
    'log_visibility' : IDL.Opt(LogVisibility),
    'wasm_memory_limit' : IDL.Opt(IDL.Nat),
    'memory_allocation' : IDL.Opt(IDL.Nat),
    'compute_allocation' : IDL.Opt(IDL.Nat),
  });
  const Result_3 = IDL.Variant({ 'Ok' : IDL.Principal, 'Err' : IDL.Text });
  const DeployWasmInput = IDL.Record({
    'args' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'name' : IDL.Text,
    'canister' : IDL.Principal,
  });
  const UpdateSettingsArgs = IDL.Record({
    'canister_id' : IDL.Principal,
    'settings' : CanisterSettings,
  });
  const DeploymentInfo = IDL.Record({
    'args' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'name' : IDL.Text,
    'prev_hash' : IDL.Vec(IDL.Nat8),
    'error' : IDL.Opt(IDL.Text),
    'deploy_at' : IDL.Nat64,
    'canister' : IDL.Principal,
    'wasm_hash' : IDL.Vec(IDL.Nat8),
  });
  const Result_4 = IDL.Variant({
    'Ok' : IDL.Vec(DeploymentInfo),
    'Err' : IDL.Text,
  });
  const MemoryMetrics = IDL.Record({
    'wasm_binary_size' : IDL.Nat,
    'wasm_chunk_store_size' : IDL.Nat,
    'canister_history_size' : IDL.Nat,
    'stable_memory_size' : IDL.Nat,
    'snapshots_size' : IDL.Nat,
    'wasm_memory_size' : IDL.Nat,
    'global_memory_size' : IDL.Nat,
    'custom_sections_size' : IDL.Nat,
  });
  const CanisterStatusType = IDL.Variant({
    'stopped' : IDL.Null,
    'stopping' : IDL.Null,
    'running' : IDL.Null,
  });
  const DefiniteCanisterSettings = IDL.Record({
    'freezing_threshold' : IDL.Nat,
    'wasm_memory_threshold' : IDL.Nat,
    'controllers' : IDL.Vec(IDL.Principal),
    'reserved_cycles_limit' : IDL.Nat,
    'log_visibility' : LogVisibility,
    'wasm_memory_limit' : IDL.Nat,
    'memory_allocation' : IDL.Nat,
    'compute_allocation' : IDL.Nat,
  });
  const QueryStats = IDL.Record({
    'response_payload_bytes_total' : IDL.Nat,
    'num_instructions_total' : IDL.Nat,
    'num_calls_total' : IDL.Nat,
    'request_payload_bytes_total' : IDL.Nat,
  });
  const CanisterStatusResult = IDL.Record({
    'memory_metrics' : MemoryMetrics,
    'status' : CanisterStatusType,
    'memory_size' : IDL.Nat,
    'cycles' : IDL.Nat,
    'settings' : DefiniteCanisterSettings,
    'query_stats' : QueryStats,
    'idle_cycles_burned_per_day' : IDL.Nat,
    'module_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'reserved_cycles' : IDL.Nat,
  });
  const Result_5 = IDL.Variant({
    'Ok' : CanisterStatusResult,
    'Err' : IDL.Text,
  });
  const Result_6 = IDL.Variant({
    'Ok' : IDL.Vec(IDL.Principal),
    'Err' : IDL.Text,
  });
  const StateInfo = IDL.Record({
    'managers' : IDL.Vec(IDL.Principal),
    'governance_canister' : IDL.Opt(IDL.Principal),
    'name' : IDL.Text,
    'deployment_logs' : IDL.Nat64,
    'deployed_total' : IDL.Nat64,
    'wasm_total' : IDL.Nat64,
    'latest_version' : IDL.Vec(IDL.Tuple(IDL.Text, IDL.Vec(IDL.Nat8))),
    'committers' : IDL.Vec(IDL.Principal),
  });
  const Result_7 = IDL.Variant({ 'Ok' : StateInfo, 'Err' : IDL.Text });
  const WasmInfo = IDL.Record({
    'hash' : IDL.Vec(IDL.Nat8),
    'name' : IDL.Text,
    'wasm' : IDL.Vec(IDL.Nat8),
    'description' : IDL.Text,
    'created_at' : IDL.Nat64,
    'created_by' : IDL.Principal,
  });
  const Result_8 = IDL.Variant({ 'Ok' : WasmInfo, 'Err' : IDL.Text });
  const Result_9 = IDL.Variant({ 'Ok' : IDL.Text, 'Err' : IDL.Text });
  return IDL.Service({
    'admin_add_committers' : IDL.Func([IDL.Vec(IDL.Principal)], [Result], []),
    'admin_add_managers' : IDL.Func([IDL.Vec(IDL.Principal)], [Result], []),
    'admin_add_wasm' : IDL.Func(
        [AddWasmInput, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result],
        [],
      ),
    'admin_batch_call' : IDL.Func(
        [IDL.Vec(IDL.Principal), IDL.Text, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_1],
        [],
      ),
    'admin_batch_topup' : IDL.Func([], [Result_2], []),
    'admin_create_canister' : IDL.Func(
        [IDL.Text, IDL.Opt(CanisterSettings), IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_3],
        [],
      ),
    'admin_create_on' : IDL.Func(
        [
          IDL.Principal,
          IDL.Text,
          IDL.Opt(CanisterSettings),
          IDL.Opt(IDL.Vec(IDL.Nat8)),
        ],
        [Result_3],
        [],
      ),
    'admin_deploy' : IDL.Func(
        [DeployWasmInput, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result],
        [],
      ),
    'admin_remove_committers' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result],
        [],
      ),
    'admin_remove_managers' : IDL.Func([IDL.Vec(IDL.Principal)], [Result], []),
    'admin_update_canister_settings' : IDL.Func(
        [UpdateSettingsArgs],
        [Result],
        [],
      ),
    'deployment_logs' : IDL.Func(
        [IDL.Text, IDL.Opt(IDL.Nat), IDL.Opt(IDL.Nat)],
        [Result_4],
        ['query'],
      ),
    'get_canister_status' : IDL.Func([IDL.Opt(IDL.Principal)], [Result_5], []),
    'get_deployed_canisters' : IDL.Func([], [Result_6], ['query']),
    'get_deployed_canisters_info' : IDL.Func([], [Result_4], ['query']),
    'get_state' : IDL.Func([], [Result_7], ['query']),
    'get_wasm' : IDL.Func([IDL.Vec(IDL.Nat8)], [Result_8], ['query']),
    'validate_admin_add_committers' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result_9],
        [],
      ),
    'validate_admin_add_managers' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result_9],
        [],
      ),
    'validate_admin_add_wasm' : IDL.Func(
        [AddWasmInput, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_9],
        [],
      ),
    'validate_admin_batch_call' : IDL.Func(
        [IDL.Vec(IDL.Principal), IDL.Text, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_9],
        [],
      ),
    'validate_admin_batch_topup' : IDL.Func([], [Result_9], []),
    'validate_admin_create_canister' : IDL.Func(
        [IDL.Text, IDL.Opt(CanisterSettings), IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_9],
        [],
      ),
    'validate_admin_create_on' : IDL.Func(
        [
          IDL.Principal,
          IDL.Text,
          IDL.Opt(CanisterSettings),
          IDL.Opt(IDL.Vec(IDL.Nat8)),
        ],
        [Result_9],
        [],
      ),
    'validate_admin_deploy' : IDL.Func(
        [DeployWasmInput, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_9],
        [],
      ),
    'validate_admin_remove_committers' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result_9],
        [],
      ),
    'validate_admin_remove_managers' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result_9],
        [],
      ),
    'validate_admin_update_canister_settings' : IDL.Func(
        [UpdateSettingsArgs],
        [Result_9],
        [],
      ),
  });
};
export const init = ({ IDL }) => {
  const UpgradeArgs = IDL.Record({
    'governance_canister' : IDL.Opt(IDL.Principal),
    'name' : IDL.Opt(IDL.Text),
    'token_expiration' : IDL.Opt(IDL.Nat64),
    'topup_threshold' : IDL.Opt(IDL.Nat),
    'topup_amount' : IDL.Opt(IDL.Nat),
  });
  const InitArgs = IDL.Record({
    'governance_canister' : IDL.Opt(IDL.Principal),
    'name' : IDL.Text,
    'topup_threshold' : IDL.Nat,
    'topup_amount' : IDL.Nat,
  });
  const ChainArgs = IDL.Variant({ 'Upgrade' : UpgradeArgs, 'Init' : InitArgs });
  return [IDL.Opt(ChainArgs)];
};
