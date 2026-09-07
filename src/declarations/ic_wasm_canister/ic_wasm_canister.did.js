export const idlFactory = ({ IDL }) => {
  const UpgradeArgs = IDL.Record({
    'governance_canister' : IDL.Opt(IDL.Principal),
    'name' : IDL.Opt(IDL.Text),
    'token_expiration' : IDL.Opt(IDL.Nat64),
    'topup_threshold' : IDL.Opt(IDL.Nat),
    'topup_amount' : IDL.Opt(IDL.Nat),
    'clear_governance_canister' : IDL.Opt(IDL.Bool),
  });
  const InitArgs = IDL.Record({
    'governance_canister' : IDL.Opt(IDL.Principal),
    'name' : IDL.Text,
    'topup_threshold' : IDL.Nat,
    'topup_amount' : IDL.Nat,
  });
  const ChainArgs = IDL.Variant({ 'Upgrade' : UpgradeArgs, 'Init' : InitArgs });
  const Result = IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text });
  const WasmEncoding = IDL.Variant({ 'Raw' : IDL.Null, 'Gzip' : IDL.Null });
  const ProvisionSettings = IDL.Record({
    'freezing_threshold' : IDL.Opt(IDL.Nat64),
    'controllers' : IDL.Vec(IDL.Principal),
    'reserved_cycles_limit' : IDL.Opt(IDL.Nat),
    'wasm_memory_limit' : IDL.Opt(IDL.Nat64),
    'memory_allocation' : IDL.Opt(IDL.Nat64),
    'compute_allocation' : IDL.Opt(IDL.Nat64),
  });
  const ProvisionTemplate = IDL.Record({
    'id' : IDL.Text,
    'initial_cycles' : IDL.Nat,
    'artifact_hash' : IDL.Vec(IDL.Nat8),
    'expected_module_hash' : IDL.Vec(IDL.Nat8),
    'encoding' : WasmEncoding,
    'pool_size' : IDL.Nat16,
    'settings' : ProvisionSettings,
    'subnet' : IDL.Opt(IDL.Principal),
    'max_init_args_bytes' : IDL.Nat32,
    'wasm_name' : IDL.Text,
  });
  const PoolStatus = IDL.Variant({
    'CreateUnknown' : IDL.Null,
    'Idle' : IDL.Null,
    'CreatePending' : IDL.Null,
  });
  const ProvisionTemplateInfo = IDL.Record({
    'hash' : IDL.Vec(IDL.Nat8),
    'installed' : IDL.Nat32,
    'reserved' : IDL.Nat32,
    'created_at' : IDL.Nat64,
    'created_by' : IDL.Principal,
    'available' : IDL.Nat32,
    'settings_hash' : IDL.Vec(IDL.Nat8),
    'template' : ProvisionTemplate,
    'pool_status' : PoolStatus,
    'subnet_policy_hash' : IDL.Vec(IDL.Nat8),
    'tombstones' : IDL.Nat32,
  });
  const Result_1 = IDL.Variant({
    'Ok' : ProvisionTemplateInfo,
    'Err' : IDL.Text,
  });
  const AddWasmInput = IDL.Record({
    'encoding' : IDL.Opt(WasmEncoding),
    'name' : IDL.Text,
    'wasm' : IDL.Vec(IDL.Nat8),
    'description' : IDL.Text,
  });
  const Result_2 = IDL.Variant({ 'Ok' : IDL.Vec(IDL.Nat8), 'Err' : IDL.Text });
  const Result_3 = IDL.Variant({ 'Ok' : IDL.Nat64, 'Err' : IDL.Text });
  const Result_4 = IDL.Variant({
    'Ok' : IDL.Vec(IDL.Vec(IDL.Nat8)),
    'Err' : IDL.Text,
  });
  const BatchCallResult = IDL.Record({
    'error' : IDL.Opt(IDL.Text),
    'canister' : IDL.Principal,
    'reply' : IDL.Opt(IDL.Vec(IDL.Nat8)),
  });
  const Result_5 = IDL.Variant({
    'Ok' : IDL.Vec(BatchCallResult),
    'Err' : IDL.Text,
  });
  const Result_6 = IDL.Variant({ 'Ok' : IDL.Nat, 'Err' : IDL.Text });
  const TopupResult = IDL.Record({
    'deposited' : IDL.Nat,
    'balance_before' : IDL.Opt(IDL.Nat),
    'error' : IDL.Opt(IDL.Text),
    'canister' : IDL.Principal,
  });
  const Result_7 = IDL.Variant({
    'Ok' : IDL.Vec(TopupResult),
    'Err' : IDL.Text,
  });
  const CommitWasmChunksInput = IDL.Record({
    'artifact_hash' : IDL.Vec(IDL.Nat8),
    'encoding' : IDL.Opt(WasmEncoding),
    'name' : IDL.Text,
    'chunk_hashes' : IDL.Vec(IDL.Vec(IDL.Nat8)),
    'description' : IDL.Text,
  });
  const EnvironmentVariable = IDL.Record({
    'value' : IDL.Text,
    'name' : IDL.Text,
  });
  const LogVisibility = IDL.Variant({
    'controllers' : IDL.Null,
    'public' : IDL.Null,
    'allowed_viewers' : IDL.Vec(IDL.Principal),
  });
  const CanisterSettings = IDL.Record({
    'freezing_threshold' : IDL.Opt(IDL.Nat),
    'wasm_memory_threshold' : IDL.Opt(IDL.Nat),
    'environment_variables' : IDL.Opt(IDL.Vec(EnvironmentVariable)),
    'controllers' : IDL.Opt(IDL.Vec(IDL.Principal)),
    'reserved_cycles_limit' : IDL.Opt(IDL.Nat),
    'log_visibility' : IDL.Opt(LogVisibility),
    'log_memory_limit' : IDL.Opt(IDL.Nat),
    'wasm_memory_limit' : IDL.Opt(IDL.Nat),
    'memory_allocation' : IDL.Opt(IDL.Nat),
    'compute_allocation' : IDL.Opt(IDL.Nat),
  });
  const Result_8 = IDL.Variant({ 'Ok' : IDL.Principal, 'Err' : IDL.Text });
  const DeployWasmInput = IDL.Record({
    'args' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'name' : IDL.Text,
    'canister' : IDL.Principal,
  });
  const Result_9 = IDL.Variant({ 'Ok' : IDL.Bool, 'Err' : IDL.Text });
  const UpdateSettingsArgs = IDL.Record({
    'canister_id' : IDL.Principal,
    'settings' : CanisterSettings,
  });
  const ReleaseReceipt = IDL.Record({
    'request_id' : IDL.Vec(IDL.Nat8),
    'canister' : IDL.Principal,
    'released_at' : IDL.Nat64,
  });
  const Result_10 = IDL.Variant({ 'Ok' : ReleaseReceipt, 'Err' : IDL.Text });
  const DeploymentInfo = IDL.Record({
    'args_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'args_size' : IDL.Nat64,
    'args' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'name' : IDL.Text,
    'prev_hash' : IDL.Vec(IDL.Nat8),
    'log_id' : IDL.Nat64,
    'error' : IDL.Opt(IDL.Text),
    'deploy_at' : IDL.Nat64,
    'canister' : IDL.Principal,
    'module_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'wasm_hash' : IDL.Vec(IDL.Nat8),
  });
  const Result_11 = IDL.Variant({
    'Ok' : IDL.Vec(DeploymentInfo),
    'Err' : IDL.Text,
  });
  const DeploymentRequest = IDL.Record({
    'request_id' : IDL.Vec(IDL.Nat8),
    'args_hash' : IDL.Vec(IDL.Nat8),
    'artifact_hash' : IDL.Vec(IDL.Nat8),
    'expected_module_hash' : IDL.Vec(IDL.Nat8),
    'expected_prev_module_hash' : IDL.Vec(IDL.Nat8),
    'args' : IDL.Vec(IDL.Nat8),
    'canister' : IDL.Principal,
    'expires_at' : IDL.Nat64,
    'wasm_name' : IDL.Text,
  });
  const ProvisionStage = IDL.Variant({
    'Failed' : IDL.Null,
    'Reserved' : IDL.Null,
    'Released' : IDL.Null,
    'InstallPending' : IDL.Null,
    'Installed' : IDL.Null,
  });
  const ProvisionReceipt = IDL.Record({
    'request_id' : IDL.Vec(IDL.Nat8),
    'updated_at' : IDL.Nat64,
    'args_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'artifact_hash' : IDL.Vec(IDL.Nat8),
    'provision_spec_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'owner' : IDL.Principal,
    'provision_template_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'created_at' : IDL.Nat64,
    'error' : IDL.Opt(IDL.Text),
    'stage' : ProvisionStage,
    'prev_module_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'provision_template_id' : IDL.Opt(IDL.Text),
    'canister' : IDL.Principal,
    'module_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'expires_at' : IDL.Nat64,
    'wasm_name' : IDL.Text,
  });
  const Result_12 = IDL.Variant({ 'Ok' : ProvisionReceipt, 'Err' : IDL.Text });
  const InstallRequest = IDL.Record({
    'request_id' : IDL.Vec(IDL.Nat8),
    'provision_spec_hash' : IDL.Vec(IDL.Nat8),
    'expected_module_hash' : IDL.Vec(IDL.Nat8),
    'provision_template_hash' : IDL.Vec(IDL.Nat8),
    'init_args' : IDL.Vec(IDL.Nat8),
    'provision_template_id' : IDL.Text,
    'canister' : IDL.Principal,
    'init_args_hash' : IDL.Vec(IDL.Nat8),
    'expires_at' : IDL.Nat64,
  });
  const MemoryMetrics = IDL.Record({
    'wasm_binary_size' : IDL.Nat,
    'log_memory_store_size' : IDL.Nat,
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
    'environment_variables' : IDL.Vec(EnvironmentVariable),
    'controllers' : IDL.Vec(IDL.Principal),
    'reserved_cycles_limit' : IDL.Nat,
    'log_visibility' : LogVisibility,
    'log_memory_limit' : IDL.Nat,
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
    'ready_for_migration' : IDL.Bool,
    'version' : IDL.Nat64,
    'cycles' : IDL.Nat,
    'settings' : DefiniteCanisterSettings,
    'query_stats' : QueryStats,
    'idle_cycles_burned_per_day' : IDL.Nat,
    'module_hash' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'reserved_cycles' : IDL.Nat,
  });
  const Result_13 = IDL.Variant({
    'Ok' : CanisterStatusResult,
    'Err' : IDL.Text,
  });
  const Result_14 = IDL.Variant({
    'Ok' : IDL.Vec(IDL.Principal),
    'Err' : IDL.Text,
  });
  const WasmMetadata = IDL.Record({
    'encoding' : WasmEncoding,
    'hash' : IDL.Vec(IDL.Nat8),
    'name' : IDL.Text,
    'description' : IDL.Text,
    'created_at' : IDL.Nat64,
    'created_by' : IDL.Principal,
    'module_hash' : IDL.Vec(IDL.Nat8),
    'wasm_size' : IDL.Nat64,
  });
  const Result_15 = IDL.Variant({ 'Ok' : WasmMetadata, 'Err' : IDL.Text });
  const StateInfo = IDL.Record({
    'provisioners' : IDL.Vec(IDL.Principal),
    'managers' : IDL.Vec(IDL.Principal),
    'governance_canister' : IDL.Opt(IDL.Principal),
    'name' : IDL.Text,
    'low_wasm_memory' : IDL.Bool,
    'topup_threshold' : IDL.Nat,
    'latest_version_total' : IDL.Nat64,
    'topup_amount' : IDL.Nat,
    'deployment_logs' : IDL.Nat64,
    'deployed_total' : IDL.Nat64,
    'wasm_total' : IDL.Nat64,
    'latest_version_truncated' : IDL.Bool,
    'latest_version' : IDL.Vec(IDL.Tuple(IDL.Text, IDL.Vec(IDL.Nat8))),
    'committers' : IDL.Vec(IDL.Principal),
  });
  const Result_16 = IDL.Variant({ 'Ok' : StateInfo, 'Err' : IDL.Text });
  const WasmInfo = IDL.Record({
    'encoding' : WasmEncoding,
    'hash' : IDL.Vec(IDL.Nat8),
    'name' : IDL.Text,
    'wasm' : IDL.Vec(IDL.Nat8),
    'description' : IDL.Text,
    'created_at' : IDL.Nat64,
    'created_by' : IDL.Principal,
    'module_hash' : IDL.Vec(IDL.Nat8),
    'wasm_size' : IDL.Nat64,
  });
  const Result_17 = IDL.Variant({ 'Ok' : WasmInfo, 'Err' : IDL.Text });
  const Result_18 = IDL.Variant({ 'Ok' : IDL.Vec(IDL.Nat8), 'Err' : IDL.Text });
  const Result_19 = IDL.Variant({
    'Ok' : IDL.Vec(ProvisionReceipt),
    'Err' : IDL.Text,
  });
  const Result_20 = IDL.Variant({
    'Ok' : IDL.Vec(IDL.Tuple(IDL.Text, IDL.Vec(IDL.Nat8))),
    'Err' : IDL.Text,
  });
  const PoolCanisterState = IDL.Variant({
    'Available' : IDL.Null,
    'Reserved' : IDL.Null,
    'Installed' : IDL.Null,
  });
  const PoolCanisterInfo = IDL.Record({
    'request_id' : IDL.Opt(IDL.Vec(IDL.Nat8)),
    'created_at' : IDL.Nat64,
    'state' : PoolCanisterState,
    'canister' : IDL.Principal,
  });
  const Result_21 = IDL.Variant({
    'Ok' : IDL.Vec(PoolCanisterInfo),
    'Err' : IDL.Text,
  });
  const Result_22 = IDL.Variant({
    'Ok' : IDL.Vec(ProvisionTemplateInfo),
    'Err' : IDL.Text,
  });
  const ReserveRequest = IDL.Record({
    'request_id' : IDL.Vec(IDL.Nat8),
    'provision_template_hash' : IDL.Vec(IDL.Nat8),
    'provision_template_id' : IDL.Text,
    'expires_at' : IDL.Nat64,
  });
  const ReservationReceipt = IDL.Record({
    'request_id' : IDL.Vec(IDL.Nat8),
    'initial_cycles' : IDL.Nat,
    'controllers' : IDL.Vec(IDL.Principal),
    'owner' : IDL.Principal,
    'provision_template_hash' : IDL.Vec(IDL.Nat8),
    'provision_template_id' : IDL.Text,
    'settings_hash' : IDL.Vec(IDL.Nat8),
    'canister' : IDL.Principal,
    'reserved_at' : IDL.Nat64,
    'subnet_policy_hash' : IDL.Vec(IDL.Nat8),
    'expires_at' : IDL.Nat64,
  });
  const Result_23 = IDL.Variant({
    'Ok' : ReservationReceipt,
    'Err' : IDL.Text,
  });
  const Result_24 = IDL.Variant({ 'Ok' : IDL.Text, 'Err' : IDL.Text });
  return IDL.Service({
    'admin_add_committers' : IDL.Func([IDL.Vec(IDL.Principal)], [Result], []),
    'admin_add_managers' : IDL.Func([IDL.Vec(IDL.Principal)], [Result], []),
    'admin_add_provision_template' : IDL.Func(
        [ProvisionTemplate],
        [Result_1],
        [],
      ),
    'admin_add_provisioners' : IDL.Func([IDL.Vec(IDL.Principal)], [Result], []),
    'admin_add_wasm' : IDL.Func(
        [AddWasmInput, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result],
        [],
      ),
    'admin_add_wasm_chunk' : IDL.Func([IDL.Vec(IDL.Nat8)], [Result_2], []),
    'admin_archive_completed_requests' : IDL.Func(
        [IDL.Nat64, IDL.Nat32],
        [Result_3],
        [],
      ),
    'admin_batch_call' : IDL.Func(
        [IDL.Vec(IDL.Principal), IDL.Text, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_4],
        [],
      ),
    'admin_batch_call_v2' : IDL.Func(
        [IDL.Vec(IDL.Principal), IDL.Text, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_5],
        [],
      ),
    'admin_batch_topup' : IDL.Func([], [Result_6], []),
    'admin_batch_topup_page' : IDL.Func(
        [IDL.Opt(IDL.Principal), IDL.Opt(IDL.Nat32)],
        [Result_7],
        [],
      ),
    'admin_batch_topup_v2' : IDL.Func([], [Result_7], []),
    'admin_clear_low_wasm_memory' : IDL.Func([], [Result], []),
    'admin_clear_wasm_chunks' : IDL.Func([], [Result_3], []),
    'admin_clear_wasm_chunks_for' : IDL.Func([IDL.Principal], [Result_3], []),
    'admin_commit_wasm_chunks' : IDL.Func(
        [CommitWasmChunksInput, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_2],
        [],
      ),
    'admin_create_canister' : IDL.Func(
        [IDL.Text, IDL.Opt(CanisterSettings), IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_8],
        [],
      ),
    'admin_create_on' : IDL.Func(
        [
          IDL.Principal,
          IDL.Text,
          IDL.Opt(CanisterSettings),
          IDL.Opt(IDL.Vec(IDL.Nat8)),
        ],
        [Result_8],
        [],
      ),
    'admin_deploy' : IDL.Func(
        [DeployWasmInput, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result],
        [],
      ),
    'admin_forget_deployment' : IDL.Func([IDL.Principal], [Result_9], []),
    'admin_handoff_canister' : IDL.Func([UpdateSettingsArgs], [Result], []),
    'admin_migrate_legacy_wasm_artifact' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [Result_9],
        [],
      ),
    'admin_rebuild_log_index' : IDL.Func(
        [IDL.Nat64, IDL.Nat32],
        [Result_3],
        [],
      ),
    'admin_reconcile_deployment' : IDL.Func(
        [IDL.Principal, IDL.Text, IDL.Vec(IDL.Nat8)],
        [Result],
        [],
      ),
    'admin_reconcile_pool' : IDL.Func(
        [IDL.Text, IDL.Opt(IDL.Principal)],
        [Result],
        [],
      ),
    'admin_refill_pool' : IDL.Func([IDL.Text], [Result_8], []),
    'admin_release_expired_reservation' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [Result_10],
        [],
      ),
    'admin_remove_committers' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result],
        [],
      ),
    'admin_remove_managers' : IDL.Func([IDL.Vec(IDL.Principal)], [Result], []),
    'admin_remove_provision_template' : IDL.Func([IDL.Text], [Result], []),
    'admin_remove_provisioners' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result],
        [],
      ),
    'admin_remove_wasm' : IDL.Func([IDL.Vec(IDL.Nat8)], [Result], []),
    'admin_update_canister_settings' : IDL.Func(
        [UpdateSettingsArgs],
        [Result],
        [],
      ),
    'deployment_logs' : IDL.Func(
        [IDL.Text, IDL.Opt(IDL.Nat), IDL.Opt(IDL.Nat)],
        [Result_11],
        ['query'],
      ),
    'ensure_deployment' : IDL.Func([DeploymentRequest], [Result_12], []),
    'ensure_install' : IDL.Func([InstallRequest], [Result_12], []),
    'get_canister_status' : IDL.Func([IDL.Opt(IDL.Principal)], [Result_13], []),
    'get_deployed_canisters' : IDL.Func([], [Result_14], ['query']),
    'get_deployed_canisters_info' : IDL.Func([], [Result_11], ['query']),
    'get_deployed_canisters_info_v2' : IDL.Func(
        [IDL.Opt(IDL.Principal), IDL.Opt(IDL.Nat32)],
        [Result_11],
        ['query'],
      ),
    'get_deployed_canisters_v2' : IDL.Func(
        [IDL.Opt(IDL.Principal), IDL.Opt(IDL.Nat32)],
        [Result_14],
        ['query'],
      ),
    'get_next_wasm_version' : IDL.Func(
        [IDL.Text, IDL.Vec(IDL.Nat8)],
        [Result_15],
        ['query'],
      ),
    'get_provision_receipt' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [Result_12],
        ['query'],
      ),
    'get_provision_template' : IDL.Func([IDL.Text], [Result_1], ['query']),
    'get_state' : IDL.Func([], [Result_16], ['query']),
    'get_wasm' : IDL.Func([IDL.Vec(IDL.Nat8)], [Result_17], ['query']),
    'get_wasm_chunk' : IDL.Func(
        [IDL.Vec(IDL.Nat8), IDL.Nat64, IDL.Nat32],
        [Result_18],
        ['query'],
      ),
    'get_wasm_metadata' : IDL.Func([IDL.Vec(IDL.Nat8)], [Result_15], ['query']),
    'list_expired_reservations' : IDL.Func(
        [IDL.Opt(IDL.Vec(IDL.Nat8)), IDL.Opt(IDL.Nat32)],
        [Result_19],
        ['query'],
      ),
    'list_latest_wasm_versions' : IDL.Func(
        [IDL.Opt(IDL.Text), IDL.Opt(IDL.Nat32)],
        [Result_20],
        ['query'],
      ),
    'list_legacy_wasm_artifacts' : IDL.Func(
        [IDL.Opt(IDL.Vec(IDL.Nat8)), IDL.Opt(IDL.Nat32)],
        [Result_4],
        ['query'],
      ),
    'list_provision_pool' : IDL.Func([IDL.Text], [Result_21], ['query']),
    'list_provision_pool_v2' : IDL.Func(
        [IDL.Text, IDL.Opt(IDL.Principal), IDL.Opt(IDL.Nat32)],
        [Result_21],
        ['query'],
      ),
    'list_provision_templates' : IDL.Func([], [Result_22], ['query']),
    'list_provision_templates_v2' : IDL.Func(
        [IDL.Opt(IDL.Text), IDL.Opt(IDL.Nat32)],
        [Result_22],
        ['query'],
      ),
    'reconcile_provision_request' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [Result_12],
        [],
      ),
    'release_reservation' : IDL.Func(
        [IDL.Vec(IDL.Nat8), IDL.Principal],
        [Result_10],
        [],
      ),
    'reserve_canister' : IDL.Func([ReserveRequest], [Result_23], []),
    'validate_admin_add_committers' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result_24],
        [],
      ),
    'validate_admin_add_managers' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result_24],
        [],
      ),
    'validate_admin_add_provision_template' : IDL.Func(
        [ProvisionTemplate],
        [Result_24],
        [],
      ),
    'validate_admin_add_provisioners' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result_24],
        [],
      ),
    'validate_admin_add_wasm' : IDL.Func(
        [AddWasmInput, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_24],
        [],
      ),
    'validate_admin_batch_call' : IDL.Func(
        [IDL.Vec(IDL.Principal), IDL.Text, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_24],
        [],
      ),
    'validate_admin_batch_topup' : IDL.Func([], [Result_24], []),
    'validate_admin_create_canister' : IDL.Func(
        [IDL.Text, IDL.Opt(CanisterSettings), IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_24],
        [],
      ),
    'validate_admin_create_on' : IDL.Func(
        [
          IDL.Principal,
          IDL.Text,
          IDL.Opt(CanisterSettings),
          IDL.Opt(IDL.Vec(IDL.Nat8)),
        ],
        [Result_24],
        [],
      ),
    'validate_admin_deploy' : IDL.Func(
        [DeployWasmInput, IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_24],
        [],
      ),
    'validate_admin_reconcile_pool' : IDL.Func(
        [IDL.Text, IDL.Opt(IDL.Principal)],
        [Result_24],
        [],
      ),
    'validate_admin_remove_committers' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result_24],
        [],
      ),
    'validate_admin_remove_managers' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result_24],
        [],
      ),
    'validate_admin_remove_provision_template' : IDL.Func(
        [IDL.Text],
        [Result_24],
        [],
      ),
    'validate_admin_remove_provisioners' : IDL.Func(
        [IDL.Vec(IDL.Principal)],
        [Result_24],
        [],
      ),
    'validate_admin_remove_wasm' : IDL.Func(
        [IDL.Vec(IDL.Nat8)],
        [Result_24],
        [],
      ),
    'validate_admin_update_canister_settings' : IDL.Func(
        [UpdateSettingsArgs],
        [Result_24],
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
    'clear_governance_canister' : IDL.Opt(IDL.Bool),
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
