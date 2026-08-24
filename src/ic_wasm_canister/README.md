# `ic_wasm_canister`

An ICP canister wasm module management service on the Internet Computer.

## Features

- Canister deployment management
- Canister recharge management
- Idempotent provisioning: governance-approved templates, a pre-created canister
  pool, and reservation/install/release keyed by a caller-chosen `request_id`
- Exact module pinning: a provisioned canister always gets the artifact and
  module hash its template fixes, never whatever `latest` happens to be
- Chunked and gzip module publishing, for artifacts above the ingress limit

## Provisioning

The provisioning API exists so a paid workflow can deploy a canister without
ever depending on a management-canister `create` whose response might be lost.
The management canister cannot be asked "which canister did you create for my
request id?", so creation is kept entirely outside the paid path:

1. **Governance approves a `ProvisionTemplate`** (`admin_add_provision_template`),
   fixing the wasm name, artifact hash, expected module hash, encoding,
   controllers, subnet, initial cycles and init-args limit. The template's `hash`
   covers all of it.
2. **Governance pre-creates pool canisters** (`admin_refill_pool`). A create whose
   outcome is unknown flips the template to `CreateUnknown` and circuit-breaks
   further refills until `admin_reconcile_pool` runs, so a lost response can only
   ever waste one unpaid, unbound canister — never a paid one.
3. **A provisioner reserves** (`reserve_canister`), which claims an already
   recorded canister for its `request_id`. This is synchronous: the binding is
   committed with the reply, so a lost response is recovered by replaying the
   call or reading `get_provision_receipt`.
4. **A provisioner installs** (`ensure_install`). The module comes from the
   template, the resulting module hash is verified against the approved one, and
   a retry after a lost response converges on the already-installed module.
5. **Unused reservations are released** (`release_reservation`) after verifying
   the canister is still empty and still carries the template's controllers. The
   `request_id` is then retired via a bounded, expiring tombstone.

Upgrades use `ensure_deployment`, which compare-and-swaps on the module hash the
canister currently runs, so a stale request can never overwrite an unexpected
module.

The `Provisioner` role is least-privilege: it may only name an approved template
and supply init args. It cannot manage roles, publish modules or deploy an
arbitrary wasm.

## Quick Start

### Deploy Locally

```bash
# dfx canister create --specified-id be2us-64aaa-aaaaa-qaabq-cai ic_wasm_canister
RUSTFLAGS="--cfg=getrandom_backend=\"custom\"" dfx deploy ic_wasm_canister --argument "(opt variant {Init =
  record {
    name = \"LDC Labs\";
    topup_threshold = 1_000_000_000_000;
    topup_amount = 5_000_000_000_000;
  }
})"

# Get state info
dfx canister call ic_wasm_canister get_state '()'
```

### Common Operations

```bash
# Add managers
MYID=$(dfx identity get-principal)
dfx canister call ic_wasm_canister admin_add_managers "(vec {principal \"$MYID\"})"

dfx canister call ic_wasm_canister admin_create_canister '("ic_object_store_canister", null, null)'
# (variant { Ok = principal "ctiya-peaaa-aaaaa-qaaja-cai" })

# Get canister status
dfx canister call ic_wasm_canister get_canister_status '(opt principal "YOUR_CANISTER_ID")'
```

## API Reference

The canister exposes a comprehensive Candid API. Key endpoints include:

```candid
admin_add_committers : (vec principal) -> (Result);
admin_add_managers : (vec principal) -> (Result);
admin_add_wasm : (AddWasmInput, opt blob) -> (Result);
admin_batch_call : (vec principal, text, opt blob) -> (Result_1);
admin_batch_topup : () -> (Result_2);
admin_create_canister : (text, opt CanisterSettings, opt blob) -> (Result_3);
admin_create_on : (principal, text, opt CanisterSettings, opt blob) -> (
    Result_3,
  );
admin_add_provision_template : (ProvisionTemplate) -> (Result_1);
admin_add_provisioners : (vec principal) -> (Result);
admin_add_wasm_chunk : (blob) -> (Result_2);
admin_commit_wasm_chunks : (CommitWasmChunksInput, opt blob) -> (Result_2);
admin_deploy : (DeployWasmInput, opt blob) -> (Result);
admin_reconcile_pool : (text, opt principal) -> (Result);
admin_refill_pool : (text) -> (Result_6);
admin_remove_committers : (vec principal) -> (Result);
admin_remove_managers : (vec principal) -> (Result);
admin_remove_provision_template : (text) -> (Result);
admin_remove_provisioners : (vec principal) -> (Result);
admin_update_canister_settings : (UpdateSettingsArgument) -> (Result);
ensure_deployment : (DeploymentRequest) -> (Result_8);
ensure_install : (InstallRequest) -> (Result_8);
release_reservation : (blob, principal) -> (Result_15);
reserve_canister : (ReserveRequest) -> (Result_16);
get_provision_receipt : (blob) -> (Result_8) query;
get_provision_template : (text) -> (Result_1) query;
list_provision_pool : (text) -> (Result_13) query;
list_provision_templates : () -> (Result_14) query;
deployment_logs : (text, opt nat, opt nat) -> (Result_4) query;
get_canister_status : (opt principal) -> (Result_5);
get_deployed_canisters : () -> (Result_6) query;
get_deployed_canisters_info : () -> (Result_4) query;
get_state : () -> (Result_7) query;
get_wasm : (blob) -> (Result_8) query;
```

Full Candid API definition: [ic_wasm_canister.did](https://github.com/ldclabs/ic-cose/tree/main/src/ic_wasm_canister/ic_wasm_canister.did)

## License
Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-cose` is licensed under the MIT License. See [LICENSE](../../LICENSE-MIT) for the full license text.
