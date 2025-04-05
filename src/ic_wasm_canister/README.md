# `ic_wasm_canister`

An ICP canister wasm module management service on the Internet Computer.

## Features

- Canister deployment management
- Canister recharge management

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
admin_deploy : (DeployWasmInput, opt blob) -> (Result);
admin_remove_committers : (vec principal) -> (Result);
admin_remove_managers : (vec principal) -> (Result);
admin_update_canister_settings : (UpdateSettingsArgument) -> (Result);
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
