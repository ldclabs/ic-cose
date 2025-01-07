# `ic_cose_canister`
⚙️ A decentralized COnfiguration service with Signing and Encryption on the Internet Computer.

## Features

- [x] Supports message signing and configuration data encryption (COSE, Threshold ECDSA, Threshold Schnorr, VetKeys (TODO)).
- [x] Organizes configuration data by namespaces and client subjects with fine-grained access control.
- [ ] Supports horizontal scalability, WASM upgrade management, and Cycles recharge management.
- [ ] Serve as a state persistence service for enclaves, aiding in loading and persisting confidential data during startup and runtime.
- [ ] Can be used as a cluster management center for both Web3 and Web2 services.

## Demo

Try it online: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=53cyg-yyaaa-aaaap-ahpua-cai

## Quick Start

### Local Deployment

Deploy the canister:
```bash
dfx deploy ic_cose_canister

# or with arguments
# dfx canister create --specified-id 53cyg-yyaaa-aaaap-ahpua-cai ic_cose_canister
dfx deploy ic_cose_canister --argument "(opt variant {Init =
  record {
    name = \"LDC Labs\";
    ecdsa_key_name = \"dfx_test_key\";
    schnorr_key_name = \"dfx_test_key\";
    vetkd_key_name = \"test_key_1\";
    allowed_apis = vec {};
    subnet_size = 0;
    freezing_threshold = 1_000_000_000_000;
  }
})"

dfx canister call ic_cose_canister state_get_info '()'

MYID=$(dfx identity get-principal)

# add managers
dfx canister call ic_cose_canister admin_add_managers "(vec {principal \"$MYID\"})"

dfx canister call ic_cose_canister ecdsa_public_key '(null)'

dfx canister call ic_cose_canister schnorr_public_key '(variant { ed25519 }, null)'

dfx canister call ic_cose_canister schnorr_public_key '(variant { bip340secp256k1 }, null)'

dfx canister call ic_cose_canister admin_create_namespace "(record {
  name = \"testing\";
  visibility = 1;
  desc = null;
  max_payload_size = opt 1_000_000;
  managers = vec {principal \"$MYID\"};
  auditors = {};
  users = {};
})"

dfx canister call ic_cose_canister admin_list_namespace "(null, null)"

dfx canister call ic_cose_canister ecdsa_public_key '(opt record {
  ns = "testing";
  derivation_path = vec {};
})'

dfx canister call ic_cose_canister namespace_add_users "(\"testing\", vec {principal \"hpudd-yqaaa-aaaap-ahnbq-cai\"})"
```

## API Reference

The canister exposes a comprehensive Candid API. Key endpoints include:

```candid
# Namespace Operations
namespace_add_managers : (text, vec principal) -> (Result)
namespace_update_info : (UpdateNamespaceInput) -> (Result)
namespace_get_info : (text) -> (Result) query
namespace_list_setting_keys : (text, bool, opt principal) -> (Result) query

# Setting Operations
setting_create : (SettingPath, CreateSettingInput) -> (Result)
setting_get : (SettingPath) -> (Result) query
setting_add_readers : (SettingPath, vec principal) -> (Result)
setting_update_payload : (SettingPath, UpdateSettingPayloadInput) -> (Result)
namespace_top_up : (text, nat) -> (Result)

# COSE Operations
schnorr_public_key : (SchnorrAlgorithm, opt PublicKeyInput) -> (Result) query
schnorr_sign : (SchnorrAlgorithm, SignInput) -> (Result)
ecdsa_sign : (SignInput) -> (Result)
ecdh_cose_encrypted_key : (SettingPath, ECDHInput) -> (Result)

# Identity Operations
namespace_get_fixed_identity : (text, text) -> (Result) query
namespace_add_delegator : (NamespaceDelegatorsInput) -> (Result)
namespace_sign_delegation : (SignDelegationInput) -> (Result)
get_delegation : (blob, blob, nat64) -> (Result) query

# Admin Operations
admin_add_managers : (vec principal) -> (Result)
admin_create_namespace : (CreateNamespaceInput) -> (Result)
admin_add_allowed_apis : (vec text) -> (Result)
```

Full Candid API definition: [ic_cose_canister.did](https://github.com/ldclabs/ic-cose/tree/main/src/ic_cose_canister/ic_cose_canister.did)

## License
Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-cose` is licensed under the MIT License. See [LICENSE](../../LICENSE-MIT) for the full license text.