# `ic_cose_canister`
⚙️ A decentralized COnfiguration service with Signing and Encryption on the Internet Computer.

## Features

- [x] Supports message signing and configuration data encryption (COSE, Threshold ECDSA, Threshold Schnorr, VetKeys (TODO)).
- [x] Organizes configuration data by namespaces and client subjects with fine-grained access control.
- [ ] Supports horizontal scalability, WASM upgrade management, and Cycles recharge management.
- [ ] Serve as a state persistence service for enclaves, aiding in loading and persisting confidential data during startup and runtime.
- [ ] Can be used as a cluster management center for both Web3 and Web2 services.

## Candid API

```shell
  admin_add_allowed_apis : (vec text) -> (Result);
  admin_add_auditors : (vec principal) -> (Result);
  admin_add_managers : (vec principal) -> (Result);
  admin_create_namespace : (CreateNamespaceInput) -> (Result_1);
  admin_list_namespace : (opt text, opt nat32) -> (Result_2) query;
  admin_remove_allowed_apis : (vec text) -> (Result);
  admin_remove_auditors : (vec principal) -> (Result);
  admin_remove_managers : (vec principal) -> (Result);
  ecdh_cose_encrypted_key : (SettingPath, ECDHInput) -> (Result_3);
  ecdsa_public_key : (opt PublicKeyInput) -> (Result_4) query;
  ecdsa_sign : (SignInput) -> (Result_5);
  namespace_add_auditors : (text, vec principal) -> (Result);
  namespace_add_managers : (text, vec principal) -> (Result);
  namespace_add_users : (text, vec principal) -> (Result);
  namespace_get_info : (text) -> (Result_1) query;
  namespace_remove_auditors : (text, vec principal) -> (Result);
  namespace_remove_managers : (text, vec principal) -> (Result);
  namespace_remove_users : (text, vec principal) -> (Result);
  namespace_top_up : (text, nat) -> (Result_6);
  namespace_update_info : (UpdateNamespaceInput) -> (Result);
  schnorr_public_key : (SchnorrAlgorithm, opt PublicKeyInput) -> (
      Result_4,
    ) query;
  schnorr_sign : (SchnorrAlgorithm, SignInput) -> (Result_5);
  schnorr_sign_identity : (SchnorrAlgorithm, SignIdentityInput) -> (Result_5);
  setting_add_readers : (SettingPath, vec principal) -> (Result);
  setting_create : (SettingPath, CreateSettingInput) -> (Result_7);
  setting_get : (SettingPath) -> (Result_8) query;
  setting_get_archived_payload : (SettingPath) -> (Result_9) query;
  setting_get_info : (SettingPath) -> (Result_8) query;
  setting_remove_readers : (SettingPath, vec principal) -> (Result);
  setting_update_info : (SettingPath, UpdateSettingInfoInput) -> (Result_7);
  setting_update_payload : (SettingPath, UpdateSettingPayloadInput) -> (
      Result_7,
    );
  state_get_info : () -> (Result_10) query;
  validate_admin_add_allowed_apis : (vec text) -> (Result);
  validate_admin_add_auditors : (vec principal) -> (Result);
  validate_admin_add_managers : (vec principal) -> (Result);
  validate_admin_remove_allowed_apis : (vec text) -> (Result);
  validate_admin_remove_auditors : (vec principal) -> (Result);
  validate_admin_remove_managers : (vec principal) -> (Result);
  vetkd_encrypted_key : (SettingPath, blob) -> (Result_5);
  vetkd_public_key : (SettingPath) -> (Result_5);
```

The complete Candid API definition can be found in the [ic_cose_canister.did](https://github.com/ldclabs/ic-cose/tree/main/src/ic_cose_canister/ic_cose_canister.did) file.

## Running locally

Deploy to local network:
```bash
dfx deploy ic_cose_canister

# or with arguments
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

## License
Copyright © 2024 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-cose` is licensed under the MIT License. See [LICENSE](../../LICENSE-MIT) for the full license text.