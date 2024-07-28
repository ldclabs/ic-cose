# `ic_cose_canister`
⚙️ A decentralized COnfiguration service with Signing and Encryption on the Internet Computer.

## Features

- [x] Supports large file uploads and downloads through file sharding, concurrent high-speed uploads, resumable uploads, and segmented downloads.
- [x] Provides data verification based on ICP's verification mechanisms to ensure file integrity during reading.
- [x] Supports file directory tree.
- [x] Access control with permissions for public, private, read-only, and write-only for files, folders, and buckets.

## Candid API

```shell
  admin_add_auditors : (vec principal) -> (Result);
  admin_add_managers : (vec principal) -> (Result);
  admin_create_namespace : (CreateNamespaceInput) -> (Result_1);
  admin_list_namespace : (opt text, opt nat32) -> (Result_2) query;
  admin_remove_auditors : (vec principal) -> (Result);
  admin_remove_managers : (vec principal) -> (Result);
  ecdh_encrypted_cose_key : (CosePath, ECDHInput) -> (Result_3);
  ecdh_setting_get : (SettingPath, ECDHInput) -> (Result_4);
  ecdsa_public_key : (opt PublicKeyInput) -> (Result_5) query;
  ecdsa_sign : (SignInput) -> (Result_6);
  ecdsa_sign_identity : (SignIdentityInput) -> (Result_6);
  namespace_add_auditors : (text, vec principal) -> (Result);
  namespace_add_managers : (text, vec principal) -> (Result);
  namespace_add_users : (text, vec principal) -> (Result);
  namespace_get_info : (text) -> (Result_1) query;
  namespace_remove_auditors : (text, vec principal) -> (Result);
  namespace_remove_managers : (text, vec principal) -> (Result);
  namespace_remove_users : (text, vec principal) -> (Result);
  namespace_update_info : (UpdateNamespaceInput) -> (Result);
  schnorr_public_key : (SchnorrAlgorithm, opt PublicKeyInput) -> (
      Result_5,
    ) query;
  schnorr_sign : (SchnorrAlgorithm, SignInput) -> (Result_6);
  schnorr_sign_identity : (SchnorrAlgorithm, SignIdentityInput) -> (Result_6);
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
  validate_admin_add_auditors : (vec principal) -> (Result);
  validate_admin_add_managers : (vec principal) -> (Result);
  validate_admin_remove_auditors : (vec principal) -> (Result);
  validate_admin_remove_managers : (vec principal) -> (Result);
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
    vetkd_key_name = \"dfx_test_key\";
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