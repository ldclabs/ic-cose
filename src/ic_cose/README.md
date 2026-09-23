# `ic_cose`
![License](https://img.shields.io/crates/l/ic_cose.svg)
[![Crates.io](https://img.shields.io/crates/d/ic_cose.svg)](https://crates.io/crates/ic_cose)
[![Test](https://github.com/ldclabs/ic-cose/actions/workflows/test.yml/badge.svg)](https://github.com/ldclabs/ic-cose/actions/workflows/test.yml)
[![Docs.rs](https://img.shields.io/docsrs/ic_cose?label=docs.rs)](https://docs.rs/ic_cose)
[![Latest Version](https://img.shields.io/crates/v/ic_cose.svg)](https://crates.io/crates/ic_cose)

[IC-COSE](https://github.com/ldclabs/ic-cose) is a decentralized COnfiguration service with Signing and Encryption on the Internet Computer.

`ic_cose` is the Rust version of the client SDK for the IC COSE canister.

## Documentation

For detailed documentation, please visit: https://docs.rs/ic_cose

## License

Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

Licensed under the MIT License. See [LICENSE](../../LICENSE-MIT) for details.

## Client verification and pagination

`agent::build_agent` verifies query signatures and retains the pinned IC root key. Use `agent::build_local_agent` explicitly for a trusted local replica. Query signatures authenticate a replica response; use `CoseSDK::setting_get_consensus` when consensus is needed.

Use `namespace_list_setting_keys_v2` with the last `(subject, key)` as an exclusive cursor for more than 1000 settings. Keep namespace, `user_owned` and subject fixed throughout pagination. `namespace_get_info_v2`, `namespace_list_members` and `namespace_list_fixed_identity_names` avoid downloading full member collections.
