# `IC-COSE`

⚙️ A decentralized COnfiguration service with Signing and Encryption on the Internet Computer.

💝 Backed by a **$25k Developer Grant** from the [DFINITY Foundation](https://dfinity.org/grants).

## Overview

`IC COSE` is a fully open-source decentralized configuration service running on the Internet Computer. Based on the [CBOR Object Signing and Encryption (COSE, RFC9052)](https://datatracker.ietf.org/doc/html/rfc9052) standard, it offers centralized message signing and configuration data encryption. Configuration data is organized by namespaces and client subjects, supporting collaboration, fine-grained access control, and horizontal scalability. It can serve as a reliable and secure configuration center for various Web3 services and Web2 services with high data security and reliability requirements.

A imaginative use case is serving as a state persistence service for enclaves running in Trusted Execution Environments (TEEs), aiding in loading confidential data during startup and persisting confidential data states during runtime.

## Features

- Supports message signing and configuration data encryption (COSE, Threshold ECDSA, Threshold Schnorr, VetKeys).
- Organizes configuration data by namespaces and client subjects with fine-grained access control.
- Serve as a state persistence service for enclaves, aiding in loading and persisting confidential data during startup and runtime.
- Supports horizontal scalability, WASM module management, and Cycles recharge management.
- Can be used as a cluster management center for both Web3 and Web2 services.

## Packages

| Package                                                                                               | Description                                                       |
| :---------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------- |
| [ic_cose_canister](https://github.com/ldclabs/ic-cose/tree/main/src/ic_cose_canister)                 | A decentralized COnfiguration service with Signing and Encryption |
| [ic_object_store_canister](https://github.com/ldclabs/ic-cose/tree/main/src/ic_object_store_canister) | A Object Store of Apache Arrow                                    |
| [ic_wasm_canister](https://github.com/ldclabs/ic-cose/tree/main/src/ic_wasm_canister)                 | An ICP canister wasm module management service                    |
| [ic_cose_types](https://github.com/ldclabs/ic-cose/tree/main/src/ic_cose_types)                       | Rust shared type definitions                                      |
| [ic_cose](https://github.com/ldclabs/ic-cose/tree/main/src/ic_cose)                                   | Rust client SDK for the IC COSE canister                          |
| [ic_object_store](https://github.com/ldclabs/ic-cose/tree/main/src/ic_object_store)                   | Rust client SDK for the IC Object Store canister                  |

## Who's using?

- [dMsg.net](https://dmsg.net): The world's 1st decentralized end-to-end encrypted messaging application fully running on the Internet Computer blockchain. dMsg.net uses `ic_cose_canister` to store encrypted keys for user.
- [IC-TEE](https://github.com/ldclabs/ic-tee): Make Trusted Execution Environments (TEEs) work with the Internet Computer. IC-TEE uses `ic_cose_canister` to store configs and confidential data (TLS cert/key, root keys).
- [Anda](https://github.com/ldclabs/anda): An AI agent framework built with Rust, powered by ICP and TEEs. Anda uses `ic_cose_canister` to store agent configs, uses `ic_object_store_canister` to store AI memory states.

If you plan to use this project and have any questions, feel free to open an issue. I will address it as soon as possible.

## License
Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-cose` is licensed under the MIT License. See [LICENSE](LICENSE-MIT) for the full license text.