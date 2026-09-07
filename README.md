# IC-COSE

[English](README.md) · [简体中文](README.zh-CN.md)

Decentralized configuration, signing, encryption, and canister deployment management on the Internet Computer.

The project name originates from **COnfiguration service with Signing and Encryption**, backed by a **$25,000 Developer Grant** from the [DFINITY Foundation](https://dfinity.org/grants).

[Configuration & Key Management Guide](src/ic_cose_canister/README.md) · [WASM & Deployment Management Guide](src/ic_wasm_canister/README.md) · [Rust SDK](src/ic_cose/README.md)

## Overview

IC-COSE provides two independently deployable canisters, alongside an accompanying Rust SDK and shared type definitions:

- **`ic_cose_canister`**: Manages configuration data partitioned by namespace and subject. Provides version history, role-based access control, Threshold ECDSA / Schnorr signatures, encryption key derivation, CWT identity tokens, and fixed-identity IC session delegations.
- **`ic_wasm_canister`**: Manages a WASM artifact repository, coordinates canister creation and upgrades, executes batch calls and cycles top-ups, and supports crash-resilient provisioning workflows via immutable templates, pre-created canister pools, and durable request receipts.

Configuration encryption occurs client-side; the service stores either raw bytes or COSE (CBOR Object Signing and Encryption) envelopes. Deployment management maintains audit and operational state for artifacts and target canisters; billing, tenant authorization, job scheduling, and concurrency control remain the responsibility of the integrating system.

## Core Capabilities

### Configuration, Signing & Encryption

| Capability                | Interface & Scope                                                                                              |
| ------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Isolation & Authorization | Namespaces, subjects, server-managed vs. user-owned scopes, with manager, auditor, user, and reader roles      |
| Version History           | Current-version reads, version-checked writes, and historical payload / DEK archiving                          |
| Message Signatures        | Threshold ECDSA (secp256k1) and Schnorr (Ed25519 / BIP340), scoped by namespace derivation paths               |
| Encryption Keys           | Retrieve server-side partial KEKs via X25519 ECDH, or fetch transport-encrypted VetKeys verified on the client |
| Identity Tokens           | Schnorr-signed COSE_Sign1 / CWT tokens asserting caller identity, audience, validity windows, and scopes       |
| Fixed Identities          | Register authorized delegators for named identities within a namespace to issue IC session delegations         |

Access control boundaries are strictly enforced: a public namespace allows reading configuration content, but does not grant key retrieval or signing permissions. Signature derivation paths within a namespace are not automatically isolated by caller. See the [ic_cose_canister Technical Integration Guide](src/ic_cose_canister/README.md) for full authorization rules.

### WASM & Deployment Management

| Capability                   | Interface & Scope                                                                                                       |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Artifact Repository          | Stores Raw and Gzip WASM artifacts by SHA-256 digest, supporting direct and chunked uploads                             |
| Classic Deployment           | Create canisters on the fly, deploy latest or next versions, and update target settings                                 |
| Template-Driven Provisioning | Approve immutable templates (artifact, module hash, controllers, subnet, creation budget) and pre-create pool canisters |
| Request Recovery             | Reserve, install, query receipts, or release uninstalled targets keyed by caller-specified `request_id`                 |
| Exact Upgrades               | Pin artifact and expected before/after module hashes, with idempotent replay on duplicate requests                      |
| Operations Management        | Inspect deployment history, broadcast batch calls to registered canisters, and run threshold-based cycles top-ups       |

Pre-creating canisters decouples unpredictable subnet creation latency and potential message loss from synchronous user payment flows. The `request_id` mechanism allows safe recovery of failed or interrupted bindings without replacing tenant authorization or operational mutexes. Pre-upgrade module hash checks do not form an atomic cross-canister compare-and-swap; Gzip artifact hashes must never be conflated with the uncompressed module hash reported by the IC management canister. See the [ic_wasm_canister Technical Integration Guide](src/ic_wasm_canister/README.md) for architectural details.

## Components & Documentation

| Component                                  | Responsibility                                                            | Documentation                                                                                             |
| ------------------------------------------ | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| [`ic_cose_canister`](src/ic_cose_canister) | Configuration, signatures, encryption keys, and identity delegation       | [Integration Guide](src/ic_cose_canister/README.md) · [Candid](src/ic_cose_canister/ic_cose_canister.did) |
| [`ic_wasm_canister`](src/ic_wasm_canister) | WASM artifacts, deployments, provisioning, and maintenance                | [Integration Guide](src/ic_wasm_canister/README.md) · [Candid](src/ic_wasm_canister/ic_wasm_canister.did) |
| [`ic_cose`](src/ic_cose)                   | Rust client SDK for the COSE service                                      | [Overview](src/ic_cose/README.md) · [Client Implementation](src/ic_cose/src/client.rs)                    |
| [`ic_cose_types`](src/ic_cose_types)       | Shared data structures, COSE utilities, and deterministic hashing helpers | [Overview](src/ic_cose_types/README.md) · [Type Definitions](src/ic_cose_types/src/types)                 |

`ic_cose::client::CoseSDK` targets `ic_cose_canister`. For `ic_wasm_canister`, use generated Candid bindings or general canister call tooling; do not assume the COSE SDK wraps WASM management endpoints.

## Quick Start

### 1. Select the Desired Service

- To store configuration, manage encryption keys, or request signatures: start with [COSE Deployment & Minimal Workflow](src/ic_cose_canister/README.md#2-deployment-and-minimal-workflow).
- To publish and manage application canisters: start with [WASM Deployment & Minimal Workflow](src/ic_wasm_canister/README.md#2-deployment-and-minimal-workflow).
- To provision canisters via templates and pre-created pools: review [Provisioning Templates & Pre-Created Pools](src/ic_wasm_canister/README.md#6-provisioning-templates-and-pre-created-canister-pool), then integrate [Reservation, Installation & Release](src/ic_wasm_canister/README.md#7-reservation-installation-and-release).

The two services operate independently and do not require co-deployment. Initial installation requires explicit `Init` arguments; do not invoke parameterless `dfx deploy` without the initialization records specified in the component documentation.

### 2. Prepare the Local Environment

Ensure Rust, the `wasm32-unknown-unknown` target, and `dfx` are installed. In the repository root, run:

```bash
rustup target add wasm32-unknown-unknown
dfx start --background
```

Deploy the canister using the commands outlined in the respective component documentation. COSE threshold signatures and VetKD require the replica or target subnet to support the configured key IDs. WASM creation and operations require the management canister to hold sufficient cycles and maintain controller privileges over target canisters.

### 3. Client Integration

| Client Environment          | Integration Entry Point                                                                                                                                                           |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rust                        | [COSE SDK Examples](src/ic_cose_canister/README.md#10-client-integration-examples), [WASM Templates & Invocations](src/ic_wasm_canister/README.md#10-client-integration-examples) |
| TypeScript / JavaScript     | [COSE Bindings](src/declarations/ic_cose_canister), [WASM Bindings](src/declarations/ic_wasm_canister), invoked via authenticated Actors                                          |
| Other Languages / Canisters | Encode arguments according to Candid definitions; handle business `Result` variants and canister reject codes                                                                     |
| VetKeys Experiments         | [Rust Example](src/ic_cose/examples/vetkeys.rs), [Frontend Example](examples/vetkeys)                                                                                             |

Regenerate bindings after deployment as needed:

```bash
dfx generate ic_cose_canister
dfx generate ic_wasm_canister
```

Identities and keys used in examples are intended solely for local experimentation. Production clients must persist actual business paths, request IDs, and approved template hashes, while validating the Candid interface version of deployed canisters.

## Common Use Cases

- **Application Configuration & Secret Management**: Store versioned configuration, encrypted payloads, and decryption access controls for Web3 and Web2 services.
- **TEE State Persistence**: Allow enclaves in Trusted Execution Environments to load configuration and secrets during boot and persist encrypted state at runtime; attestation and authorization flows are managed by the application layer.
- **Service Identity & Signing**: Sign business payloads with threshold keys, or delegate stable canister signature identities to short-lived session keys.
- **Platform Canister Delivery & Operations**: Reserve and install canisters against pinned templates, recover provisioning workflows across network interruptions, coordinate upgrades, and automate cycles replenishment.

## Production Adoption

- [dMsg.net](https://dmsg.net): An end-to-end encrypted messaging application running on the Internet Computer, using `ic_cose_canister` to store user encryption keys.
- [IC-TEE](https://github.com/ldclabs/ic-tee): Integrates TEEs with the Internet Computer, leveraging `ic_cose_canister` to store enclave configuration, TLS certificates, private keys, and root secrets.
- [Anda](https://github.com/ldclabs/anda): An AI agent framework in Rust combining ICP and TEEs, utilizing `ic_cose_canister` for agent state and configuration management.

## Development & Testing

This repository is a Cargo workspace containing all four crates. Continuous integration checks can be run locally via:

```bash
cargo clippy --all-targets --all-features
cargo test --workspace --all-features
```

When modifying Candid interfaces, keep component README files, Candid definitions, and generated declarations in sync. Bug reports, integration feedback, and feature requests are welcome via [GitHub Issues](https://github.com/ldclabs/ic-cose/issues). Please include canister version, reproduction steps, and error messages to assist troubleshooting.

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
