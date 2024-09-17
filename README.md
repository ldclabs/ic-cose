# `IC-COSE`

⚙️ A decentralized COnfiguration service with Signing and Encryption on the Internet Computer.

💝 This project received a **$25k Developer Grant** from the [DFINITY Foundation](https://dfinity.org/grants).

## Overview

`ic-cose` is a fully open-source decentralized configuration service running on the Internet Computer. Based on the [CBOR Object Signing and Encryption (COSE, RFC9052)](https://datatracker.ietf.org/doc/html/rfc9052) standard, it offers centralized message signing and configuration data encryption. Configuration data is organized by namespaces and client subjects, supporting collaboration, fine-grained access control, and horizontal scalability. It can serve as a reliable and secure configuration center for various Web3 services and Web2 services with high data security and reliability requirements.

A imaginative use case is serving as a state persistence service for enclaves running in Trusted Execution Environments (TEEs), aiding in loading confidential data during startup and persisting confidential data states during runtime.

**Online Demo**: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=53cyg-yyaaa-aaaap-ahpua-cai

## Features

- [x] Supports message signing and configuration data encryption (COSE, Threshold ECDSA, Threshold Schnorr, VetKeys (TODO)).
- [x] Organizes configuration data by namespaces and client subjects with fine-grained access control.
- [ ] Supports horizontal scalability, WASM upgrade management, and Cycles recharge management.
- [ ] Serve as a state persistence service for enclaves, aiding in loading and persisting confidential data during startup and runtime.
- [ ] Can be used as a cluster management center for both Web3 and Web2 services.

## Who's using?

- [ICPanda](https://github.com/ldclabs/ic-panda): A decentralized Panda meme platform featuring E2E encrypted messaging, lucky draws, airdrops.

If you plan to use this project and have any questions, feel free to open an issue. I will address it as soon as possible.

## License
Copyright © 2024 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-cose` is licensed under the MIT License. See [LICENSE](LICENSE-MIT) for the full license text.