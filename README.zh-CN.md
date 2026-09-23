# IC-COSE

[English](README.md) · [简体中文](README.zh-CN.md)

Internet Computer 上的配置、签名、加密与 canister 部署管理服务。

项目名称来自 **COnfiguration service with Signing and Encryption**，获得过 [DFINITY Foundation](https://dfinity.org/grants) 的 **25,000 美元开发者资助**。

[配置与密钥服务对接文档](src/ic_cose_canister/README.zh-CN.md) · [WASM 部署管理对接文档](src/ic_wasm_canister/README.zh-CN.md) · [Rust SDK](src/ic_cose/README.md)

## 项目概览

IC-COSE 提供两个可独立部署的 canister，以及配套 Rust SDK 和共享类型库：

- **`ic_cose_canister`**：按命名空间和 subject 管理配置，提供版本记录、访问控制、Threshold ECDSA / Schnorr 签名、加密密钥获取、业务身份令牌及固定身份委托。
- **`ic_wasm_canister`**：保存 WASM 制品、管理创建与升级、执行批量调用和 cycles 补充，并通过不可变模板、预创建池和请求回执支持可恢复的 provisioning 流程。

配置加密在客户端完成，服务支持保存明文或 COSE（CBOR Object Signing and Encryption）加密封装。部署管理则负责制品与目标 canister 的操作记录；业务支付、租户授权、作业调度和并发协调由接入方实现。

## 核心能力

### 配置、签名与加密

| 能力           | 对接方式                                                                            |
| -------------- | ----------------------------------------------------------------------------------- |
| 配置隔离与授权 | Namespace、subject、服务端 / 个人配置区域，以及 manager、auditor、user、reader 角色 |
| 配置版本       | 当前版本读取、携带版本的修改、历史 payload / DEK 归档                               |
| 消息签名       | Threshold ECDSA secp256k1、Schnorr Ed25519 / BIP340，支持命名空间派生路径           |
| 加密密钥       | 通过 X25519 ECDH 获取服务端部分 KEK，或获取传输加密的 VetKey 并在客户端验证         |
| 业务身份       | Schnorr 签名的 COSE_Sign1 / CWT，包含身份、受众、有效期和权限声明                   |
| 固定身份       | 为命名空间内的固定名称配置 delegators，签发 IC session delegation                   |

权限与可见性有明确边界：公开命名空间允许读取配置内容，但不自动授予密钥获取或签名权限；命名空间内的签名派生路径也不自动按 caller 隔离。完整规则见 [配置服务技术对接文档](src/ic_cose_canister/README.zh-CN.md)。

### WASM 与部署管理

| 能力                | 对接方式                                                           |
| ------------------- | ------------------------------------------------------------------ |
| 制品仓库            | 按 SHA-256 保存 Raw / Gzip 制品，支持直接发布和分块上传            |
| 传统部署            | 创建目标、部署下一版本或 latest、更新目标 settings                 |
| 模板化 provisioning | 批准固定制品、module hash、controllers、子网和预算，再预创建池目标 |
| 请求恢复            | 用 request_id 预留、安装、查询回执或释放未安装的目标               |
| 精确升级            | 固定 artifact 与预期前后 module hash，支持相同请求的结果恢复       |
| 运行管理            | 查询部署记录、批量调用已登记目标、手动按余额阈值补充 cycles        |

预创建将创建结果未知的处理移出业务预留路径；request_id 帮助恢复绑定，但不代替租户权限或目标操作互斥。升级的前置 hash 检查不是跨调用的原子 CAS；Gzip 制品的 artifact hash 也不能直接当作安装后的 module hash。详见 [部署管理技术对接文档](src/ic_wasm_canister/README.zh-CN.md)。

## 组件与文档

| 组件                                       | 职责                                              | 对接入口                                                                                               |
| ------------------------------------------ | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`ic_cose_canister`](src/ic_cose_canister) | 配置、签名、加密密钥与身份服务                    | [技术文档](src/ic_cose_canister/README.zh-CN.md) · [Candid](src/ic_cose_canister/ic_cose_canister.did) |
| [`ic_wasm_canister`](src/ic_wasm_canister) | WASM 制品、部署、provisioning 与运维              | [技术文档](src/ic_wasm_canister/README.zh-CN.md) · [Candid](src/ic_wasm_canister/ic_wasm_canister.did) |
| [`ic_cose`](src/ic_cose)                   | COSE 服务的 Rust 客户端 SDK                       | [说明](src/ic_cose/README.md) · [客户端实现](src/ic_cose/src/client.rs)                                |
| [`ic_cose_types`](src/ic_cose_types)       | 两类服务的共享类型、COSE 工具与确定性哈希辅助方法 | [说明](src/ic_cose_types/README.md) · [类型定义](src/ic_cose_types/src/types)                          |

`ic_cose::client::CoseSDK` 主要面向 COSE 服务；WASM 管理接口可使用其 Candid 绑定或通用 canister 调用工具接入，不应假定该 SDK 已封装全部部署接口。

## 快速开始

### 1. 选择需要的服务

- 保存配置、管理加密密钥或请求签名：从 [COSE 部署与最小调用流程](src/ic_cose_canister/README.zh-CN.md#2-部署与最小调用流程) 开始。
- 发布和管理业务 canister：从 [WASM 部署与最小调用流程](src/ic_wasm_canister/README.zh-CN.md#2-部署与最小调用流程) 开始。
- 为业务请求提供模板化部署：先阅读 [模板与预创建池](src/ic_wasm_canister/README.zh-CN.md#6-provisioning-模板与预创建池)，再对接 [预留、安装与释放](src/ic_wasm_canister/README.zh-CN.md#7-预留安装与释放)。

两个服务不要求一起部署。首次安装都必须提供对应的 `Init` 参数；不要直接用无参数的 `dfx deploy` 代替组件文档中的初始化步骤。

### 2. 准备本地环境

准备 Rust、`dfx` 和 WASM target，在仓库根目录执行：

```bash
rustup target add wasm32-unknown-unknown
dfx start --background
```

随后执行所选组件文档中的部署命令。COSE 的阈值签名 / VetKD 功能还要求目标 replica 或子网支持配置的算法与 key ID；WASM 创建和运维则需要管理服务具备足够 cycles 及目标控制权限。

### 3. 接入客户端

| 客户端                  | 入口                                                                                                                                               |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rust                    | [COSE SDK 示例](src/ic_cose_canister/README.zh-CN.md#10-客户端接入示例)、[WASM 模板与调用说明](src/ic_wasm_canister/README.zh-CN.md#10-客户端示例) |
| TypeScript / JavaScript | [COSE 绑定](src/declarations/ic_cose_canister)，[WASM 绑定](src/declarations/ic_wasm_canister)，使用带身份的 Actor 调用                            |
| 其他 canister / 语言    | 按对应 Candid 编码参数，处理业务 Result 与底层调用错误                                                                                             |
| VetKeys 实验            | [Rust 示例](src/ic_cose/examples/vetkeys.rs)、[前端示例](examples/vetkeys)                                                                         |

部署后可按需重新生成绑定：

```bash
make bindings
```

示例中的演示身份和密钥仅供实验。客户端应持久化实际业务路径、部署请求 ID 和已批准模板 hash，并核对当前部署实例的接口版本。

## 适用场景

- **应用配置与密钥管理**：为 Web3 / Web2 服务保存版本化配置、加密数据及解密所需的授权信息。
- **TEE 状态持久化**：让 enclave 在启动时加载配置和机密数据，在运行期间保存加密状态；enclave 身份与授权流程由应用集成。
- **服务身份与签名**：为业务消息签名，或将稳定的 canister signature 身份委托给短期会话密钥。
- **平台 canister 交付与运维**：使用固定模板预留和安装目标，并通过回执恢复部署作业、管理升级与 cycles 补充。

## 使用案例

- [dMsg.net](https://dmsg.net)：运行在 Internet Computer 上的端到端加密通信应用，使用 `ic_cose_canister` 保存用户的加密密钥。
- [IC-TEE](https://github.com/ldclabs/ic-tee)：将 TEE 与 Internet Computer 集成，使用 `ic_cose_canister` 保存配置、TLS 证书 / 私钥和根密钥等机密数据。
- [Anda](https://github.com/ldclabs/anda)：结合 ICP 与 TEE 的 Rust AI agent 框架，使用 `ic_cose_canister` 保存 agent 配置。

## 开发与贡献

仓库是包含上述四个组件的 Rust workspace。与 [CI](.github/workflows/test.yml) 一致的检查命令为：

```bash
cargo clippy --all-targets --all-features
cargo test --workspace --all-features
```

修改接口时，应同步核对组件 README、Candid 和生成绑定。遇到问题或希望反馈接入案例，欢迎提交 [Issue](https://github.com/ldclabs/ic-cose/issues)；描述目标组件、版本、调用方法和可复现行为有助于排查。

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

按照 workspace 的许可证声明，项目采用 **MIT OR Apache-2.0** 双许可证，可任选其一。详见 [MIT License](LICENSE-MIT) 与 [Apache License 2.0](LICENSE-APACHE)。
