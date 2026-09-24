# `ic_wasm_canister` 技术对接文档

[English](README.md) · [简体中文](README.zh-CN.md)

`ic_wasm_canister` 是 Internet Computer 上的 WASM 制品仓库与 canister 部署管理服务。它提供模块发布、版本路径、创建与升级、批量调用及 cycles 补充，并支持基于不可变模板和预创建池的 provisioning 流程。

本文面向前端、后端、治理及业务 canister 开发者，描述当前仓库实现。准确类型以 [Candid 定义](ic_wasm_canister.did) 为准，行为依据 [API](src/api.rs)、[管理接口](src/api_admin.rs)、[provisioning 接口](src/api_provision.rs) 和 [存储实现](src/store/mod.rs)。部署实例可能运行其他版本，应先核对接口。

## 目录

- [`ic_wasm_canister` 技术对接文档](#ic_wasm_canister-技术对接文档)
  - [目录](#目录)
  - [1. 接入入口与协议约定](#1-接入入口与协议约定)
  - [2. 部署与最小调用流程](#2-部署与最小调用流程)
    - [2.1 部署管理服务](#21-部署管理服务)
    - [2.2 发布一个可安装的最小模块](#22-发布一个可安装的最小模块)
    - [2.3 分配角色](#23-分配角色)
  - [3. 角色与权限边界](#3-角色与权限边界)
  - [4. WASM 发布与版本路径](#4-wasm-发布与版本路径)
    - [4.1 Artifact hash 与 module hash](#41-artifact-hash-与-module-hash)
    - [4.2 发布接口](#42-发布接口)
    - [4.3 版本路径不是 semver](#43-版本路径不是-semver)
  - [5. 传统创建与部署接口](#5-传统创建与部署接口)
  - [6. Provisioning 模板与预创建池](#6-provisioning-模板与预创建池)
    - [6.1 模板字段与哈希](#61-模板字段与哈希)
    - [6.2 模板和池接口](#62-模板和池接口)
    - [6.3 补池与创建结果对账](#63-补池与创建结果对账)
  - [7. 预留安装与释放](#7-预留安装与释放)
    - [7.1 请求 ID 与过期时间](#71-请求-id-与过期时间)
    - [7.2 预留](#72-预留)
    - [7.3 安装](#73-安装)
    - [7.4 回执与恢复](#74-回执与恢复)
    - [7.5 释放](#75-释放)
  - [8. 精确升级与重试](#8-精确升级与重试)
  - [9. 查询日志与运行管理](#9-查询日志与运行管理)
    - [9.1 查询接口](#91-查询接口)
    - [9.2 批量调用](#92-批量调用)
    - [9.3 Cycles 补充](#93-cycles-补充)
  - [10. 客户端示例](#10-客户端示例)
    - [10.1 TypeScript：分块发布](#101-typescript分块发布)
    - [10.2 TypeScript：预留与安装](#102-typescript预留与安装)
    - [10.3 Rust：模板批准前计算绑定](#103-rust模板批准前计算绑定)
  - [11. 治理校验与服务升级](#11-治理校验与服务升级)
    - [11.1 校验方法](#111-校验方法)
    - [11.2 升级管理服务自身](#112-升级管理服务自身)
  - [12. 错误处理与对接限制](#12-错误处理与对接限制)
  - [License](#license)

## 1. 接入入口与协议约定

| 资源                                            | 用途                                                                         |
| ----------------------------------------------- | ---------------------------------------------------------------------------- |
| [ic_wasm_canister.did](ic_wasm_canister.did)    | 全部服务方法、请求、返回和 query 标记                                        |
| [生成绑定](../declarations/ic_wasm_canister)    | JavaScript IDL 与 TypeScript 类型，可用 `make bindings` 更新 |
| [Rust 类型](../ic_cose_types/src/types/wasm.rs) | 模板、哈希辅助方法、请求与回执结构                                           |
| [management.rs](src/management.rs)              | 创建、状态检查、直接安装与分块安装实现                                       |
| [dfx.json](../../dfx.json)                      | 仓库构建和本地部署配置                                                       |

对接需要网络 host、管理服务的 canister ID 和调用身份；目标业务 canister ID 与管理服务 ID 是两个不同对象。本文中的 controller 指管理服务的 IC controller 或配置的 `governance_canister`，目标 canister 的 controllers 则决定管理调用是否能执行。

业务方法返回 `variant { Ok : T; Err : text }`，无数据的成功结果为 `variant { Ok; Err : text }`。下文写作 `Result<T>`，`Result<()>` 表示无附加数据。Candid 文件中的 `Result_1` 等只是生成别名，不是协议错误码。

| Candid                      | TypeScript / 调用约定                                                  |
| --------------------------- | ---------------------------------------------------------------------- |
| `opt T`                     | `[]` 或 `[value]`；不是 JavaScript `null`                              |
| `blob`                      | 原始字节 `Uint8Array` / 绑定允许的 `number[]`；不是 hex 或 base64 文本 |
| 哈希、`request_id`          | Candid 虽写 `blob`，Rust 固定长度类型要求 **32 字节**                  |
| `principal`                 | `Principal` 对象                                                       |
| `nat`、`nat64`              | `bigint`；cycles 字段在服务端通常为 `u128`                             |
| `nat16`、`nat32`            | `number`                                                               |
| `WasmEncoding`              | `{ Raw: null }` 或 `{ Gzip: null }`，注意大小写                        |
| `vec record { text; blob }` | `[string, Uint8Array                                                   | number[]][]` |
| `Result<T>`                 | `{ Ok: value }` 或 `{ Err: message }`                                  |

业务时间戳（包括 `expires_at`、`deploy_at`、`created_at`、`updated_at`、`reserved_at`、`released_at`）均为 Unix **毫秒**。CanisterSettings / ProvisionSettings 的 `freezing_threshold` 则以**秒**计。InitArgs 的 `topup_threshold` 和 `topup_amount` 是 **cycles**。

`args`、`init_args` 是目标 canister 接收的 **Candid 二进制参数序列**。空参数 `()` 编码为 hex `4449444c0000`，不是空 blob，也不是 UTF-8 字符串 `"()"`。传统接口的 `args = null` 会自动使用这个空参数编码；provisioning 接口要求显式传字节。

除业务 `Err` 外，还要处理网络失败、guard 拒绝、管理 canister reject 和 trap。Query 读取通常无需 update 的共识流程；回执是服务状态记录，不是独立的跨系统支付或交付证明。

## 2. 部署与最小调用流程

### 2.1 部署管理服务

从仓库根目录执行，准备 Rust、`wasm32-unknown-unknown` target 和 `dfx`：

```bash
rustup target add wasm32-unknown-unknown
dfx start --background

RUSTFLAGS='--cfg=getrandom_backend="custom"' dfx deploy ic_wasm_canister --argument '(opt variant { Init = record {
  name = "Local WASM Manager";
  topup_threshold = 1_000_000_000_000;
  topup_amount = 5_000_000_000_000;
  governance_canister = null;
}})'

dfx canister call ic_wasm_canister get_state '()'
dfx canister call ic_wasm_canister get_canister_status '(null)'
```

首次安装必须传 `opt variant { Init = ... }`；虽然服务签名为 `opt ChainArgs`，安装时传 `null` 会 trap。`name` 是实例显示名称；topup 参数用于手动执行的 `admin_batch_topup`，**不会启动定时自动充值**。充值须以两个 0 禁用，或满足 `topup_amount > topup_threshold > 0`。Governance principal 必须非匿名，它获得应用层 controller 权限，但不会自动改变管理服务的 IC controllers。

### 2.2 发布一个可安装的最小模块

以下模块是仅含 WASM 标准头的空模块，用于本地验证发布与创建流程，不包含业务方法。用当前 controller 身份执行，无需先添加 manager：

```bash
dfx canister call ic_wasm_canister admin_add_wasm '(record {
  name = "demo";
  description = "Minimal module for local integration";
  encoding = opt variant { Raw };
  wasm = blob "\00\61\73\6d\01\00\00\00";
}, null)'

dfx canister call ic_wasm_canister get_state '()'

# 读取 demo 的 latest 并创建目标，成功返回目标 canister principal。
dfx canister call ic_wasm_canister admin_create_canister '("demo", null, null)'

dfx canister call ic_wasm_canister get_deployed_canisters '()'
dfx canister call ic_wasm_canister get_deployed_canisters_info '()'
dfx canister call ic_wasm_canister deployment_logs '("demo", null, opt 10)'
```

创建从管理服务余额支出固定 2T cycles，包含网络创建费；余额应足以创建和执行后续管理调用。相同模块重复发布会报 `wasm already exists`；查询 `get_state.latest_version` 或按本地计算的 artifact hash 调用 `get_wasm` 确认是否已经发布。

### 2.3 分配角色

```bash
export MYID=$(dfx identity get-principal)
dfx canister call ic_wasm_canister admin_add_managers "(vec { principal \"$MYID\" })"
dfx canister call ic_wasm_canister admin_add_committers "(vec { principal \"$MYID\" })"
dfx canister call ic_wasm_canister admin_add_provisioners "(vec { principal \"$MYID\" })"
```

这些命令演示角色接口，不要求给同一身份全部授权。Controller 本来就能执行对应操作；业务 canister 通常只需 provisioner。角色授权范围见下一节。

## 3. 角色与权限边界

| 操作                                        | Controller / governance | Manager | Committer | Provisioner  | 公众 |
| ------------------------------------------- | ----------------------- | ------- | --------- | ------------ | ---- |
| 修改 managers / committers / provisioners   | 是                      | 否      | 否        | 否           | 否   |
| 发布 WASM、上传 / 提交 / 清理块             | 是                      | 是      | 是        | 否           | 否   |
| 传统创建、`admin_deploy`、修改目标 settings | 是                      | 否      | 否        | 否           | 否   |
| 批量调用 / 充值、状态、部署日志、池清单     | 是                      | 是      | 否        | 否           | 否   |
| 添加 / 删除模板、对账池创建结果             | 是                      | 否      | 否        | 否           | 否   |
| `admin_refill_pool`                         | 是                      | 是      | 否        | 否           | 否   |
| 预留、安装、释放、`ensure_deployment`       | 是                      | 否      | 否        | 是           | 否   |
| 状态摘要、WASM、已部署摘要、模板            | 是                      | 是      | 是        | 是           | 是   |
| 请求回执                                    | 是                      | 否      | 否        | 仅自己的请求 | 否   |
| `validate_admin_*`                          | 是                      | 否      | 否        | 否           | 否   |

角色集合互相独立，不自动继承。例如 manager 不能仅凭该角色调用 `reserve_canister`，provisioner 不能调用 `get_canister_status`。角色增删输入必须非空、不含匿名 principal，并按集合去重。

对权限设计尤其需要了解以下实现边界：

- `request_id` 是**整个服务共享的命名空间**，但首次请求会持久绑定 owner 与原始 expires_at；其他 provisioner 不能读取、安装或释放该请求。旧版本中没有 owner 的记录会在首次合法重试时绑定当前 caller。
- Provisioner 的首次安装受模板约束；但 `ensure_deployment` 允许把已部署目标升级到**相同 wasm_name 下任何已发布 artifact**，不要求该 artifact 另有 provisioning 模板。发布权限因此会影响后续升级可选范围。
- Manager 的 `admin_batch_call` 能以管理服务身份调用已部署目标的任意 method，没有方法白名单；这不只是只读运维权限。
- WASM 制品、模板和角色摘要可公开读取。请求回执限 provisioner owner 或 controller；新部署日志只保存 args 的 SHA-256 和长度，不保存参数明文，旧日志中最多 8 KiB 的历史参数仍可能返回给 controller / manager。

角色接口均为 update，成功返回 `Result<()>`：`admin_add_managers`、`admin_remove_managers`、`admin_add_committers`、`admin_remove_committers`、`admin_add_provisioners`、`admin_remove_provisioners`。

## 4. WASM 发布与版本路径

### 4.1 Artifact hash 与 module hash

| 名称                              | 含义                                                                                                                 |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `artifact_hash` / `WasmInfo.hash` | 对实际存储和传输的制品字节计算 SHA-256                                                                               |
| `expected_module_hash`            | 希望管理 canister 在安装后报告的 module hash                                                                         |
| `ProvisionReceipt.module_hash`    | 成功检查后记录的管理 canister module hash                                                                            |
| `DeploymentInfo.wasm_hash`        | 本次发布制品的 artifact hash                                                                                         |
| `DeploymentInfo.prev_hash`        | 传统部署为检查到的前一 module hash；ensure_deployment 为请求声明的 expected_prev_module_hash；首次安装为全零 32 字节 |

对于 Raw 制品，通常 artifact hash 与安装模块 hash 相同。对于 Gzip，artifact hash 覆盖压缩文件字节，**不能假定与安装后的 module hash 相同**。应固定可复现的构建产物，并独立确认目标运行时报告的 module hash。

发布时会验证 name / description 边界、Raw 或解压后的 Gzip 是否为结构合法的 WebAssembly，并分别计算 artifact hash 与真实 module hash。Gzip 解压有 100 MiB 上限，制品本身最大 64 MiB；最终安装兼容性仍由管理 canister 决定。

### 4.2 发布接口

| 方法                                 | 模式                           | 参数 → `Ok`                                                                       |
| ------------------------------------ | ------------------------------ | --------------------------------------------------------------------------------- |
| `admin_add_wasm`                     | update                         | `(AddWasmInput, opt blob force_prev_hash) → ()`                                   |
| `admin_add_wasm_chunk`               | update                         | `(blob chunk) → blob`，返回 chunk SHA-256                                         |
| `admin_commit_wasm_chunks`           | update                         | `(CommitWasmChunksInput, opt blob force_prev_hash) → blob`，返回 artifact SHA-256 |
| `admin_clear_wasm_chunks`            | update                         | `() → nat64`，返回删除的块数量                                                    |
| `admin_remove_wasm`                  | update / controller            | `(blob artifact_hash) → ()`，仅可删除无引用且非 latest 的制品                     |
| `get_wasm`                           | query                          | `(blob artifact_hash) → WasmInfo`，仅适用于不超过 1.5 MB 的兼容读取               |
| `get_wasm_metadata`                  | query                          | `(blob artifact_hash) → WasmMetadata`                                             |
| `get_wasm_chunk`                     | query                          | `(blob artifact_hash, nat64 offset, nat32 take) → blob`，单次最多 1 MiB           |
| `list_latest_wasm_versions`          | query                          | `(opt text, opt nat32) → vec record { text; blob }`                               |
| `get_next_wasm_version`              | query                          | `(text, blob previous_module_hash) → WasmMetadata`                                |

`AddWasmInput = { name; description; wasm : blob; encoding : opt WasmEncoding }`，encoding 为空默认为 Raw。`WasmInfo` / `WasmMetadata` 同时返回 artifact `hash`、`module_hash` 和 `wasm_size`。

发布以 artifact hash 全局去重：相同字节即使换 name 或 description 也不能再次发布。发布成功更新 `latest_version[name]`；安全删除会检查 latest、版本边、模板、部署和请求引用。

分块发布流程：

1. 将制品按顺序切成每块 **1–1,048,576 字节**，用同一身份逐个调用 `admin_add_wasm_chunk`。
2. 保存返回的 32 字节 chunk hashes；相同 caller 上传相同块会返回原 hash，不重复占位。
3. 调用 `admin_commit_wasm_chunks({ name; description; encoding; chunk_hashes; artifact_hash }, force_prev_hash)`，其中 `chunk_hashes` 按原拼接顺序排列，`artifact_hash = SHA-256(完整制品字节)`。
4. 服务端拼接、校验总 hash，并执行与直接发布相同的去重和版本路径更新。
5. 成功提交后清除**该 caller 的全部暂存块**，包括未参与本次提交的块；失败时保留以便重试。放弃发布可调用 clear。

每个 caller 最多暂存 64 个不同块，拼接制品最大 **67,108,864 字节（64 MiB）**。不要让同一上传身份并发维护多个独立上传任务，否则提交或 clear 会清掉另一任务的块。制品仓库的暂存块与目标 canister 的 management chunk store 是两套存储。

大制品必须通过 metadata + chunk 接口下载；存储层按 1 MiB 稳定内存块保存，新安装也逐块读取，避免在 Wasm heap 中同时复制完整大制品。升级前已有的单体制品可增量迁移；大于直接安装阈值的旧制品必须先迁移，避免每上传一块都重复反序列化整份模块。

### 4.3 版本路径不是 semver

发布时建立 `(wasm_name, previous_module_hash) → new_artifact_hash`，previous 来自同名 latest；首次发布使用全零 module hash。同时将新 artifact hash 设为 latest。

`force_prev_hash` 是 artifact latest 的乐观锁：提供时必须精确等于该 name 当前 latest（首次发布为全零），且既有 `(name, previous_module_hash)` 后继不会被覆盖。同一 name 下重复当前或历史 module hash 的制品都会在写入前拒绝，包括重新压缩的旧模块，以防形成循环并阻断后续发布。

版本路径按 name 分区，因此不同 WASM 家族的全零起点不再冲突。旧全局路径在首次升级时迁移，并为每个历史 name 重建确定性的首版本边。

## 5. 传统创建与部署接口

| 方法                             | 参数 → `Ok`                                                                           | 行为                                          |
| -------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------- |
| `admin_create_canister`          | `(text wasm_name, opt CanisterSettings, opt blob args) → principal`                   | 当前子网创建并安装同名 latest                 |
| `admin_create_on`                | `(principal subnet, text wasm_name, opt CanisterSettings, opt blob args) → principal` | 通过 CMC 在指定 subnet 创建并安装 latest      |
| `admin_deploy`                   | `(DeployWasmInput, opt blob ignore_prev_hash) → ()`                                   | 空目标 install，已有模块目标 upgrade          |
| `admin_update_canister_settings` | `(UpdateSettingsArgs) → ()`                                                           | 修改已登记部署目标的 settings                 |
| `admin_handoff_canister`         | `(UpdateSettingsArgs) → ()`                                                           | 显式移交 controllers，成功后移出部署索引      |
| `admin_reconcile_deployment`     | `(principal, text, blob artifact_hash) → ()`                                          | 核验目标真实 module/controller 后修复成功记录 |

全部为 controller / governance 限定的 update。`DeployWasmInput = { name; canister; args : opt blob }`，`UpdateSettingsArgs = { canister_id; settings }`。

创建会自动把**管理服务本身**加入目标 controllers，保留显式提供的其余 controllers；不会自动把外部 caller 加进去。settings 为空时，目标仅由管理服务控制。每次创建附带固定 **2,000,000,000,000 cycles**，包括网络创建费，目标实际得到扣费后的余额。`admin_create_on` 依赖 CMC，普通本地 replica 未必提供该服务。

`CanisterSettings` 允许配置 controllers、compute_allocation、memory_allocation、freezing_threshold、reserved_cycles_limit、wasm_memory_limit、wasm_memory_threshold、log_visibility、log_memory_limit 和 environment_variables，均为可选字段。普通 settings 更新会拒绝匿名/重复 controller，并强制保留管理服务自身；真正移交控制权必须使用显式 handoff。

`admin_deploy` 要求第二参数显式提供目标预期的当前 module hash（空目标为全零），然后安装指定 name 的 latest；`null` 会被拒绝。前置状态检查、安装和结果 hash 核验都在同一目标互斥锁下完成。需要指定非 latest artifact 或可重放请求时使用 `ensure_deployment`。

传统路径没有 request_id。创建返回丢失时不能用业务 ID 找回创建结果；创建成功但安装失败时，错误包含 `canister <id> created, but install failed: ...`，并保存失败日志。不要再次创建，应记录该 ID、检查实际状态，并按需用 `admin_deploy` 重试。只有成功安装才进入 deployed_list。

传统部署会用仓库计算的真实 module hash 核验安装结果；成功写入稳定部署索引，失败也写入不含参数明文的审计日志。若安装已落地但本地记账失败，可用 reconcile 修复。

当 `wasm字节数 + args字节数 <= 1,500,000` 时直接 `install_code`，不触碰目标 chunk store；更大时先清空目标容量有限的 chunk store，再按 1 MiB 从 stable storage 分批并发上传，最后 `install_chunked_code`，安装尝试后再次尽力清理；服务内部按目标串行，但其他 controller 仍不应与它并行操作同一 chunk store。

## 6. Provisioning 模板与预创建池

Provisioning 将有可能丢失创建结果的步骤放在预创建池中，业务请求只绑定已登记的 canister：

```text
发布 artifact → 批准不可变模板 → admin_refill_pool（每次创建一个）
                                    ↓ Available
reserve_canister(request_id) → Reserved
                                    ├─ ensure_install → Installed
                                    └─ release_reservation → Available + Released 回执
```

本服务不验证支付、不收取业务价格，也不会按订单自动补池。业务方负责批准模板、支付和请求的关联、库存补充、重试及结果确认。

### 6.1 模板字段与哈希

| `ProvisionTemplate` 字段 | 类型 / 约束                                                      |
| ------------------------ | ---------------------------------------------------------------- |
| `id`、`wasm_name`        | `text`，1–64 字节，仅小写字母、数字、下划线                      |
| `artifact_hash`          | 已发布制品的 32 字节 SHA-256                                     |
| `expected_module_hash`   | 安装后期望的 32 字节 module hash                                 |
| `encoding`               | Raw / Gzip，必须与仓库制品元数据一致                             |
| `settings`               | 固定的 `ProvisionSettings`，见下文                               |
| `subnet`                 | `opt principal`，空值在当前子网创建；指定值通过 CMC              |
| `initial_cycles`         | `nat`，服务端 u128，必须大于 0；总创建预算，**包含创建费**       |
| `max_init_args_bytes`    | `nat32`，1–262,144 字节                                          |
| `pool_size`              | `nat16`，1–32；补池时的 Available 数量阈值，不是模板累计创建上限 |

`ProvisionSettings` 包含 `controllers : vec principal`，以及可选的 `compute_allocation`、`memory_allocation`、`freezing_threshold`、`wasm_memory_limit`（nat64）和 `reserved_cycles_limit`（nat）。其他 CanisterSettings 字段不通过模板配置。

Controllers 必须是按 principal 规范顺序排序的两个不同、非匿名身份，并包含管理服务自身；配置了 governance 时也必须包含它。资源分配还会检查 compute allocation 与 Wasm/内存上限。

`admin_add_provision_template(ProvisionTemplate) → Result<ProvisionTemplateInfo>` 校验类型约束、制品存在、wasm_name / encoding 一致，并要求 `expected_module_hash` 等于发布时解析出的真实 module hash。模板 ID 不可覆盖修改，需要为新配置创建新 ID。

返回的 `ProvisionTemplateInfo` 包含原模板、`hash`、`settings_hash`、`subnet_policy_hash`、`created_at`、`created_by`、`pool_status`、`available`、`reserved`、`installed`、`tombstones`。

哈希公式为 `SHA-256(canonical_CBOR([domain, value]))`，使用 [canonical_hash](../ic_cose_types/src/lib.rs) 的确定性 CBOR 编码：

| 返回字段             | domain                               | value                  |
| -------------------- | ------------------------------------ | ---------------------- |
| `hash`               | `ic-cose:provision-template:v1`      | 完整 ProvisionTemplate |
| `settings_hash`      | `ic-cose:provision-settings:v1`      | 完整 ProvisionSettings |
| `subnet_policy_hash` | `ic-cose:provision-subnet-policy:v1` | template.subnet        |

不要用 JSON hash 或 Candid 编码 hash 替代。独立实现还需匹配 Rust serde 的字节、principal、枚举、可选值及整数编码；数组顺序参与哈希，因此 controllers 交换顺序也改变模板 hash。Rust 可直接调用 `template.hash()`、`template.settings.hash()`、`template.subnet_policy_hash()`。请求可引用查询返回的 hash，但业务批准记录应固定对应模板内容及 hash，不能每次无条件追随最新查询结果。

### 6.2 模板和池接口

| 方法                              | 模式 / 权限                    | 参数 → `Ok`                                               |
| --------------------------------- | ------------------------------ | --------------------------------------------------------- |
| `admin_add_provision_template`    | update / controller            | `(ProvisionTemplate) → ProvisionTemplateInfo`             |
| `admin_remove_provision_template` | update / controller            | `(text id) → ()`                                          |
| `get_provision_template`          | query / 公开                   | `(text id) → ProvisionTemplateInfo`                       |
| `list_provision_templates`        | query / 公开                   | `() → vec ProvisionTemplateInfo`                          |
| `list_provision_templates_v2`     | query / 公开                   | `(opt text, opt nat32) → vec ProvisionTemplateInfo`       |
| `admin_refill_pool`               | update / controller 或 manager | `(text id) → principal`                                   |
| `admin_reconcile_pool`            | update / controller            | `(text id, opt principal found) → ()`                     |
| `list_provision_pool`             | query / controller 或 manager  | `(text id) → vec PoolCanisterInfo`                        |
| `list_provision_pool_v2`          | query / controller 或 manager  | `(text, opt principal, opt nat32) → vec PoolCanisterInfo` |

删除模板要求 available + reserved 为 0 且 pool_status 为 Idle；成功安装后池条目会移除，审计由请求、日志和部署索引承担，因此历史 installed 计数不会永久阻止删除。兼容 list 超过 1000 项会要求改用 v2 分页。

`PoolCanisterInfo` 返回 `canister`、`state`、`created_at`、`request_id`；`created_at` 保留补池登记时间，reserve 不再覆盖它。

### 6.3 补池与创建结果对账

池创建的 cycles 从管理服务余额支出；预留和安装接口没有按订单收取或转入 initial_cycles 的步骤。

`admin_refill_pool` **每次只创建一个目标**，不是一次补满。它先持久化 CreatePending，再调用管理 canister 或 CMC；仅在 Available 小于 pool_size 且 pool_status 为 Idle 时允许执行。

| pool_status / 创建结果 | 含义与后续处理                                                                  |
| ---------------------- | ------------------------------------------------------------------------------- |
| Idle                   | 无正在进行的创建，可以在库存不足时 refill                                       |
| CreatePending          | 创建正在进行，同模板新 refill 被拒绝                                            |
| 创建成功               | 登记目标为 Available，恢复 Idle                                                 |
| 确定未创建             | 恢复 Idle，返回错误；例如发送前余额不足、本地预算低于创建费或 CMC 明确 Refunded |
| CreateUnknown          | 可能创建成功但结果未知，后续 refill 被熔断                                      |

CreateUnknown 时，由治理方在服务外查明创建结果，再调用 `admin_reconcile_pool(id, found)`：提供 principal 表示接纳该目标为 Available；`null` 表示将创建记录为丢失，仅恢复 Idle。该接口只接受 CreateUnknown，不处理 CreatePending。

提供 `found` 时，reconcile 会查询目标并要求 module 为空、controllers 与模板完全一致，同时拒绝已经被其他池或部署索引跟踪的 principal。它仍无法凭链上信息证明该 canister 就是丢失创建的结果，治理方必须先在服务外完成归属确认；传 `null` 也不会销毁可能已经创建的未知目标。

## 7. 预留安装与释放

### 7.1 请求 ID 与过期时间

`reserve_canister`、`ensure_install`、`ensure_deployment` 都检查：

```text
当前时间 < expires_at <= 当前时间 + 3,600,000 毫秒
```

即使请求已经完成，入口仍先检查过期时间；过期后 owner 或 controller 仍可通过 `get_provision_receipt` 读取记录。服务不自动释放，但 controller / manager 可分页列出过期 reservation，controller 可在核验目标仍为空且 controllers 未漂移后回收。

原始 expires_at 与 owner 都写入请求绑定，重试不能刷新时间或换 caller。Released 记录按有限 tombstone 保留；Installed 记录可在至少 30 天后压缩成永久 request-id tombstone。业务方仍应持久化并永不复用 request_id。

安装/升级曾尝试但回调丢失或后置查询失败时，owner 或 controller 可调用 `reconcile_provision_request(request_id) → Result<ProvisionReceipt>`，该恢复接口不受原请求过期时间限制。它仅查询目标，不安装或升级代码，也不更改 owner、expires_at 或参数绑定。目标为预期模块时完成回执和索引；目标仍为空（预留安装）或仍是旧模块（升级）时记为 Failed，随后可释放空预留或用新的请求重新规划升级。它拒绝仍持有目标锁的在途操作；升级清除锁后通过新 attempt 拒绝旧回调。Controllers 漂移或意外模块会报错，需要治理处理。

### 7.2 预留

`reserve_canister(ReserveRequest) → Result<ReservationReceipt>` 是同步执行的 update，内部不创建 canister，也不执行跨 canister await。

| ReserveRequest            | 含义                          |
| ------------------------- | ----------------------------- |
| `request_id`              | 业务选定的全局唯一 32 字节 ID |
| `provision_template_id`   | 已批准模板 ID                 |
| `provision_template_hash` | 该模板的准确 hash             |
| `expires_at`              | 请求有效期，Unix 毫秒         |

首次请求从 Available 取一个目标并记录绑定；没有库存返回 `no available canister...`。相同 request_id 和模板重放返回原 canister，不多占库存。换模板会被拒绝，Released 请求在记录保留期间不能复用。

`ReservationReceipt` 还返回绑定的 owner 和 expires_at。这里的 initial_cycles 是模板承诺的**含创建费预算**，不是目标当前余额。

### 7.3 安装

`ensure_install(InstallRequest) → Result<ProvisionReceipt>` 的字段：

| 字段                                               | 校验 / 用途                                            |
| -------------------------------------------------- | ------------------------------------------------------ |
| `request_id`、`canister`                           | 必须与预留绑定一致                                     |
| `provision_template_id`、`provision_template_hash` | 必须与预留模板一致                                     |
| `expected_module_hash`                             | 必须与模板批准值一致                                   |
| `init_args`                                        | 目标初始化 Candid 字节，不超过模板上限                 |
| `init_args_hash`                                   | `SHA-256(init_args)`，必须精确匹配                     |
| `provision_spec_hash`                              | 业务规范的 32 字节绑定；服务原样保存，不解析或重新计算 |
| `expires_at`                                       | 有效请求时间窗口                                       |

首次安装尝试后绑定 args hash 和 provision_spec_hash；重试不能换参数，即使之前失败也一样。服务端将状态写为 InstallPending，再检查目标 controllers 集合是否与模板一致。如果目标为空则安装；如果已运行 expected module 则认定收敛成功；如果运行其他 module 则拒绝。安装后再次读取并比较 module hash。

这证明了记录中的部署目标与模块结果，不代表接口能从 module hash 反推出初始化参数确实执行过。若目标在外部被安装成同一 module，或者不同请求使用同一 module hash 但不同参数，不能把“hash 相同”当作参数执行证明。

### 7.4 回执与恢复

`get_provision_receipt(blob request_id) → Result<ProvisionReceipt>` 是 provisioner 限定 query，且除 controller 外只允许绑定 owner 读取。回执字段包括：

- request_id、owner、expires_at、stage、canister、wasm_name、created_at、updated_at、error。
- artifact_hash，以及成功检查后记录的 module_hash。
- provision_template_id / provision_template_hash：预留安装有值，精确升级为空。
- args_hash、provision_spec_hash：安装尝试后记录；升级没有 provision_spec_hash。
- prev_module_hash：升级时记录，首次安装为空。

| stage          | 调用方处理                                                         |
| -------------- | ------------------------------------------------------------------ |
| Reserved       | 已绑定目标，尚未开始安装；可安装或释放                             |
| InstallPending | 安装尝试在进行或等待后续恢复；不要并行释放或另发冲突安装           |
| Installed      | 该请求已成功记录；保存并核对目标、artifact 和 module hash          |
| Failed         | 记录了失败原因；**不保证目标仍为空或未升级**，可能只是结果检查失败 |
| Released       | 预留已归还；不要再使用该请求 ID                                    |

收到超时或 Err 后先查询回执；必要时用相同绑定参数重试 ensure。Installed 重放会再次读取目标 module hash，并在部署索引/日志缺失时修复记录；若外部 controller 已改变目标则返回错误。失败发生在前置参数校验时，可能没有新回执或不会更新已有 stage。

### 7.5 释放

`release_reservation(blob request_id, principal canister) → Result<ReleaseReceipt>` 返回 `{ request_id; canister; released_at }`。无需 expires_at，但要求 provisioner 权限，并执行：

1. 找到请求所属模板，读取目标的实际 controllers 与 module_hash。
2. 确认目标仍为空、controllers 集合与模板一致。
3. 拒绝 Installed 或 InstallPending 请求；核对绑定 canister。
4. 将目标归还 Available，将请求设为 Released 并记录释放 tombstone。

Failed 请求在满足空目标等条件时也可释放。Installed 目标不会再进入池。释放与安装共享目标互斥锁；已成功 Released 的重放直接返回原回执，不再被后续目标状态变化误伤。

Released 记录按模板保留 tombstone：过期阈值 **24 小时**、数量阈值 **4096**，在后续释放时清理，每次最多删除 64 条；不是精确的定时保留承诺，超过数量阈值可能提前淘汰。清理后原请求 query 可能 NotFound，仍应由业务系统永久禁止 ID 复用。

运维接口 `list_expired_reservations(opt request_id, opt take)` 分页发现过期未使用请求，`admin_release_expired_reservation(request_id)` 由 controller 执行与普通释放相同的实时空模块、controller 和互斥检查。

## 8. 精确升级与重试

`ensure_deployment(DeploymentRequest) → Result<ProvisionReceipt>` 为 provisioner / controller 可用的 update，针对已经登记在 deployed_list 的目标，不需要先 reserve。

| DeploymentRequest 字段      | 说明                                          |
| --------------------------- | --------------------------------------------- |
| `request_id`                | 本次升级独立的 32 字节 ID                     |
| `canister`                  | 已由本服务成功部署并登记的目标                |
| `wasm_name`                 | 必须与该目标最近登记的部署 name 相同          |
| `artifact_hash`             | 已发布、属于该 name 的精确制品                |
| `expected_module_hash`      | 期望安装结果                                  |
| `expected_prev_module_hash` | 预期目标目前运行的 module hash                |
| `args`、`args_hash`         | 升级 Candid 字节及 SHA-256；最多 262,144 字节 |
| `expires_at`                | 当前时间之后、最多 1 小时                     |

升级先校验参数和 artifact/name，再按 request_id 绑定完整参数并取得目标锁。相同请求若已 Installed，会核验目标仍运行预期 module 并修复缺失索引；否则读取目标当前 module hash：

- 等于 expected_module_hash：认为结果已经收敛，返回成功，不执行 upgrade hook。
- 等于 expected_prev_module_hash：执行 Upgrade，再检查结果 hash。
- 其他值或目标为空：拒绝，避免基于陈旧前置状态升级。

相同 request_id 的 canister、artifact、预期前后 module hash 和 args hash 必须保持不变。这里不沿用模板的 controllers 集合校验，实际执行仍需要管理服务有目标控制权限。

服务对传统部署、ensure install/deployment、释放、批量调用和 settings 变更使用同一套按目标互斥锁；前置 hash 检查和安装都在锁内，锁跨 `await` 保持且不会按墙钟自动过期。升级会清除瞬态锁，持久化的 attempt 编号可拒绝迟到 callback；其他 controller 的外部操作仍无法被本服务锁住，因此最终 module hash 核验不可省略。

本接口以“目标模块达到预期”为幂等判断，因此不能用于保证**同一 WASM、不同升级参数**的 hook 必定再次执行。需要运行同模块升级逻辑时应明确选择和审核合适的部署路径，而不是更换 request_id 后期待 ensure 强制执行。

## 9. 查询日志与运行管理

### 9.1 查询接口

| 方法                             | 模式 / 权限                    | 参数 → `Ok`                                                    |
| -------------------------------- | ------------------------------ | -------------------------------------------------------------- |
| `get_state`                      | query / 公开                   | `() → StateInfo`                                               |
| `get_deployed_canisters`         | query / 公开                   | `() → vec principal`                                           |
| `get_deployed_canisters_info`    | query / 公开                   | `() → vec DeploymentInfo`                                      |
| `get_deployed_canisters_v2`      | query / 公开                   | `(opt principal, opt nat32) → vec principal`                   |
| `get_deployed_canisters_info_v2` | query / 公开                   | `(opt principal, opt nat32) → vec DeploymentInfo`              |
| `get_canister_status`            | update / controller 或 manager | `(opt principal) → CanisterStatusResult`                       |
| `deployment_logs`                | query / controller 或 manager  | `(text name, opt nat prev, opt nat take) → vec DeploymentInfo` |

`StateInfo` 包含 name、managers、committers、provisioners、topup 配置、latest_version 摘要及其总数/截断标志、wasm/deployed/log 总数、governance_canister 和 low-memory 状态。Latest 超过 1000 项时用专用分页接口。

`get_canister_status(null)` 查询管理服务自身；指定其他目标必须已在 deployed_list 中。空池和仅预留的目标还未成功部署，不在该列表内。返回完整管理状态，包括运行状态、controllers / settings、cycles、module_hash、memory_size、内存指标及 query_stats；它是 update，不是 query。

`get_deployed_canisters_info` 返回每个目标最近一次成功登记的公开摘要，`args` 与 `args_hash` 固定为空；不是实时目标探测。记录仍包含 `log_id`、真实 `module_hash` 和 `args_size`，受限的日志接口才返回参数 hash。兼容全量接口超过 1000 项会要求使用 v2。

`deployment_logs` 通过稳定的 `(name, log_id)` 索引逆序分页，take 默认 10、最大 100。`prev` 是排除式全局 log ID；返回记录的 `log_id` 可直接作为下一页游标。超出 u64 的 nat 会明确报错。

传统创建 / 部署会记录安装成功或失败（到达日志步骤时）；ensure 成功会在同一无 `await` 的提交阶段衔接日志、请求完成和部署索引，失败主要通过请求回执的 error 排查。新日志不保存 args 明文。

### 9.2 批量调用

`admin_batch_call(vec principal canisters, text method, opt blob args) → Result<vec blob>`：

- 输入集合为空表示**全部已部署目标**；非空时每个目标必须已登记。
- 按 principal 排序、每批最多 7 个并发调用，不按输入原始顺序；所有目标使用相同 method 和原始 Candid 参数。每个调用使用 bounded wait（约 5 分钟），永不响应的目标只会得到该目标的错误，不会阻塞本服务升级；超时的调用仍可能已在目标上执行。
- 返回各目标原始 Candid 响应字节，应用按目标接口解码；目标返回业务 Err 仍属于成功的原始响应，不由管理服务自动识别。
- 最多 100 个目标，参数最多 256 KiB，单目标回复最多 64 KiB、聚合回复最多约 1.5 MB。`admin_batch_call_v2` 为每个目标返回 `{ canister; reply; error }`；兼容接口遇到任一失败会返回包含目标明细的整体 Err。此前副作用不会回滚，非幂等动作不可盲目整批重试。

### 9.3 Cycles 补充

`admin_batch_topup() → Result<nat>` 由 controller / manager 手动触发，返回本次成功流程累计转出的 cycles；`admin_batch_topup_v2` 返回逐目标结果，超过 100 个部署目标时使用 `admin_batch_topup_page(cursor, take)`。

- topup_threshold 或 topup_amount 为 0 时禁用；无已部署目标时返回错误。
- 分批检查 deployed_list，每批最多 7 个目标并发；目标余额 **小于等于 threshold** 时转入固定 amount。
- 先读取本页所有目标余额，再按真正低于阈值的数量一次性校验 `liquid balance >= threshold + amount × 待充值数`；随后每 7 个并发转账。
- 从管理服务余额支出，调用者传入的业务参数不用于代付。只预留或 Available 的池目标不在自动检查范围内。
- 全局 topup 锁阻止重入；所有目标都会独立报告结果，不因一个失败中断同批其余目标。兼容接口最终仍可能返回整体 Err，因此不能认为 Err 表示零支出。

## 10. 客户端示例

### 10.1 TypeScript：分块发布

使用与生成绑定匹配的 `@icp-sdk/core/agent`、身份和 IDL。以下 helper 适用于 Node.js，actor 应已带有 controller / manager / committer 身份；不要把所有输入文件直接塞入一次 Candid ingress。

```typescript
import { createHash } from 'node:crypto';
import type { _SERVICE } from '../declarations/ic_wasm_canister/ic_wasm_canister.did';

function unwrap<T>(result: { Ok: T } | { Err: string }): T {
  if ('Err' in result) throw new Error(result.Err);
  return result.Ok;
}
const sha256 = (bytes: Uint8Array): Uint8Array =>
  new Uint8Array(createHash('sha256').update(bytes).digest());

export async function publish(
  actor: _SERVICE,
  name: string,
  artifact: Uint8Array,
  gzip = false,
) {
  if (artifact.length === 0 || artifact.length > 64 * 1024 * 1024) {
    throw new Error('artifact must be 1 byte to 64 MiB');
  }
  const hashes: Uint8Array[] = [];
  for (let offset = 0; offset < artifact.length; offset += 1024 * 1024) {
    const chunk = artifact.slice(offset, offset + 1024 * 1024);
    hashes.push(new Uint8Array(unwrap(await actor.admin_add_wasm_chunk(chunk))));
  }
  const expected = sha256(artifact);
  const stored = unwrap(await actor.admin_commit_wasm_chunks({
    name,
    description: 'Published by integration client',
    encoding: [gzip ? { Gzip: null } : { Raw: null }],
    chunk_hashes: hashes,
    artifact_hash: expected,
  }, []));
  return new Uint8Array(stored);
}
```

提交结果丢失时先按 expected artifact hash 查询是否已发布，不能假设可以原样重放 commit：成功提交后块已经清空。示例没有自动 clear，避免失败时误删可恢复的上传数据；应用结束或放弃任务时再显式清理。

Actor 初始化方式：

```typescript
import { Actor, HttpAgent, type Identity } from '@icp-sdk/core/agent';
import { idlFactory } from '../declarations/ic_wasm_canister/ic_wasm_canister.did.js';
import type { _SERVICE } from '../declarations/ic_wasm_canister/ic_wasm_canister.did';

export async function connect(
  host: string, canisterId: string, identity: Identity, localReplica = false,
) {
  const agent = await HttpAgent.create({ host, identity });
  if (localReplica) await agent.fetchRootKey(); // 仅本地 replica
  return Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
}
```

导入路径按应用目录调整。生产连接应使用预期的信任根，不通过 fetchRootKey 从任意 host 建立信任。

### 10.2 TypeScript：预留与安装

前提：治理已发布制品、批准模板并补池；actor 具有 provisioner 权限。requestId、approvedTemplateHash 和 provisionSpecHash 必须由业务系统生成 / 固定并持久化，不应在每次重试时重新生成。下例复用上面的 unwrap / sha256。

```typescript
import type { _SERVICE } from '../declarations/ic_wasm_canister/ic_wasm_canister.did';

const sameBytes = (a: Uint8Array | number[], b: Uint8Array | number[]) =>
  a.length === b.length && Array.from(a).every((value, i) => value === b[i]);

export async function provision(
  actor: _SERVICE,
  templateId: string,
  approvedTemplateHash: Uint8Array,
  requestId: Uint8Array,
  provisionSpecHash: Uint8Array,
  initArgs: Uint8Array,
) {
  const info = unwrap(await actor.get_provision_template(templateId));
  if (!sameBytes(info.hash, approvedTemplateHash)) throw new Error('template changed');
  // 生产系统应在作业记录中保存本次时间窗口，并管理过期后的恢复。
  const expiresAt = BigInt(Date.now() + 10 * 60 * 1000);
  const reservation = unwrap(await actor.reserve_canister({
    request_id: requestId,
    provision_template_id: templateId,
    provision_template_hash: approvedTemplateHash,
    expires_at: expiresAt,
  }));
  // 持久化 reservation 后再安装；连接断开可通过 requestId 查询回执。
  const receipt = unwrap(await actor.ensure_install({
    request_id: requestId,
    canister: reservation.canister,
    provision_template_id: templateId,
    provision_template_hash: approvedTemplateHash,
    expected_module_hash: info.template.expected_module_hash,
    init_args: initArgs,
    init_args_hash: sha256(initArgs),
    provision_spec_hash: provisionSpecHash,
    expires_at: expiresAt,
  }));
  if (!('Installed' in receipt.stage) || receipt.module_hash.length !== 1 ||
      !sameBytes(receipt.module_hash[0], info.template.expected_module_hash)) {
    throw new Error('installation was not confirmed');
  }
  return receipt;
}
```

无参数目标的 `initArgs` 可以是 `Uint8Array.from([0x44, 0x49, 0x44, 0x4c, 0, 0])`。有参数时应使用目标 DID 对应的 Candid 编码器；不要对 JSON 或 Candid 文本直接计算 init_args_hash。

### 10.3 Rust：模板批准前计算绑定

仓库提供 `ic_cose_types::types::wasm` 数据类型；当前 `ic_cose::client::CoseSDK` 主要面向 COSE 服务，不提供这里完整的 WASM 管理专用 client。可使用 `ic-agent` 或 `CanisterCaller` 按 DID 调用，并区分传输错误与内层 `Result<T, String>`。

```rust
use candid::Principal;
use ic_cose_types::types::wasm::{ProvisionSettings, ProvisionTemplate, WasmEncoding};

pub fn template(
    manager: Principal,
    governance: Principal,
    artifact_hash: [u8; 32],
    module_hash: [u8; 32],
) -> Result<ProvisionTemplate, String> {
    let template = ProvisionTemplate {
        id: "demo_v1".into(),
        wasm_name: "demo".into(),
        artifact_hash: artifact_hash.into(),
        expected_module_hash: module_hash.into(),
        encoding: WasmEncoding::Raw,
        settings: ProvisionSettings {
            controllers: vec![manager, governance],
            ..Default::default()
        },
        subnet: None,
        initial_cycles: 2_000_000_000_000,
        max_init_args_bytes: 262_144,
        pool_size: 2,
    };
    template.validate()?;
    let _approved_hash = template.hash()?; // 持久化到治理 / 业务批准记录
    Ok(template)
}
```

这里 manager 是管理服务 canister ID，governance 是另一个治理 canister principal，不能传同一个值。此 helper 只构造和校验数据，不发布、批准或补池；预算还需适配实际目标子网。

## 11. 治理校验与服务升级

### 11.1 校验方法

所有 `validate_admin_*` 都是 controller / governance 限定 update，参数与对应执行方法相同，返回大小受限的可读摘要。它们不执行对应业务动作；校验通过不保证未来执行时状态仍相同。

| 校验接口                                                                 | 覆盖内容                                                                 |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| `validate_admin_add_managers` / `validate_admin_remove_managers`         | 非空且非匿名的 principal 集合                                            |
| `validate_admin_add_committers` / `validate_admin_remove_committers`     | 同上                                                                     |
| `validate_admin_add_provisioners` / `validate_admin_remove_provisioners` | 同上                                                                     |
| `validate_admin_add_wasm`                                                | WASM/gzip 结构、hash、去重及 latest CAS                                  |
| `validate_admin_create_canister` / `validate_admin_create_on`            | latest、controllers 与 args 大小；不创建目标                             |
| `validate_admin_deploy`                                                  | 目标 controller、显式前置 hash、latest 与 args 大小；会查询管理 canister |
| `validate_admin_batch_call`                                              | 目标、方法和参数大小；不执行目标方法                                     |
| `validate_admin_batch_topup`                                             | 充值开关与是否存在部署目标                                               |
| `validate_admin_update_canister_settings`                                | 目标、在途锁和 controller 保留策略                                       |
| `validate_admin_add_provision_template`                                  | 完整模板、artifact/name/encoding/module hash 和 controllers              |
| `validate_admin_remove_provision_template`                               | 模板引用计数和 pool 状态                                                 |
| `validate_admin_reconcile_pool`                                          | pool 状态及 found 目标真实 module/controllers；会查询管理 canister       |

分块上传、commit、clear、refill 和 ensure 没有对应的 validate 方法。

### 11.2 升级管理服务自身

安装接收 `Init`；升级接收 `opt variant { Upgrade = record { ... } }` 或 `null`。UpgradeArgs 还包含显式的 `clear_governance_canister`；`token_expiration` 为保留字段，任何非空值都会被拒绝，避免静默忽略配置。

自 0.12 起移除了旧单体制品存储、schema v1 迁移与部署日志索引补建：stable schema 低于 v2、仍有旧制品或按名日志索引未覆盖全部部署日志时，升级会 trap 并回滚。此类部署需先升级到 0.11，并在其上运行 `admin_migrate_legacy_wasm_artifact`（配合 `list_legacy_wasm_artifacts`）与 `admin_rebuild_log_index` 直至完成。

```bash
RUSTFLAGS='--cfg=getrandom_backend="custom"' dfx deploy ic_wasm_canister --mode upgrade --argument '(opt variant { Upgrade = record {
  name = null;
  topup_threshold = opt 1_000_000_000_000;
  topup_amount = opt 5_000_000_000_000;
  governance_canister = null;
  clear_governance_canister = null;
  token_expiration = null;
}})'
```

空选项保留旧值；清除治理身份需传 `clear_governance_canister = opt true`，且不能同时设置新 governance。Topup 必须同时为 0（禁用），或满足 `amount > threshold > 0`。

WASM metadata/块、版本路径、latest、部署索引、日志索引、模板、库存、请求、tombstones 和暂存 chunks 均使用 stable storage；旧 heap 索引只迁移一次。升级会把遗留 CreatePending 转为 CreateUnknown，并清除瞬态目标/topup 锁，让持久 request attempt 通过真实目标探测恢复。升级不是 reinstall。

`admin_handoff_canister` 与 `admin_forget_deployment` 会持久化退出管理标记，普通回执重试及恢复不会撤销该标记。只有 controller 通过成功的 `admin_deploy`、`admin_reconcile_deployment` 或接纳空目标的 `admin_reconcile_pool` 核验并显式重新接管后，才会恢复管理。

运行跨升级回归测试：先 `make build-wasm`，再设置 `POCKET_IC_BIN` 为本地 PocketIC 16 server 路径，执行 `cargo test -p ic_wasm_canister --test canister_runtime -- --ignored`。`CANISTER_WASM_DIR` 可改为 wasm64 release 目录，使用相同测试验证 wasm64 的签名认证和 stable memory 持久化。运行时测试默认 ignored，普通单元测试不依赖 PocketIC server。

## 12. 错误处理与对接限制

| 错误 / 现象                                                                 | 排查与处理                                                 |
| --------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `user is not a controller/manager/...`                                      | 区分当前调用身份和角色；guard 拒绝可能不以业务 Result 返回 |
| `wasm already exists`                                                       | artifact 全局去重；查询该 hash 确认已有发布                |
| `force_prev_hash is stale`                                                  | 发布 CAS 不是该 name 当前 latest；重新读取并决定是否重基   |
| `no next version`                                                           | 该 `(name, previous_module_hash)` 没有后继                 |
| `artifact hash ... does not match the declared ...`                         | 拼接顺序、原始文件或预期 SHA-256 不一致                    |
| `chunk ... not staged`                                                      | 使用了不同 caller、已 clear / commit 或漏传块              |
| `provision template ... hash mismatch`                                      | 请求引用的批准 hash 与模板不一致                           |
| `no available canister in the pool ...`                                     | 补充池库存；reserve 不会自动创建                           |
| `a pool create is already in flight`                                        | CreatePending；等待并核对，不重复创建                      |
| `pool refill is circuit-broken ...`                                         | CreateUnknown；治理对账后才能继续                          |
| `request epoch has expired` / `... more than 3600000ms ...`                 | 检查毫秒时间、系统时钟和窗口；先查询已有回执               |
| `request id already bound ...`                                              | 同一 ID 被用于不同模板、参数或目标；恢复原作业记录         |
| `init_args_hash does not match init_args` / `args_hash does not match args` | 必须对实际上传的 Candid 字节计算 SHA-256                   |
| `canister controllers no longer match the template`                         | 目标控制集合漂移或模板配置错误                             |
| `prev module hash mismatch ...`                                             | 精确升级前置状态不一致；不能盲目覆盖期望 hash 后重试       |
| `installed module hash ... does not match the approved ...`                 | 已安装结果不符；检查真实 module，不能假定安装未发生        |
| `canister is not empty and cannot be released`                              | 不得归还池；查询回执与目标实际状态                         |
| `an install is in flight for this request`                                  | InstallPending 不能释放，先完成或恢复安装                  |
| `canister topup is disabled` / `no canister deployed`                       | topup 配置为 0 或没有已登记目标                            |
| `balance ... is less than threshold ...`                                    | 管理服务余额不满足整批预留要求                             |

接口没有统一数字错误码，不宜只靠字符串全文匹配控制关键业务。重试至少区分：参数 / 权限错误、未知执行结果、可恢复的失败回执，以及已经完成的历史结果。

接入时还应遵守这些当前实现约束：

- 请求幂等性用于恢复相同业务绑定，不能代替付款校验或初始化副作用验证；owner 隔离和服务内部目标互斥也无法约束其他 controller 的外部操作。
- 控制权限或真实状态可能被其他 controller 改变；列表与历史回执不会主动刷新实际部署状态。
- 大型 WASM、latest、库存、模板和已部署清单都有分页接口；兼容全量接口会在 1000 项处拒绝并提示 v2。
- 成功请求至少保留 30 天后可由 controller 压缩为永久 request-id tombstone；部署日志保留，需规划 stable memory 和运维成本。
- 触发 low-Wasm-memory 后，发布、建池、角色/模板扩容等新增写入会保护性拒绝；释放、清理和显式 controller 恢复接口仍可用。
- 直接发布、分块提交和模板批准均不等于目标部署成功；业务交付应检查 ensure 回执以及应用自身需要的初始化结果。

### 有界请求维护

`list_expired_reservations_page(prev, scan_limit)` 与 `admin_archive_completed_requests_page(before_ms, prev, scan_limit)` 返回 `{ items; next_cursor }`。每次最多扫描 1000 条记录，包括不匹配项；即使 items 为空也应继续使用 next_cursor，直到其为空。归档接口的 items 是本次归档的请求 ID，30 天保留要求不变。旧扫描接口在请求总数超过 1000 时要求使用分页版本。

运行 `make build-did` 可提取接口，并统一生成主目录和示例的绑定。Actor 工厂保留调用方 agent 的 root key；本地环境由调用方显式 `await agent.fetchRootKey()` 后再创建 actor。


### 存储 cycles 测量

`storage_operations_report_cycle_costs` 测试输出 256 KiB / 1 MiB 配置创建、更新、删除，以及 100 / 3999 成员集合中单成员增删的 cycles。执行 `POCKET_IC_BIN=/path/to/pocket-ic-16 cargo test -p ic_wasm_canister --test canister_runtime storage_operations_report_cycle_costs -- --ignored --nocapture`；将 `CANISTER_WASM_DIR` 指向单独构建的旧版本，可以对比相同负载。

## License

Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-cose` is licensed under the MIT License. See [LICENSE](../../LICENSE-MIT).
