# `ic_cose_canister` 技术对接文档

[English](README.md) · [简体中文](README.zh-CN.md)

`ic_cose_canister` 是部署在 Internet Computer 上的配置、签名与加密服务。业务以命名空间隔离配置和权限，可以保存明文或客户端加密的配置、调用 Threshold ECDSA / Schnorr 签名、获取加密传输的密钥材料，以及签发固定身份的 IC delegation。

本文面向前端、后端和 canister 开发者，描述当前仓库实现。接口的准确类型以 [Candid 定义](ic_cose_canister.did) 为准，权限和状态行为以 [store 模块](src/store/mod.rs) 为准。部署实例可能运行不同版本，接入前应核对其 Candid。

## 目录

- [`ic_cose_canister` 技术对接文档](#ic_cose_canister-技术对接文档)
  - [目录](#目录)
  - [1. 接入入口与调用约定](#1-接入入口与调用约定)
  - [2. 部署与最小调用流程](#2-部署与最小调用流程)
    - [2.1 初始化](#21-初始化)
    - [2.2 建立角色与命名空间](#22-建立角色与命名空间)
    - [2.3 创建、读取、更新和读取历史](#23-创建读取更新和读取历史)
  - [3. 数据模型与权限](#3-数据模型与权限)
    - [3.1 命名空间与配置路径](#31-命名空间与配置路径)
    - [3.2 角色不是继承关系](#32-角色不是继承关系)
    - [3.3 可见性、状态与密钥权限](#33-可见性状态与密钥权限)
  - [4. 命名空间接口](#4-命名空间接口)
  - [5. 配置接口与版本管理](#5-配置接口与版本管理)
  - [6. ECDSA 与 Schnorr 签名](#6-ecdsa-与-schnorr-签名)
  - [7. 加密配置与密钥获取](#7-加密配置与密钥获取)
    - [7.1 加密数据格式](#71-加密数据格式)
    - [7.2 ECDH 获取部分 KEK](#72-ecdh-获取部分-kek)
    - [7.3 VetKeys](#73-vetkeys)
  - [8. 身份令牌与固定身份委托](#8-身份令牌与固定身份委托)
    - [8.1 `schnorr_sign_identity`：业务身份 CWT](#81-schnorr_sign_identity业务身份-cwt)
    - [8.2 固定身份接口](#82-固定身份接口)
    - [8.3 申请会话 delegation](#83-申请会话-delegation)
  - [9. 管理与治理接口](#9-管理与治理接口)
  - [10. 客户端接入示例](#10-客户端接入示例)
    - [10.1 TypeScript Actor](#101-typescript-actor)
    - [10.2 Rust SDK](#102-rust-sdk)
  - [11. 错误处理与运行约束](#11-错误处理与运行约束)
    - [Cycles 与资源](#cycles-与资源)
  - [License](#license)

## 1. 接入入口与调用约定

| 资源                         | 位置 / 用途                                                                               |
| ---------------------------- | ----------------------------------------------------------------------------------------- |
| Canister Candid              | [ic_cose_canister.did](ic_cose_canister.did)，包含全部请求、响应和 query 标记             |
| JavaScript / TypeScript 绑定 | [生成目录](../declarations/ic_cose_canister)，用 `make bindings` 重新生成 |
| Rust SDK                     | [ic_cose](../ic_cose)，核心接口为 `client::CoseSDK`，实现为 `client::Client`              |
| Rust 数据类型与 COSE 工具    | [ic_cose_types](../ic_cose_types)                                                         |
| VetKeys 示例                 | [Rust 示例](../ic_cose/examples/vetkeys.rs)、[前端示例](../../examples/vetkeys)           |
| 仓库原有演示实例             | `53cyg-yyaaa-aaaap-ahpua-cai`，仅作探索入口，不保证版本或可用性                           |

对接需要确定网络 host、canister ID、调用身份和 namespace。调用身份决定 `caller`；它也决定 `subject = null` 时访问哪一个配置。

所有业务接口返回 Candid `variant { Ok : T; Err : text }`，无数据的成功结果为 `variant { Ok; Err : text }`。下文用 `Result<T>` 简写；Candid 中 `Result_1` 等名称只是生成的类型别名。除了业务 `Err`，还必须处理网络失败、canister reject、guard 拒绝和 trap。

| Candid                                 | JavaScript / TypeScript 绑定                             |
| -------------------------------------- | -------------------------------------------------------- |
| `opt T`                                | `[]` 表示空，`[value]` 表示有值；不是 `null`             |
| `blob`                                 | `Uint8Array` 或绑定允许的 `number[]`；不是十六进制字符串 |
| `principal`                            | `Principal` 对象；不是文本                               |
| `nat`、`nat64`                         | `bigint`，例如 `1n`                                      |
| `nat32`、`nat8`、`int8`                | `number`                                                 |
| `vec record { text; text }`            | `[string, string][]`                                     |
| `variant { ed25519; bip340secp256k1 }` | `{ ed25519: null }` 或 `{ bip340secp256k1: null }`       |
| `Result<T>`                            | `{ Ok: value }` 或 `{ Err: message }`                    |

配置与命名空间的 `created_at`、`updated_at`、`archived_at` 是 Unix **毫秒**；delegation 的 `expiration` 是 Unix **纳秒**；CWT 时间声明是 Unix **秒**。

`query` 通常用于读取；`update` 需要等待执行完成。服务端特别建议对 `setting_get` 使用 update 调用，以使读取经过共识；Rust SDK 的 `setting_get` 当前仍使用 query，需要该保证时应显式走 `canister_update`。`get_delegation` 依赖 query 的数据证书，必须按 query 调用。

## 2. 部署与最小调用流程

### 2.1 初始化

从仓库根目录执行，准备好 Rust、`wasm32-unknown-unknown` target 和 `dfx`。以下密钥名称是本地配置示例，目标 replica 必须支持对应算法和 key ID；初始化成功不代表所有阈值密钥已经就绪。

```bash
rustup target add wasm32-unknown-unknown
dfx start --background

RUSTFLAGS='--cfg=getrandom_backend="custom"' dfx deploy ic_cose_canister --argument '(opt variant { Init = record {
  name = "Local IC COSE";
  ecdsa_key_name = "dfx_test_key";
  schnorr_key_name = "dfx_test_key";
  vetkd_key_name = "dfx_test_key";
  allowed_apis = vec {};
  subnet_size = 0;
  freezing_threshold = 1_000_000_000_000;
  governance_canister = null;
  vetkd_context_version = opt 2;
}})'

dfx canister call ic_cose_canister state_get_info '()'
```

安装虽然接收 `opt InstallArgs`，但首次安装必须传入 `opt variant { Init = ... }`；传 `null` 会触发 `init args is missing`。三个 key name 是管理 canister 的密钥标识，不是私钥。

`InitArgs` 字段说明：

| 字段                                                     | 类型            | 用途                                                                                  |
| -------------------------------------------------------- | --------------- | ------------------------------------------------------------------------------------- |
| `name`                                                   | `text`          | 实例显示名称，与 namespace 名称无关                                                   |
| `ecdsa_key_name` / `schnorr_key_name` / `vetkd_key_name` | `text`          | 目标网络提供的各算法 key ID 名称                                                      |
| `allowed_apis`                                           | `vec text`      | 业务 update 白名单，空集合允许全部                                                    |
| `governance_canister`                                    | `opt principal` | 获得应用层 controller 权限的治理 canister，不会改变 IC controller 设置                |
| `subnet_size`                                            | `nat64`         | 保存的子网大小参数，当前不控制业务计费或充值                                          |
| `freezing_threshold`                                     | `nat64`         | 应用层保留 cycles；发起付费管理调用前要求 liquid balance 至少覆盖该阈值和本次调用成本 |
| `vetkd_context_version`                                  | `opt nat8`      | 新安装默认 2（长度分隔、域分隔）；1 仅用于兼容旧派生 context                          |

初始化后定时任务获取 ECDSA、Schnorr 两种算法的根公钥和内部随机 IV；失败会以 30 秒起步、最长 1 小时的指数退避重试，且不会覆盖已成功的公钥或 IV。用以下接口检查公钥是否就绪；VetKD 公钥按请求获取，不在启动时缓存：

```bash
dfx canister call ic_cose_canister ecdsa_public_key '(null)'
dfx canister call ic_cose_canister schnorr_public_key '(variant { ed25519 }, null)'
dfx canister call ic_cose_canister schnorr_public_key '(variant { bip340secp256k1 }, null)'
```

### 2.2 建立角色与命名空间

Controller / governance 或全局 manager 都可创建 namespace。通常仍建议把日常运维身份加入**全局 managers**，把 IC controller 留作恢复通道。

```bash
export MYID=$(dfx identity get-principal)
dfx canister call ic_cose_canister admin_add_managers "(vec { principal \"$MYID\" })"

dfx canister call ic_cose_canister admin_create_namespace "(record {
  name = \"testing\";
  visibility = 0;
  desc = opt \"Integration example\";
  max_payload_size = opt 1_000_000;
  session_expires_in_ms = opt 86_400_000;
  managers = vec { principal \"$MYID\" };
  auditors = vec {};
  users = vec { principal \"$MYID\" };
})"
```

此例同时授予 namespace manager 和 user，便于分别操作服务端配置与个人配置；生产环境应根据业务需要分配。

### 2.3 创建、读取、更新和读取历史

以下使用服务端配置 `user_owned = false`，`subject = null` 自动取当前 caller。`key` 是原始字节，这里用 UTF-8 文本 `app_config`。

```bash
# 创建必须使用 version = 0，成功后返回 version = 1。
dfx canister call ic_cose_canister setting_create '(record {
  ns = "testing"; user_owned = false; subject = null;
  key = blob "app_config"; version = 0;
}, record {
  payload = opt blob "hello"; dek = null; status = opt 0;
  desc = opt "Example config";
  tags = opt vec { record { "env"; "local" } };
})'

# version = 0 读取最新值；--update 使该 query 方法经过共识执行。
dfx canister call ic_cose_canister setting_get '(record {
  ns = "testing"; user_owned = false; subject = null;
  key = blob "app_config"; version = 0;
})' --update

# 写入携带当前版本 1，成功后版本变为 2。
dfx canister call ic_cose_canister setting_update_payload '(record {
  ns = "testing"; user_owned = false; subject = null;
  key = blob "app_config"; version = 1;
}, record {
  payload = opt blob "hello v2"; dek = null;
  status = null; deprecate_current = opt false;
})'

# 历史 payload 通过专用接口读取。
dfx canister call ic_cose_canister setting_get_archived_payload '(record {
  ns = "testing"; user_owned = false; subject = null;
  key = blob "app_config"; version = 1;
})'
```

重复创建同一路径会报 `already exists`。跨身份读取时显式指定原始 subject，否则 `null` 会变成新 caller，得到另一条路径。

## 3. 数据模型与权限

### 3.1 命名空间与配置路径

Namespace 是业务权限边界，包含角色集合、可见性、状态、payload 大小限制和固定身份授权表。

```candid
type SettingPath = record {
  ns : text;
  user_owned : bool;
  subject : opt principal;
  key : blob;
  version : nat32;
};
```

逻辑配置由 `(ns, user_owned, subject, key)` 唯一确定，`version` 用于当前版本校验或历史读取。`user_owned = false` 与 `true` 是不同的存储区域，即使其余字段相同也不是同一条配置。

| 字段 / 对象                     | 约束与默认值                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------ |
| Namespace `name`                | 1–64 字节，仅 `a-z`、`0-9`、`_`；不可重命名                                                |
| Setting `key`                   | 1–64 字节，允许任意二进制；无需满足 namespace 命名规则                                     |
| `subject`                       | `null` 取 caller；可以显式指定其他 principal，但不会因此获得权限                           |
| `desc`                          | UTF-8 字节长度不超过 1024；创建时为空则保存空字符串                                        |
| `tags`                          | 最多 32 项；key 遵循 namespace 命名规则，value 不超过 256 字节                             |
| `max_payload_size`              | 1–2,000,000 字节，默认 2,000,000；检查存储的 payload 字节数，包含加密封装开销              |
| `dek`                           | 最多 3072 字节，必须是可解析的 COSE_Encrypt0                                               |
| `session_expires_in_ms`         | 默认 86,400,000（1 天），最大 31,536,000,000（365 天）；0 禁用新的固定身份委托             |
| 成员集合                        | 去重；创建 namespace 时 managers 必须非空，auditors / users 可以为空；不允许匿名 principal |
| 增删成员 / readers / delegators | 输入集合必须非空且不能包含匿名 principal                                                   |

### 3.2 角色不是继承关系

| 角色                                       | 实际权限                                                                         |
| ------------------------------------------ | -------------------------------------------------------------------------------- |
| IC controller / 配置的 governance canister | 修改全局 managers、auditors、allowed_apis；不会自动获得 namespace 数据权限       |
| 全局 manager                               | 创建、列出命名空间；不是每个 namespace 的 manager                                |
| 全局 auditor                               | 列出命名空间；不是每个 namespace 的 auditor                                      |
| Namespace manager                          | 管理本 namespace、读配置、写服务端配置、签名；不能仅凭 manager 角色修改个人配置  |
| Namespace auditor                          | 读配置、获取解密密钥材料、签发自身身份 CWT；不能写配置或调用普通签名             |
| Namespace user                             | 写 `subject = caller` 的个人配置、普通签名、签发自身身份 CWT                     |
| Setting subject                            | 在非归档 namespace 中读该配置、获取对应密钥材料；写个人配置仍须是 namespace user |
| Setting reader                             | 读取被授权配置、获取对应密钥材料，但不自动获得 namespace 元数据或密钥列表权限    |
| 固定身份 delegator                         | 为指定固定身份申请 delegation；不自动成为 namespace 成员                         |

个人配置的写入条件是 **namespace user 且 caller 等于 subject**；manager 如果也在 users 中，可以写自己的个人配置。服务端配置只能由 namespace manager 写入，即使 subject 是调用者也一样。

### 3.3 可见性、状态与密钥权限

`visibility = 0` 为私有，`1` 为公开。公开 namespace 允许所有调用者（包括匿名）读取 namespace 信息、列出配置键和读取配置内容；公开并不授予写入、签名或解密密钥权限。明文 payload 在公开 namespace 中可被直接读取。

| 状态 | Namespace 行为                                                                        | Setting 行为                                                                                   |
| ---- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `0`  | 正常读写                                                                              | 正常读写                                                                                       |
| `1`  | 禁止配置内容写入；manager 仍可修改 namespace 元数据、角色或恢复为 `0`；普通签名仍可用 | payload、readers 和删除被禁止；拥有写权限者可通过 `setting_update_info` 修改元数据或恢复为 `0` |
| `-1` | 禁止配置写入；私有读取限 manager / auditor；manager 仍可管理或恢复                    | payload 和 readers 被禁止；可通过 `setting_update_info` 恢复，且允许删除                       |

Namespace 和 setting 的状态都可由相应管理者恢复；状态门槛保护内容写入，不会锁死管理面。

其他边界按具体接口执行：

- 私有且未归档：manager、auditor、subject 或 setting readers 可读配置；不要求 subject / readers 同时属于 users。
- 私有且归档：只有 manager / auditor 可读；公开 namespace 的读取规则优先于归档状态。
- KEK 权限：namespace 归档时先拒绝非 manager；随后允许 subject、namespace auditor、服务端配置的 namespace manager，或当前 setting 的 reader。个人配置 manager 没有隐含 KEK 权限。
- Namespace 成员可预取自身路径的 KEK；非成员 subject / reader 需要已经存在的 setting 授权。VetKD 公钥也向获得该路径密钥授权的 caller 开放。Setting 状态或版本不自动撤销密钥权限。
- 普通签名允许 manager / user；归档时仅 manager。`schnorr_sign_identity` 和固定身份委托有各自的角色检查，并不使用相同的状态门槛。

## 4. 命名空间接口

下表除注明 query 外均为 update；`()` 表示成功没有附带数据。

| 方法                                                   | 参数 → `Ok`                                                                                               | 行为                                                                       |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `state_get_info`（query）                              | `() → StateInfo`                                                                                          | 所有人可读；根公钥字段仅向 controller / governance / 全局 manager 返回     |
| `namespace_get_info`（query）                          | `(text) → NamespaceInfo`                                                                                  | 按 namespace 读取权限检查                                                  |
| `namespace_get_info_v2`（query）                       | `(text, bool with_members) → NamespaceInfo`                                                               | 可只取摘要；成员过大时须用分页接口                                         |
| `namespace_is_member`（query）                         | `(text, text, principal) → bool`                                                                          | 第二参数为 `manager` / `auditor` / `user`；caller 须非匿名且可读 namespace |
| `namespace_list_members`（query）                      | `(text, text, opt principal, opt nat32) → vec principal`                                                  | 按 manager / auditor / user 分页                                           |
| `namespace_list_fixed_identity_names`（query）         | `(text, opt text, opt nat32) → vec text`                                                                  | 分页列固定身份名称                                                         |
| `namespace_list_setting_keys`（query）                 | `(text, bool, opt principal) → vec record { principal; blob }`                                            | 兼容接口，超过 1000 项时要求改用 v2                                        |
| `namespace_list_setting_keys_v2`（query）              | `(text, bool, opt principal, opt record { principal; blob }, opt nat32) → vec record { principal; blob }` | 排除式 `(subject, key)` 游标分页                                           |
| `namespace_update_info`                                | `(UpdateNamespaceInput) → ()`                                                                             | Namespace manager；可恢复只读/归档状态                                     |
| `namespace_delete`                                     | `(text) → ()`                                                                                             | 同上，且 namespace 内必须没有配置                                          |
| `namespace_add_managers` / `namespace_remove_managers` | `(text, vec principal) → ()`                                                                              | 管理 managers 集合                                                         |
| `namespace_add_auditors` / `namespace_remove_auditors` | `(text, vec principal) → ()`                                                                              | 管理 auditors 集合                                                         |
| `namespace_add_users` / `namespace_remove_users`       | `(text, vec principal) → ()`                                                                              | 管理 users 集合                                                            |
| `namespace_top_up`                                     | `(text, nat) → nat`                                                                                       | 返回实际接收的 cycles；详见运行约束                                        |
| `namespace_rebuild_payload_bytes`                      | `(text) → nat64`                                                                                          | Manager 重新统计 current + archived payload/dek 字节                       |

`NamespaceInfo` 还返回 `manager_count`、`auditor_count`、`user_count`、`fixed_delegator_count`。兼容接口在完整成员可能超过安全响应预算时只返回摘要（集合为空、计数保留）；需要成员时使用 v2 分页接口。

`UpdateNamespaceInput` 的 `name` 是目标 namespace；其余字段 `desc`、`max_payload_size`、`status`、`visibility`、`session_expires_in_ms` 均可选，空值表示保留。

列键权限有特殊规则：公开 namespace 或 manager / auditor 可以用 `subject = null` 列全部，也可以指定 subject 过滤；私有未归档 namespace 的普通 user 只能列 caller 自己，但可传 `null` 或显式传自己。仅有 setting reader 权限不能列键。

增删 namespace 角色要求 manager；每种角色有总量上限，单次请求也有上限。服务拒绝移除最后一个 manager；若历史异常状态已经没有 manager，controller / governance 可用 `admin_recover_namespace_managers` 恢复。

## 5. 配置接口与版本管理

| 方法                                             | 模式   | 参数 → `Ok`                                                      |
| ------------------------------------------------ | ------ | ---------------------------------------------------------------- |
| `setting_create`                                 | update | `(SettingPath, CreateSettingInput) → CreateSettingOutput`        |
| `setting_get_info`                               | query  | `(SettingPath) → SettingInfo`，`payload`、`dek` 固定为空         |
| `setting_get`                                    | query  | `(SettingPath) → SettingInfo`，包含当前 payload / dek            |
| `setting_get_archived_payload`                   | query  | `(SettingPath) → SettingArchivedPayload`                         |
| `setting_update_info`                            | update | `(SettingPath, UpdateSettingInfoInput) → CreateSettingOutput`    |
| `setting_update_payload`                         | update | `(SettingPath, UpdateSettingPayloadInput) → CreateSettingOutput` |
| `setting_add_readers` / `setting_remove_readers` | update | `(SettingPath, vec principal) → ()`                              |
| `setting_delete`                                 | update | `(SettingPath) → ()`                                             |

`SettingInfo` 包含 `key`、`subject`、`desc`、时间、`status`、`version`、`readers`、`tags`、`payload`、`dek`。`CreateSettingOutput` 包含 `created_at`、`updated_at`、`version`；更新也复用该返回类型。

| 输入                        | 字段与语义                                                                                       |
| --------------------------- | ------------------------------------------------------------------------------------------------ |
| `CreateSettingInput`        | `payload`、`dek`、`desc`、`tags`、`status` 均可选；status 默认 0，只允许 0 / 1；readers 初始为空 |
| `UpdateSettingInfoInput`    | `desc`、`tags`、`status` 均可选；提供 tags 时整体替换，空集合清空；status 允许 -1 / 0 / 1        |
| `UpdateSettingPayloadInput` | `payload`、`dek` 至少提供一个；还可提供 `status`、`deprecate_current`                            |
| `SettingArchivedPayload`    | `version`、`archived_at`、`deprecated`、历史 `payload` / `dek`                                   |

版本规则：

1. 创建使用 `path.version = 0`，首个保存版本为 1。
2. `setting_get` 的 0 表示最新；非零必须等于当前版本。旧版本不能通过此接口读取。
3. `setting_get_info` 返回当前元数据，允许 0 或不大于当前值的版本；不会返回历史元数据。
4. 所有修改和删除（包括 readers）必须携带精确的当前版本。0 不是写入通配符。
5. 只有 `setting_update_payload` 推进版本。更新描述、标签、状态、readers 不推进版本，因此这个版本号不能防止元数据写入之间的所有并发覆盖。
6. 更新 payload / dek 前，只要当前 payload 或 dek 任一存在，就会归档该版本；仅更新 dek 也会保存旧 payload 的副本，DEK-only 版本也不会丢失。
7. 历史读取必须指定 `0 < version < 当前版本`，并按当前配置权限检查。`deprecated` 只是提示，服务端仍返回数据。
8. 删除配置会删除其历史 payload，之后不能再读取历史。

更新 payload / dek 时，空选项表示保留旧值，不能用 `null` 清除已有字段。`opt blob ""` 是空字节串，不是删除；如果处于加密配置路径，空字节串也必须满足 COSE 校验，通常不能直接使用。

发生 `version mismatch` 后，重新读取当前版本并决定是否合并；不要只替换版本号后盲目重放写入。删除成功后的重试会得到 NotFound。

## 6. ECDSA 与 Schnorr 签名

| 方法                 | 模式   | 参数 → `Ok`                                                |
| -------------------- | ------ | ---------------------------------------------------------- |
| `ecdsa_public_key`   | query  | `(opt PublicKeyInput) → PublicKeyOutput`                   |
| `ecdsa_sign`         | update | `(SignInput) → blob`                                       |
| `schnorr_public_key` | query  | `(SchnorrAlgorithm, opt PublicKeyInput) → PublicKeyOutput` |
| `schnorr_sign`       | update | `(SchnorrAlgorithm, SignInput) → blob`                     |

`PublicKeyInput = { ns; derivation_path : vec blob }`，`SignInput` 在此基础上增加 `message : blob`。`PublicKeyOutput` 包含 `public_key` 和 `chain_code`。公钥 input 为空时返回根公钥，不检查 namespace 权限；有 input 时需要可读该 namespace。

| 算法                    | message                                             | 返回 / 验证约定                                                        |
| ----------------------- | --------------------------------------------------- | ---------------------------------------------------------------------- |
| ECDSA secp256k1         | 必须是 **32 字节摘要**，canister 不替业务消息做哈希 | 原始签名，无 COSE 封装；派生公钥为压缩 SEC1 格式                       |
| Schnorr ed25519         | 原始消息字节                                        | 原始签名；派生公钥为 32 字节原始 Ed25519 公钥                          |
| Schnorr bip340secp256k1 | 原样交给管理 canister，业务双方应约定消息预处理     | BIP340 签名；接口派生公钥为压缩 SEC1 格式，验证库可能需要转换为 x-only |

调用方提供的 derivation path 最多 253 个分量、每个分量最多 64 字节、合计最多 4 KiB；通用 Schnorr 消息最多 64 KiB。服务端分别添加：

```text
ECDSA:  [UTF8("COSE_ECDSA_Signing"), UTF8(ns), ...derivation_path]
Schnorr:[UTF8("COSE_Schnorr_Signing"), UTF8(ns), ...derivation_path]
```

路径**不自动包含 caller**，同一 namespace 中有签名权限的成员可以对同一路径请求签名。不能仅靠把用户 ID 放进后缀实现用户间签名授权隔离；需要独立 namespace 或上层授权设计。

```bash
dfx canister call ic_cose_canister schnorr_public_key '(variant { ed25519 }, opt record {
  ns = "testing"; derivation_path = vec { blob "app_v1" };
})'

dfx canister call ic_cose_canister schnorr_sign '(variant { ed25519 }, record {
  ns = "testing"; derivation_path = vec { blob "app_v1" }; message = blob "hello";
})'
```

验签必须使用相同算法、namespace 和完整后缀所对应的公钥。普通签名不能使用根公钥验签；第 8.1 节的身份 CWT 则使用根公钥。

## 7. 加密配置与密钥获取

### 7.1 加密数据格式

Canister 保存字节，不替客户端自动加密明文。常用信封加密流程：

1. 客户端生成随机 DEK（Data Encryption Key），使用 DEK 将业务数据加密为 COSE_Encrypt0。
2. 客户端获取或派生 KEK（Key Encryption Key），将双方约定编码的 DEK 加密为另一份 COSE_Encrypt0。
3. `setting_create` / `setting_update_payload` 分别上传 `payload` 和 `dek`。
4. 读取后先用 KEK 解开 dek，再用 DEK 解开 payload。

提供 dek 时，服务端校验 dek 是可解析的 COSE_Encrypt0，并校验存在的 payload 也是该格式。更新时已有 dek 也会触发 payload 格式校验，包括仅替换 dek 时保留的 payload。此校验不等于验证客户端使用了正确密钥或能成功解密。

[COSE 工具](../ic_cose_types/src/cose/encrypt0.rs) 提供 AES-256-GCM 封装；双方需约定 DEK 明文字节格式、external AAD 和 key ID。每个 AES-GCM 密钥下使用不重复的 12 字节 nonce。历史内容的解密约定和密钥也需要保留。

### 7.2 ECDH 获取部分 KEK

`ecdh_cose_encrypted_key(SettingPath, ECDHInput) → Result<ECDHOutput>` 为 update，需要非匿名调用和 KEK 权限。

| 字段                    | 格式                                                |
| ----------------------- | --------------------------------------------------- |
| `ECDHInput.public_key`  | 客户端临时 X25519 公钥，32 字节                     |
| `ECDHInput.nonce`       | 客户端随机 nonce，12 字节                           |
| `ECDHOutput.public_key` | 服务端临时 X25519 公钥，32 字节                     |
| `ECDHOutput.payload`    | 用共享秘密作为 AES-256-GCM 密钥加密的 COSE_Encrypt0 |

客户端与返回公钥做 X25519，使用 **subject principal 的原始字节**作为 external AAD 解密 payload。明文是 COSE_Key，其中保存 32 字节 AES 密钥材料，`kid` 为 `SettingPath.key`。

该值定位为**服务端部分 KEK**，应与本地部分密钥通过业务约定的 KDF 派生完整 KEK。本接口和 Rust `get_cose_encrypted_key` helper 都不会自动完成这一步；KDF、域分隔和本地密钥备份由接入方定义。Rust helper 要求 `path.subject` 显式有值，以便构造 AAD。

服务端材料与内部 IV、subject、user_owned、namespace、key 绑定，**不包含 version**。修改版本或移除 reader 不会改变已分发的密钥；撤销权限只阻止后续获取，不能收回客户端已保存的密钥或明文。需要轮换时使用新 key 路径及新的加密材料。

### 7.3 VetKeys

| 方法                  | 模式   | 参数 → `Ok`                                     |
| --------------------- | ------ | ----------------------------------------------- |
| `vetkd_public_key`    | update | `(SettingPath) → blob`，派生公钥                |
| `vetkd_encrypted_key` | update | `(SettingPath, blob) → blob`，传输加密的 VetKey |

两者都要求非匿名，且受 `allowed_apis` 控制。公钥接口要求可读 namespace；加密密钥接口检查 KEK 权限。仅有 reader 权限者可能能获取加密密钥却不能调用公钥接口，需要由授权方提供相应公钥。

客户端流程：

1. 生成随机种子，创建 `TransportSecretKey`；传输公钥必须为 48 字节。
2. 获取同一路径的派生公钥和加密 VetKey。
3. 解析 `DerivedPublicKey`、`EncryptedVetKey`，调用 `decrypt_and_verify(transport_secret_key, derived_public_key, path.key)`。
4. 通过双方约定的派生方式得到应用密钥，或使用 VetKey 的 IBE 能力。不要跳过验证直接使用解密结果。

`vetkd_context_version = 2` 时，context 对固定域和每个分量的 64 位长度前缀做 SHA3-256，避免相邻分量边界碰撞。分量依次为：

```text
"COSE_Symmetric_Key", subject.raw_bytes, [user_owned ? 1 : 0], UTF8(ns)
```

版本 1 保留旧实现的原始拼接，只用于既有部署兼容。`path.key` 是 VetKD 的独立 input；setting version 不参与。改变 namespace、subject、user_owned、key、VetKD key name 或 context version 都会改变密钥语义；有既有密文时不得无迁移方案直接切换。Rust `CoseSDK::vetkey` 已封装取公钥、取加密密钥、解密与验证，参见 [SDK 实现](../ic_cose/src/client.rs)。

## 8. 身份令牌与固定身份委托

### 8.1 `schnorr_sign_identity`：业务身份 CWT

`schnorr_sign_identity(SchnorrAlgorithm, { ns; audience }) → Result<blob>` 为 update，返回 COSE_Sign1 封装的 CWT，非 IC delegation。

| 声明 / 验证输入        | 值                                                 |
| ---------------------- | -------------------------------------------------- |
| issuer                 | 当前 canister ID 文本                              |
| subject                | caller principal 文本                              |
| audience               | 请求中的 audience                                  |
| issued_at / not_before | 当前 Unix 秒                                       |
| expiration             | 当前时间加 3600 秒                                 |
| cwt_id                 | 随机 16 字节                                       |
| external AAD           | caller principal 原始字节                          |
| 验证公钥               | `schnorr_public_key(algorithm, null)` 返回的根公钥 |

Scope 随角色变化：manager 为 `Namespace.*:<ns>`；auditor 为 `Namespace.Read:<ns>`；user 为 `Namespace.Read.Info:<ns> Namespace.*.SubjectedSetting:<ns>`；同时为 user / auditor 则前半段为 `Namespace.Read:<ns>`。manager 优先。

该接口只检查角色，不按 namespace 状态禁发。消费方应校验签名、issuer、subject、audience、有效期和 scope；角色变更不会自动撤销已签发令牌。

身份 CWT 仅支持 Ed25519 / EdDSA。BIP340 会被明确拒绝，因为标准 COSE `ES256K` 表示 secp256k1 ECDSA，而不是 BIP340 Schnorr；服务不再生成算法标签与真实签名不一致的令牌。

### 8.2 固定身份接口

| 方法                           | 模式   | 参数 → `Ok`                                                     |
| ------------------------------ | ------ | --------------------------------------------------------------- |
| `namespace_get_fixed_identity` | query  | `(text ns, text name) → principal`                              |
| `namespace_get_delegators`     | query  | `(text ns, text name) → vec principal`                          |
| `namespace_add_delegator`      | update | `(NamespaceDelegatorsInput) → vec principal`，返回合并后的集合  |
| `namespace_remove_delegator`   | update | `(NamespaceDelegatorsInput) → ()`                               |
| `namespace_sign_delegation`    | update | `(SignDelegationInput) → SignInResponse`                        |
| `get_delegation`               | query  | `(blob seed, blob pubkey, nat64 expiration) → SignedDelegation` |

`NamespaceDelegatorsInput = { ns; name; delegators : vec principal }`。增删需要 namespace manager；输入 name 必须符合小写命名规则。查询和签发会将 name 做 ASCII 小写归一化。查询 delegators 需要 namespace 读取权限。

固定 principal 由当前 canister ID 和 `CBOR([ns, lowercase(name)])` seed 派生。`namespace_get_fixed_identity` 只计算身份，不检查 namespace 或授权表是否存在，拿到 principal 不代表可以登录。移除最后一个 delegator 会删除该 name 的授权表项。

### 8.3 申请会话 delegation

1. Namespace manager 为 name 添加已认证调用方的 principal 到 delegators。
2. 客户端生成会话密钥对，将公钥编码成 IC 接受的 **DER 用户公钥**，作为 `pubkey`。
3. 使用会话私钥签名挑战 `CBOR([ns, lowercase(name), caller])`。其中 caller 编码为 CBOR byte string（principal 原始字节），不是 principal 文本；可直接参考服务端 `cbor2::to_writer` 编码。
4. 使用 delegator 身份调用 `namespace_sign_delegation({ ns; name; pubkey; sig })`。会话密钥不必等于该调用身份的密钥，但 sig 必须由 pubkey 对应私钥产生。
5. 得到 `{ user_key; seed; expiration }`：`user_key` 为固定身份的 DER canister signature 公钥，expiration 已是纳秒，不要再次换算。
6. 立即 query `get_delegation(seed, 相同的会话pubkey, expiration)`，取得完整 `SignedDelegation`，交由支持 IC canister signature 的 delegation identity 构造器使用。

签发会验证 caller 在 delegators 中且 `session_expires_in_ms != 0`。返回 delegation 的 `targets = null`、`permissions = null`，接口不接受目标 canister 限制。申请方应按这个实际授权范围使用会话私钥。

签名证明的 intent 同时保存在 stable storage 中并在升级后重建 certified root，默认保留约 60 秒且总量有上限；仍应立即获取并保存完整 delegation。移除 delegator 或将会话期限设为 0 不会使已经签出的 delegation 立即失效，现有 delegation 按其 expiration 到期。

## 9. 管理与治理接口

| 方法                                                   | 模式   | 参数 → `Ok`                                           | 权限                                             |
| ------------------------------------------------------ | ------ | ----------------------------------------------------- | ------------------------------------------------ |
| `admin_add_managers` / `admin_remove_managers`         | update | `(vec principal) → ()`                                | Controller / governance                          |
| `admin_add_auditors` / `admin_remove_auditors`         | update | `(vec principal) → ()`                                | Controller / governance                          |
| `admin_add_allowed_apis` / `admin_remove_allowed_apis` | update | `(vec text) → ()`                                     | Controller / governance                          |
| `admin_create_namespace`                               | update | `(CreateNamespaceInput) → NamespaceInfo`              | Controller / governance / 全局 manager           |
| `admin_list_namespace`                                 | query  | `(opt text prev, opt nat32 take) → vec NamespaceInfo` | Controller / governance / 全局 manager / auditor |
| `admin_migrate_legacy_settings`                        | update | `(nat32 take) → nat64`                                | Controller / governance；增量迁移 setting 存储   |
| `admin_migrate_legacy_namespace_acls`                  | update | `(nat32 take) → nat64`                                | Controller / governance；增量迁移 ACL            |
| `admin_recover_namespace_managers`                     | update | `(text, vec principal) → ()`                          | Controller / governance；仅限 manager 已为空     |
| `admin_clear_low_wasm_memory`                          | update | `() → ()`                                             | Controller / governance；确认恢复后清除保护状态  |

`admin_list_namespace` 按 namespace 名称排序，`prev` 是排除式游标；`take` 默认 10，最大 100。下一页传上一页最后一个 name。Controller / governance 可直接列举；全局 auditor 也可读取。

`allowed_apis` **为空表示全部允许**；非空时只允许集合中精确匹配的方法名。这是业务 update 白名单，覆盖 namespace / setting 更新、普通签名、密钥获取、CWT、delegator 更新和 delegation 签发，以及 `admin_create_namespace`。Query、管理角色 / 白名单接口和 validate 接口不受它限制。清空集合会重新开放全部受控接口，不是关闭全部接口。

治理提案可使用六组校验接口，对应 `admin_{add,remove}_{managers,auditors,allowed_apis}`：

- `validate2_admin_add_managers`、`validate2_admin_remove_managers`
- `validate2_admin_add_auditors`、`validate2_admin_remove_auditors`
- `validate2_admin_add_allowed_apis`、`validate2_admin_remove_allowed_apis`

它们均为 controller / governance 限定的 update，返回 `Result<text>`，成功文本是 Candid 风格的 `vec { ... }` 参数摘要；仅校验输入，不实际修改状态。旧接口仍可用，只返回 `Result<()>`；新对接优先使用 `validate2_`。完整对应关系如下：

| 推荐接口                              | 兼容接口                             |
| ------------------------------------- | ------------------------------------ |
| `validate2_admin_add_managers`        | `validate_admin_add_managers`        |
| `validate2_admin_remove_managers`     | `validate_admin_remove_managers`     |
| `validate2_admin_add_auditors`        | `validate_admin_add_auditors`        |
| `validate2_admin_remove_auditors`     | `validate_admin_remove_auditors`     |
| `validate2_admin_add_allowed_apis`    | `validate_admin_add_allowed_apis`    |
| `validate2_admin_remove_allowed_apis` | `validate_admin_remove_allowed_apis` |

Allowed API 校验目前不检查方法名是否真实存在。

升级接收 `opt variant { Upgrade = record { ... } }`，也允许 `null` 仅恢复状态。可选字段为 `name`、`subnet_size`、`freezing_threshold`、`governance_canister`、`vetkd_key_name`、`clear_governance_canister`、`vetkd_context_version`、`migrate_legacy_namespaces`。空选项保留旧值；清除治理身份必须显式传 `clear_governance_canister = opt true`，且不能同时设置新 governance。ECDSA / Schnorr key name 不在升级参数中。

Namespace、setting、ACL、历史 payload 和短期 canister-signature intent 使用 stable storage，升级保存 / 恢复全局状态及 certified root。`migrate_legacy_namespaces = opt true` 只用于从最早期单体 namespace 存储直接升级；当前 stable-map 部署必须保持 false / null，以免把旧快照误当作权威数据。若公钥或内部 IV 缺失，升级后会持续退避重试；不会覆盖已经存在的 IV。更换 VetKD key name 或 context version 前需要处理旧密文兼容；reinstall 不能当作普通升级使用。

wasm32 与 wasm64 均使用真实 IC stable memory；wasm64 显式适配稳定存储，避免依赖的默认内存模拟后端。两种 Wasm 架构都会使用 IC 时间并更新 canister-signature 的认证根，宿主单元测试才使用模拟后端。

## 10. 客户端接入示例

### 10.1 TypeScript Actor

以下是可放入应用的 helper，依赖 `@icp-sdk/core/agent` 和生成的 IDL。`identity` 由调用方提供，须具备目标 namespace 的权限；使用与生成绑定配套的 SDK 版本。

```typescript
import { Actor, HttpAgent, type Identity } from '@icp-sdk/core/agent';
import { idlFactory } from '../declarations/ic_cose_canister/ic_cose_canister.did.js';
import type { _SERVICE } from '../declarations/ic_cose_canister/ic_cose_canister.did';

function unwrap<T>(result: { Ok: T } | { Err: string }): T {
  if ('Err' in result) throw new Error(result.Err);
  return result.Ok;
}

export async function readAndUpdate(
  canisterId: string,
  host: string,
  identity: Identity,
  localReplica = false,
) {
  const agent = await HttpAgent.create({ host, identity });
  if (localReplica) await agent.fetchRootKey(); // 仅本地 replica
  const actor = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  const path = {
    ns: 'testing',
    user_owned: false,
    subject: [identity.getPrincipal()] as [ReturnType<Identity['getPrincipal']>],
    key: new TextEncoder().encode('app_config'),
    version: 0,
  };
  // 普通 Actor query；需要共识读取时改用 update 调用路径。
  const current = unwrap(await actor.setting_get(path));
  const updated = unwrap(await actor.setting_update_payload(
    { ...path, version: current.version },
    {
      payload: [new TextEncoder().encode('updated from TypeScript')],
      dek: [],
      status: [],
      deprecate_current: [false],
    },
  ));
  return updated.version;
}
```

这里更新的是第 2 节已创建的**明文**配置；如果当前配置有 dek，必须先按加密协议产生 COSE_Encrypt0，不能直接上传 UTF-8 明文。生成绑定的相对导入路径需按应用目录调整。

### 10.2 Rust SDK

在使用仓库对应版本 `ic_cose`、`ic_cose_types` 的 Rust 应用中，已有带身份的 `Client` 后可这样读取并更新：

```rust
use ic_cose::client::{Client, CoseSDK};
use ic_cose_types::types::setting::{SettingPath, UpdateSettingPayloadInput};

pub async fn update_plaintext(cli: &Client, mut path: SettingPath) -> Result<u32, String> {
    path.version = 0;
    let current = cli.setting_get(&path).await?;
    if current.dek.is_some() {
        return Err("expected a plaintext setting".into());
    }
    path.version = current.version;
    let output = cli.setting_update_payload(&path, &UpdateSettingPayloadInput {
        payload: Some(b"updated from Rust".to_vec().into()),
        ..Default::default()
    }).await?;
    Ok(output.version)
}
```

`Client::new(Arc<Agent>, Principal)` 接收已配置身份和网络的 agent。更完整的连接、VetKey 验证和 IBE 流程参见 [示例](../ic_cose/examples/vetkeys.rs)；示例中的固定演示密钥不能用于生产身份。

## 11. 错误处理与运行约束

| 错误 / 现象                                                       | 含义与排查                                                                 |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `anonymous user is not allowed`                                   | 使用已认证身份；guard 拒绝可能不是业务 Result                              |
| `user is not a controller`                                        | 使用 controller 或已配置 governance 身份调用管理接口                       |
| `no permission`                                                   | 分别检查全局角色、namespace 角色、user_owned、subject、namespace 状态      |
| `API <method> not allowed`                                        | 非空白名单未包含该方法                                                     |
| `NotFound: setting ... not found or no permission`                | 有意合并不存在和无读取权限；同时检查路径及授权                             |
| `version mismatch`                                                | 修改携带旧版本，或误用当前读取接口获取历史；重新读取后处理冲突             |
| `setting is not writable` / `readonly setting can not be deleted` | 先用 `setting_update_info` 恢复状态，或按策略删除 archived setting         |
| `namespace ... is not empty`                                      | 删除 namespace 前需要删除其中所有配置                                      |
| `payload size exceeds the limit` / `DEK size exceeds the limit`   | 检查封装后字节长度                                                         |
| COSE 解析错误                                                     | dek 或加密 payload 不是合法 COSE_Encrypt0，不能传裸 AES 密文或 base64 文本 |
| `message must be 32 bytes`                                        | ECDSA 需要 32 字节摘要，不能传摘要的 64 字符 hex 文本                      |
| `derivation path length exceeds the limit 253`                    | 减少调用方路径分量                                                         |
| `no ... public key` / `failed to retrieve ... public key`         | 启动缓存未就绪或 key ID 不受目标网络支持；查 canister 日志和状态           |
| `caller ... is not a delegator` / `NotFound: name not found`      | 校验固定身份 name 与 delegators 表                                         |
| `challenge verification failed`                                   | 校验 DER 公钥、会话签名、CBOR 顺序、name 小写化和 caller 原始字节          |
| `delegation is disabled`                                          | namespace 的 session_expires_in_ms 为 0                                    |
| `cycles should be at least 1T` / `insufficient cycles`            | 充值参数须至少 1T 且调用必须附带足够 cycles                                |

业务错误没有稳定的数字错误码，不要仅依赖字符串全文匹配实现关键控制流。调用超时并不保证 update 未执行；重试创建、修改或 delegation 签发前，先确认状态和已有返回数据。

### Cycles 与资源

- `namespace_top_up` 接收的 cycles 参数必须 **大于等于 1,000,000,000,000**，并且不超过该消息附带的 cycles。普通用户 ingress 只传数字不会附带 cycles；需要支持附带 cycles 的 canister / wallet 调用。
- 任何非匿名 caller 都可为已存在 namespace 充值，不要求 namespace 成员身份。返回实际接收数量并累加 gas_balance。
- ECDSA、Schnorr、VetKD 和 ECDH 的管理调用会在 `await` 前从 namespace gas 原子预扣请求费和 `cost_call` 预算上限；余额不足时拒绝。明确未发出的调用全额退回；已发出调用收到的附带 cycles 退款记回 namespace。调用部分保守保留最大响应/回调预算，不代表实际消耗。多步身份签名分别结算 raw-rand 与 Schnorr。
- `subnet_size` 作为兼容字段保留；动态管理调用费用不再依赖手工配置的子网节点数。`freezing_threshold` 是额外的应用层 cycles 保留值，不是 IC canister settings 中按秒计的同名字段。
- `payload_bytes_total` 统计当前及历史 payload/dek 字节；更新增加新版本实际存储量，删除会扣减全部版本。历史异常计数可用 `namespace_rebuild_payload_bytes` 修复；它仍不包含元数据和索引开销。
- 兼容的 `namespace_list_setting_keys` 最多返回 1000 项；大集合使用 v2 游标分页。历史 payload 仍没有独立批量清理接口，持续更新需规划 stable memory。
- 触发 low-Wasm-memory 后，新增/扩容类写入会被保护性拒绝；先删除或迁移数据并确认内存恢复，再由 controller 清除标志。
- Query 没有通用配置内容认证证明；需要共识读取时使用 update。固定身份 delegation 的证书验证应交由支持 IC canister signature 的客户端完成。

公开可见性不授予消耗 namespace gas 的权限；VetKD 公钥调用仍要求 namespace 角色或现有 setting 授权。

### 有界 ACL 迁移与 Rust 客户端

`admin_migrate_legacy_namespace_acls_page(prev, scan_limit)` 每次最多扫描 100 个 namespace，返回 `{ items; next_cursor }`；items 是本次迁移的名称。即使 items 为空，也要继续使用 next_cursor，直到其为空。旧迁移接口在总 namespace 数超过 1000 时要求使用分页版本。

Rust `build_agent` 默认保留 IC root key 并验证 query 签名，包括 HTTP host。仅本地 replica 使用显式 `build_local_agent`。`setting_get_consensus` 用 update 读取配置；常规查询保留 query 速度。SDK 还提供 `namespace_get_info_v2`、成员/固定身份分页和 `namespace_list_setting_keys_v2`。


## License

Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-cose` is licensed under the MIT License. See [LICENSE](../../LICENSE-MIT).
