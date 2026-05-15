# Open-source / 企业版 仓库结构与同步方案

## Context

permit0 OSS 版本（`github.com/permit0-ai/permit0`，Apache-2.0）已经有清晰的 trait 扩展点
（`PolicyState` / `AuditSink` / `DigestStore` / `AuditSigner` / `Normalizer` /
`Redactor`），并且通过最近的三个 PR 完成了 storage 拆分 + Postgres + 数字签名摘要。
现在要再开一个企业版仓库，主要承载：

1. 高级 audit sink / 合规集成（S3, QLDB, Datadog 原生连接器，SOC2/HIPAA 报表）
2. 完整 SSO / SAML / 细粒度 RBAC（OSS 只有基础 OIDC）
3. 中央策略管理 / 多租户 / 多 engine 集群面板
4. **对 OSS 核心代码偶有闭源修改**（最大风险点，下面会专门讲怎么处理）
5. **S3 / 云端 audit log + approval state 存储**（用户明确点名）

期望：OSS 主导开发节奏，企业版偶尔加功能；最小化前期改造成本。

**用户决定（不要再讨论）：**
- 仓库结构：**fork 模式**——私有仓 fork OSS，git pull upstream 同步
- 不搞 monorepo + CI 双向同步（复杂度太高）
- 不强制要求所有企业功能都做成 plugin（可以但不强制）

## 推荐结构

```
github.com/permit0-ai/permit0              ← 公开，Apache-2.0，照常开发
github.com/permit0-ai/permit0-enterprise   ← 私有，fork 自 OSS + enterprise crates
```

私有仓的目录布局（在 OSS 的基础上新增）：

```
permit0-enterprise/
├── ... (OSS 全部内容，作为 fork)
├── crates/
│   ├── ... (OSS 全部 crates)
│   ├── enterprise-audit-s3/         ← 新增：S3AuditSink + S3DigestStore
│   ├── enterprise-audit-qldb/       ← 新增：AWS QLDB 连接器
│   ├── enterprise-sso/              ← 新增：SAML / 高级 OIDC / RBAC
│   ├── enterprise-multitenant/      ← 新增：组织隔离 / 策略分发
│   └── enterprise-cli/              ← 新增（可选）：把 enterprise-* 拼成一个 `permit0-ee` binary
├── LICENSE                          ← OSS 部分仍是 Apache-2.0
├── LICENSE-ENTERPRISE.txt           ← 新增：商业许可，覆盖 enterprise-* crates
├── ENTERPRISE_PATCHES.md            ← 新增：列出所有对 OSS 核心代码的闭源 patch
├── docs/enterprise/                 ← 新增：企业版文档
└── .github/workflows/
    └── sync-from-upstream.yml       ← 新增：定期 fetch + 自动 PR
```

**核心原则：**
- 95% 的企业功能放在 `crates/enterprise-*/` 新 crate 里——这些 crate 通过 OSS 已有的
  trait 扩展点接入，零侵入。OSS 升级不影响。
- 5% 不可避免要改 OSS 核心代码的，放进 `ENTERPRISE_PATCHES.md` 里登记，每次 merge
  upstream 时优先确认这些点是否冲突。
- 企业版的 binary（`permit0-ee` 或者 OSS 的 `permit0` 加 features）需要把
  enterprise crates 串起来；OSS 的 `permit0` binary 完全不变。

## 为什么不直接 fork 然后乱改

**Fork + 大量核心改动 = 维护噩梦。** 每次 upstream 有新 PR，merge 几乎肯定有冲突。
半年后你的私有仓和 OSS 已经面目全非，没人敢同步。

**Fork + enterprise crates 模式 = 几乎没有 merge 冲突。** 因为 95% 的企业代码放在 OSS
没有的新文件里，git merge 只看到 add 不会冲突。剩下的 5% 用 `ENTERPRISE_PATCHES.md`
管理。

## 关键文件 / 步骤

### 一次性设置

1. **创建私有仓**（用户手工，不能由代码完成）：
   - GitHub 上点 New repository → Private → 名字 `permit0-enterprise`
   - 不要勾 README/LICENSE，让它空着

2. **从 OSS fork 内容**（在你本地）：
   ```bash
   git clone git@github.com:permit0-ai/permit0.git permit0-enterprise
   cd permit0-enterprise
   git remote rename origin upstream
   git remote add origin git@github.com:permit0-ai/permit0-enterprise.git
   git push -u origin main
   ```
   注意：远程名 `upstream` 指 OSS，`origin` 指私有仓——这是行业惯例。

3. **加 enterprise 文件骨架**（`crates/enterprise-*/Cargo.toml` + 占位 lib.rs，`LICENSE-ENTERPRISE.txt`，`ENTERPRISE_PATCHES.md`）

4. **配置 `.github/workflows/sync-from-upstream.yml`**：每周自动 fetch upstream，开个
   PR；如果 merge clean 就自动 merge，有冲突就停下等人处理。

### 第一个企业 crate（推荐做 S3 sink，因为用户明确点名）

`crates/enterprise-audit-s3/`：
- `src/lib.rs` 实现 `S3DigestStore`（impl `permit0_store::DigestStore`）
- 同样可以加 `S3AuditSink`，但更像是 cold-tier；写性能不如 Postgres
- Cargo.toml 里 `license = "LicenseRef-permit0-enterprise"`
- 依赖：`permit0-store = { git = "https://github.com/permit0-ai/permit0", tag = "v0.x" }`
  或者直接 `path = "../permit0-store"`（fork 模式下走 path 更简单）

### Sync workflow（日常）

```bash
# 每周或每月跑一次
cd permit0-enterprise
git fetch upstream
git merge upstream/main          # 95% 时间是 clean merge
# 如果有冲突，先看 ENTERPRISE_PATCHES.md 是不是登记过这个 patch
git push origin main
```

自动化：CI 任务每周自动跑这个流程，clean merge 自动合并，有冲突开 issue 通知。

### 闭源修改 OSS 核心怎么办

不可避免时（比如改 `engine.rs` 加多租户钩子）：

1. **优先把它变成 OSS 贡献**——加一个泛化的 hook 上游接受了，企业版直接用。这是
   最干净的办法。
2. **不行的话，在 `ENTERPRISE_PATCHES.md` 里记录**：
   ```markdown
   ## crates/permit0-engine/src/engine.rs

   ### Patch: tenant context injection
   - Lines: ~145-160 (run_pipeline)
   - Reason: 多租户隔离，注入 tenant_id 到 norm_hash
   - Upstream PR attempt: github.com/permit0-ai/permit0/pull/123 (rejected)
   - Conflict risk: HIGH if upstream refactors run_pipeline
   ```
3. **Merge 时检查** `ENTERPRISE_PATCHES.md` 列出的所有文件，确认 patch 还成立。

## Critical files / artifacts to create

| 文件 | 用途 |
|---|---|
| `crates/enterprise-audit-s3/Cargo.toml` + `src/lib.rs` | 第一个企业 crate，实现 `DigestStore` for S3 |
| `crates/enterprise-audit-s3/src/store.rs` | `S3DigestStore { bucket, prefix, client: aws_sdk_s3::Client }` |
| `LICENSE-ENTERPRISE.txt` | 商业许可（可参考 ELv2 / BSL / Confluent Community License） |
| `ENTERPRISE_PATCHES.md` | OSS 核心改动清单 |
| `.github/workflows/sync-from-upstream.yml` | 自动同步 OSS upstream |
| `docs/enterprise/architecture.md` | 企业版架构图：哪些是 trait impl，哪些是核心 patch |
| `Cargo.toml`（workspace） | 把 `crates/enterprise-*/*` 加到 `members` |

## 复用现有 trait 扩展点（关键）

OSS 已经留好的 trait 都可以直接 impl，**不用改 OSS 代码**：

- `permit0_store::DigestStore` → S3 / GCS / Azure Blob 实现
- `permit0_store::AuditSink` → S3 / QLDB / Cloud Logging 实现
- `permit0_store::PolicyState` → 云端 KV (DynamoDB / Spanner) 实现
- `permit0_store::AuditSigner` → KMS / HSM 签名（替代本地 ed25519 文件）
- `permit0_dsl::Normalizer` → 企业 SaaS 工具的 normalizer pack
- `permit0_store::audit::Redactor` → 企业级 PII 检测（Presidio / Comprehend）

S3 audit log + approval state（用户明确要的）= `S3AuditSink` + `S3PolicyState`，
两个新 crate，零 OSS 修改。

## Verification

设置完之后跑一遍：

1. **Sync 流程**：
   ```bash
   git fetch upstream && git merge upstream/main
   # 应该是 "Already up to date" 或 clean merge
   ```

2. **Workspace 编译**：
   ```bash
   cargo build --workspace          # 包括 enterprise-* crates
   cargo test --workspace
   ```

3. **OSS-only build 不破**（关键 sanity check）：
   ```bash
   cd /tmp && git clone https://github.com/permit0-ai/permit0
   cd permit0 && cargo build --workspace
   # 必须 clean，证明你没污染过 OSS
   ```

4. **企业 crate 测试**：
   ```bash
   cargo test -p enterprise-audit-s3
   # 用 `localstack` 或 minio 起一个 mock S3 跑集成测试
   ```

## 第一阶段交付清单

按优先级：

1. 私有仓 fork 完成 + `sync-from-upstream.yml` 跑通
2. `LICENSE-ENTERPRISE.txt` + `ENTERPRISE_PATCHES.md` 占位
3. `crates/enterprise-audit-s3/` 实现 `S3DigestStore`（最简单，用户也明确要）
4. 文档：`docs/enterprise/architecture.md` 解释扩展点 + patch 策略
5. 后续每加一个企业功能，先问"能不能做成 trait impl 不改 OSS"——95% 答案是能

## 不在本次 plan 范围

- 实际的商业许可文本（找律师，不是工程师该写的）
- 计费 / license key 验证逻辑（独立 PR）
- 多租户的具体 schema 设计（独立 plan）
- OSS 那边的 trait 是否需要再泛化（按需在 OSS 提 PR）
