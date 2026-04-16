# permit0

**AI Agent 运行时权限控制框架 — 确定性策略执行、风险评分引擎、会话感知、合规审计**

[English](README.md) | 简体中文

---

> **这不是 prompt guardrail 或内容审核工具。**
> permit0 管控的是 Agent 的 **动作（工具调用）**，而非 LLM 的输入/输出。

```
Agent actions (tool calls) ──► Normalize ──► Session-aware deterministic risk scoring ──► Allow / Deny / Agent Review (→ Human / Deny) ──► Audit log
```

**确定性策略 vs. 概率性方法：** 基于规则的策略执行，不依赖 LLM 做策略判断 — 零违规率，可审计、可复现。

---

## 这是什么（不是什么）

| | permit0 | Prompt Guardrails |
|---|---|---|
| **管控对象** | Agent 的工具调用（Bash、HTTP、文件写入…） | LLM 输入/输出文本 |
| **决策方式** | 确定性规则引擎，0% 误判 | 概率模型，存在误判 |
| **延迟** | < 0.1ms / 次 | 50–500ms（需要 LLM 调用） |
| **可审计** | 哈希链 + ed25519 签名 | 无审计链 |
| **会话感知** | 跨调用模式检测、攻击链识别 | 单次判断 |

---

## 快速体验

```bash
# 1. 安装
git clone https://github.com/anthropics/permit0-core.git && cd permit0-core
cargo build --release

# 2. 启动管理后台
cargo run -- serve --ui --port 9090
# 打开 http://localhost:9090/ui/

# 3. 通过 REST API 评估工具调用
curl -X POST http://localhost:9090/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"tool_name":"Bash","parameters":{"command":"ls -la"}}'
# ✓ {"permission":"Allow","tier":"MINIMAL","score":9,...}

curl -X POST http://localhost:9090/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"tool_name":"Bash","parameters":{"command":"sudo rm -rf /"}}'
# ✗ {"permission":"Deny","tier":"CRITICAL","score":100,...}
```

### Docker 部署

```bash
docker compose up -d
# 访问 http://localhost:9090/ui/
```

---

## 你将获得

| 能力 | 说明 | 状态 |
|------|------|------|
| **策略引擎** | YAML DSL 定义标准化规则 + 风险规则，6 步混合评分算法 | 可用 |
| **会话感知** | 跨调用累计追踪、频率检测、攻击链识别 | 可用 |
| **三层校准** | Base → Profile（fintech/healthtech）→ Org 策略，安全护栏不可绕过 | 可用 |
| **合规审计** | 哈希链 + ed25519 签名，JSONL/CSV 导出，防篡改 | 可用 |
| **Agent 审阅** | Medium 风险先由 LLM Agent 二次审阅，不确定再升级到人工 | 可用 |
| **人工审批** | Agent 审阅未通过时路由到 Human-in-the-loop，Web GUI 或 CLI 审批 | 可用 |
| **管理后台** | 6 页签 Dashboard：审计日志、审批、策略编辑、配置、实时监控 | 可用 |
| **Denylist / Allowlist** | 基于 norm_hash 的黑白名单，即时生效 | 可用 |
| **CLI 工具** | check / hook / gateway / serve / calibrate / audit 命令 | 可用 |
| **Python SDK** | PyO3 原生绑定，直接 `import permit0` | 可用 |
| **TypeScript SDK** | napi-rs 原生绑定，`@permit0/core` | 可用 |

---

## 适配你的技术栈

### Agent 框架集成

| 框架 | 集成方式 | 说明 |
|------|---------|------|
| **Claude Code** | `PreToolUse` Hook | 原生支持，一行配置 |
| **OpenAI Agents** | HTTP Sidecar | `POST /api/v1/check` |
| **LangChain** | Python SDK | `engine.get_permission(tool, params)` |
| **CrewAI** | Python SDK | 同上 |
| **AutoGen** | Python SDK / HTTP | 两种方式均可 |
| **自定义 Agent** | HTTP / Gateway | REST API 或 JSONL 管道 |

### 运行模式

| 模式 | 命令 | 适用场景 |
|------|------|---------|
| **Hook** | `permit0 hook` | Claude Code PreToolUse 钩子 |
| **Serve** | `permit0 serve --ui` | HTTP 守护进程 + Web 管理后台 |
| **Gateway** | `permit0 gateway` | JSONL 管道，批量处理 |
| **Check** | `permit0 check` | 单次评估，调试用 |

### 多语言 SDK

| 语言 | 安装 | 最低版本 |
|------|------|---------|
| **Rust** | `cargo add permit0-engine` | 1.85+ |
| **Python** | `pip install permit0` | 3.9+ |
| **TypeScript** | `npm install @permit0/core` | Node 18+ |

---

## 系统架构

```
                         ┌─────────────────────────────────┐
                         │          permit0 引擎             │
                         ├─────────────────────────────────┤
  工具调用                │                                 │
  (Bash, HTTP,  ───────► │  1. Normalize (YAML Pack)       │
   Write, ...)           │  2. Denylist / Allowlist         │
                         │  3. Risk Scoring (6 步混合)      │
                         │  4. Session Amplifier            │  ┌──────────┐
                         │  5. 分级路由                     ├─►│  Allow   │
                         │     Minimal/Low  → Allow         │  │  Deny    │
                         │     High/Critical→ Deny          │  └──────────┘
                         │     Medium ──┐                   │
                         │              ▼                   │
                         │  6. Agent Review (LLM 审阅)      │
                         │     ├─ 不通过 → Deny              │
                         │     └─ 不确定 → Human-in-the-loop│
                         │  7. 审计日志 (哈希链 + 签名)      │
                         └─────────────────────────────────┘
                                      ↑
                           三层校准 (Profile)
                        Base → Domain → Org Policy
```

### 决策管道

1. **Normalize** — 原始工具调用 → 标准化 `NormAction`（`domain.verb` 格式）
2. **Denylist** — norm_hash 命中黑名单 → 直接 Deny
3. **Allowlist** — norm_hash 命中白名单 → 直接 Allow
4. **策略缓存** — 命中缓存 → 返回历史决策
5. **未知动作** — 无 risk rule → Human-in-the-loop（保守策略）
6. **风险评分** — DSL 规则 + 混合算法 → 0–100 分
7. **会话放大** — 历史操作、频率模式 → 调整分数
8. **分级路由** — 分数 → Tier → 决策（Minimal/Low → Allow, High/Critical → Deny）
9. **Agent Review** — Medium 风险由 LLM Agent 二次审阅：不通过 → Deny，不确定 → 升级到 Human-in-the-loop
10. **审计记录** — 哈希链 + ed25519 签名
11. **返回结果** — `{ permission, action_type, score, tier, source }`

### 风险分级

| Tier | 分数 | 决策 | 示例 |
|------|------|------|------|
| Minimal | 0–15 | Allow | `ls -la`、读取文件 |
| Low | 15–35 | Allow | 普通文件写入 |
| Medium | 35–55 | Agent Review → Human | 网络请求、敏感文件操作 |
| High | 55–75 | Deny | 大额支付、权限变更 |
| Critical | 75–100 | Deny | `rm -rf /`、SSH 密钥写入 |

---

## 集成指南

### 方案一：Claude Code 集成（推荐）

在 `~/.claude/settings.json` 添加一行：

```json
{
  "hooks": {
    "PreToolUse": [{
      "command": "permit0 hook --profile fintech --db ~/.permit0/sessions.db",
      "description": "permit0 agent safety check"
    }]
  }
}
```

配置后 Claude Code 每次工具调用前自动经过 permit0 评估。

### 方案二：HTTP API（通用，适用任何框架）

```bash
# 启动服务
permit0 serve --ui --port 9090

# 调用
curl -X POST http://localhost:9090/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"tool":"Bash","input":{"command":"ls"}}'
```

**响应**：
```json
{
  "permission": "allow",
  "action_type": "process.shell",
  "score": 9,
  "tier": "MINIMAL",
  "blocked": false,
  "source": "Scorer"
}
```

**Python 客户端**：
```python
import requests

def check_permission(tool_name: str, params: dict) -> dict:
    return requests.post("http://localhost:9090/api/v1/check",
        json={"tool_name": tool_name, "parameters": params}).json()

result = check_permission("Bash", {"command": "rm -rf /"})
if result["permission"] == "deny":
    print(f"Blocked: {result.get('block_reason')}")
```

### 方案三：原生 SDK

**Python**：
```python
from permit0 import Engine

engine = Engine.from_packs("packs", profile="fintech")
result = engine.get_permission("Bash", {"command": "ls"})
print(result.permission)  # Allow | Human | Deny
```

**TypeScript**：
```typescript
import { Engine } from '@permit0/core';
const engine = Engine.fromPacks('packs', 'profiles/fintech.profile.yaml');
const result = engine.getPermission('Bash', { command: 'ls' });
```

---

## API 参考

### REST API（`permit0 serve --ui`）

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/v1/check` | 评估工具调用 |
| `GET` | `/api/v1/health` | 健康检查 |
| `GET` | `/api/v1/stats` | 决策统计 |
| `GET` | `/api/v1/audit` | 查询审计日志 |
| `GET` | `/api/v1/audit/export?format=jsonl\|csv` | 导出审计 |
| `GET` | `/api/v1/approvals` | 待审批列表 |
| `POST` | `/api/v1/approvals/decide` | 提交审批决策 |
| `GET` | `/api/v1/packs` | 列出 Pack |
| `GET/PUT` | `/api/v1/packs/:name/normalizers/:file` | 查看/编辑 Normalizer |
| `GET/PUT` | `/api/v1/packs/:name/risk_rules/:file` | 查看/编辑 Risk Rule |
| `GET` | `/api/v1/profiles` | 列出 Profile |
| `GET/POST/DELETE` | `/api/v1/lists/denylist` | 管理黑名单 |
| `GET/POST/DELETE` | `/api/v1/lists/allowlist` | 管理白名单 |

---

## 管理后台

启动 `permit0 serve --ui --port 9090` 后访问 `http://localhost:9090/ui/`。

| 页签 | 功能 |
|------|------|
| **Dashboard** | 决策统计卡片、最近决策流、系统状态 |
| **Audit Log** | 可筛选审计表、详情展开、JSONL/CSV 导出 |
| **Approvals** | 待审批队列、批准/拒绝、2 秒自动刷新 |
| **Policies** | Pack 编辑器 — 在线编辑 normalizer 和 risk rule |
| **Config** | Profile 查看、Denylist/Allowlist 管理 |
| **Live Monitor** | 实时决策流、Tier 颜色编码、速率统计 |

数据持久化到 `~/.permit0/permit0.db`（SQLite），服务重启不丢失。

---

## Pack 规则系统

Pack 是 permit0 的核心扩展单元，每个 Pack = **normalizer**（标准化规则）+ **risk rule**（风险规则）。

### 内置 Pack

| Pack | 覆盖工具 | Normalizer | Risk Rule |
|------|---------|------------|-----------|
| `claude_code` | Bash, Write, Edit, Read, Glob, Grep, Agent, Web | 9 | 4 |
| `stripe` | charges, refund | 2 | 1 |
| `gmail` | send | 1 | 1 |
| `bank_transfer` | wire, ACH | 1 | 1 |
| `bash` | shell commands | 1 | 1 |
| `filesystem` | read, write | 1 | 1 |

### Normalizer 示例

```yaml
# packs/claude_code/normalizers/bash.yaml
permit0_pack: "permit0/claude_code"
id: "claude_code:bash"
priority: 200

match:
  tool: Bash                       # 匹配工具名

normalize:
  action_type: "process.shell"     # 标准化为 domain.verb
  domain: "process"
  verb: "shell"
  channel: "claude_code"
  entities:
    command:
      from: "command"
      type: "string"
      required: true
```

### Risk Rule 示例

```yaml
# packs/claude_code/risk_rules/file_write.yaml
action_type: "files.write"

base:
  flags: { MUTATION: primary }
  amplifiers: { scope: 4, irreversibility: 5, sensitivity: 3 }

rules:
  - when:
      file_path: { contains_any: [".env", "credentials", "secret"] }
    then:
      - add_flag: { flag: EXPOSURE, role: primary }
      - upgrade: { dim: sensitivity, delta: 20 }

  - when:
      file_path: { contains: ".ssh/" }
    then:
      - gate: "ssh_directory_write"  # 硬阻断

session_rules:
  - when: { record_count: { gt: 8 } }
    then:
      - upgrade: { dim: scope, delta: 6 }
```

### 内置动作类型

| Domain | Verb | 示例 |
|--------|------|------|
| `process` | shell, exec | 执行命令 |
| `files` | read, write, list, delete | 文件操作 |
| `email` | send, forward | 邮件 |
| `payments` | charge, refund, transfer | 支付 |
| `network` | http_get, http_post | 网络 |
| `iam` | assign_role, generate_api_key | 身份 |
| `db` | query, export, drop | 数据库 |
| `secrets` | read, rotate | 密钥 |

### 创建自定义 Pack

```bash
permit0 pack new my_service        # 创建
permit0 pack validate packs/X/     # 验证
permit0 pack test packs/X/         # 测试
```

---

## 风险评分

### 9 个风险标签

| 标签 | 权重 | 说明 |
|------|------|------|
| DESTRUCTION | 0.28 | 不可逆破坏 |
| PHYSICAL | 0.26 | 物理世界影响 |
| EXECUTION | 0.22 | 代码执行 |
| PRIVILEGE | 0.20 | 权限提升 |
| FINANCIAL | 0.20 | 金融影响 |
| EXPOSURE | 0.16 | 数据泄露 |
| GOVERNANCE | 0.14 | 合规问题 |
| OUTBOUND | 0.10 | 外发通信 |
| MUTATION | 0.10 | 数据修改 |

### 7 个放大维度

| 维度 | 权重 | 说明 |
|------|------|------|
| destination | 0.155 | 目标地址 |
| sensitivity | 0.136 | 敏感度 |
| scope | 0.136 | 影响范围 |
| amount | 0.117 | 金额 |
| session | 0.097 | 会话累积 |
| irreversibility | 0.097 | 不可逆 |
| boundary | 0.078 | 边界跨越 |

### 6 步混合评分

```
模板门控 → 阻断规则 → 分类加权 → 乘法复合 → 加法提升 → Tanh 压缩
                                                          ↓
                                               raw ∈ [0, 1] → score ∈ [0, 100]
```

---

## 校准（Calibrate）

permit0 内置一套黄金测试语料库（60 条用例），覆盖 Bash 命令、Stripe 支付、Gmail 邮件、未知工具等场景，用于验证评分引擎在各种工具调用下的分级是否符合预期。

### 校准命令

| 命令 | 用途 |
|------|------|
| `permit0 calibrate test` | 运行全部黄金用例，验证 Tier / Permission 是否匹配预期 |
| `permit0 calibrate diff --profile fintech` | 对比 Profile 与基础配置的权重差异 |
| `permit0 calibrate validate --profile fintech` | 验证 Profile 是否通过安全护栏检查 |

### 黄金用例格式

```yaml
# corpora/calibration/bash_ls.yaml
name: "safe directory listing"
tool_name: "Bash"
parameters:
  command: "ls -la"
expected_tier: "MINIMAL"
expected_permission: "ALLOW"
```

```yaml
# corpora/calibration/stripe_large_charge.yaml
name: "large USD charge over threshold"
tool_name: "stripe_charge"
parameters:
  amount: 50000
  currency: "usd"
expected_tier: "HIGH"
expected_permission: "DENY"
```

### 运行校准测试

```bash
# 使用默认语料库
permit0 calibrate test

# 指定语料库目录
permit0 calibrate test --corpus corpora/calibration

# 使用特定 Profile 校准
permit0 calibrate test --profile fintech

# 查看 Profile 与基准的差异
permit0 calibrate diff --profile healthtech
```

校准测试会逐条评估每个用例，比较实际输出的 Tier 和 Permission 与预期值，输出通过/失败统计和详细差异报告。建议在修改 Pack 或 Profile 后始终运行校准测试，确保不会引入回归。

---

## 领域 Profile

同一引擎，不同标准 — Profile 在基础评分上叠加领域调整。

| Profile | 场景 | 特点 |
|---------|------|------|
| `fintech` | PCI-DSS, SOX | FINANCIAL 权重 1.5x，支付最低 Low |
| `healthtech` | HIPAA | EXPOSURE 权重 1.8x，敏感度放大 1.6x |
| *(默认)* | 通用 | 基础配置 |

```bash
permit0 serve --profile fintech     # 使用金融 profile
permit0 calibrate diff --profile X  # 查看与基础配置差异
```

**安全护栏（不可绕过）**：
- 权重倍率：0.5x – 2.0x
- 阈值偏移上限：±10%
- 不可归零：DESTRUCTION, PHYSICAL, EXECUTION
- 阻断规则只能加严

---

## 审计日志

- **不可篡改** — 哈希链，每条记录包含前一条的哈希
- **可验证** — ed25519 签名
- **合规导出** — JSONL / CSV

```bash
permit0 audit verify FILE --public-key <hex>   # 验证完整性
permit0 audit inspect FILE --limit 50          # 查看摘要
```

Web GUI 的 **Audit Log** 页签也支持在线查看和导出。

---

## 项目结构

```
permit0-core/
├── crates/
│   ├── permit0-engine      # 核心决策管道
│   ├── permit0-scoring     # 6 步混合评分算法
│   ├── permit0-dsl         # YAML DSL 解析器
│   ├── permit0-normalize   # Normalizer 注册匹配
│   ├── permit0-session     # 会话上下文与模式检测
│   ├── permit0-store       # 存储层（InMemory / SQLite）
│   ├── permit0-types       # 共享类型
│   ├── permit0-token       # Biscuit 能力令牌
│   ├── permit0-agent       # LLM Agent 审阅器
│   ├── permit0-ui          # Web 管理后台（axum）
│   ├── permit0-cli         # CLI 入口
│   ├── permit0-py          # Python 绑定（PyO3）
│   └── permit0-node        # TypeScript 绑定（napi-rs）
├── packs/                  # 内置 YAML 规则包
├── profiles/               # 领域校准配置
└── corpora/calibration/    # 60 条黄金测试用例
```

---

## 构建

```bash
cargo build --release --workspace     # 发布构建
cargo test --workspace                # 全部测试
permit0 calibrate test                # 校准测试
```

### CLI 速查

```bash
permit0 check                         # 单次评估
permit0 hook --profile fintech        # Claude Code 钩子
permit0 gateway                       # JSONL 流式网关
permit0 serve --ui --port 9090        # HTTP 服务 + Web GUI
permit0 pack new / validate / test    # Pack 管理
permit0 calibrate test / diff / validate  # 校准
permit0 audit verify / inspect        # 审计
```

**环境要求**：Rust 1.85+, SQLite3

---

## License

Apache-2.0
