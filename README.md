# permit0

**Runtime permission control framework for AI Agents — deterministic policy execution, risk scoring engine, session awareness, compliance audit**

English | [简体中文](README.zh.md)

---

> **This is not a prompt guardrail or content moderation tool.**
> permit0 governs Agent **actions (tool calls)**, not LLM input/output.

```
Agent actions (tool calls) ──► Normalize ──► Session-aware deterministic risk scoring ──► Allow / Deny / Optional Agent Review (→ Human / Deny) ──► Audit log
```

**Deterministic policies vs. probabilistic approaches:** Rule-based policy execution, no LLM dependency for policy decisions — zero violation rate, auditable, reproducible.

---

## What This Is (and Isn't)

| | permit0 | Prompt Guardrails |
|---|---|---|
| **Governs** | Agent tool calls (Bash, HTTP, file write…) | LLM input/output text |
| **Decision method** | Deterministic rule engine, 0% false positives | Probabilistic model, false positives exist |
| **Latency** | < 0.1ms per call | 50–500ms (requires LLM call) |
| **Auditable** | Hash chain + ed25519 signatures | No audit chain |
| **Session-aware** | Cross-call pattern detection, attack chain identification | Single-call judgment |

---

## Quick Start

```bash
# 1. Install
git clone https://github.com/anthropics/permit0-core.git && cd permit0-core
cargo build --release

# 2. Start the admin dashboard
cargo run -- serve --ui --port 9090
# Open http://localhost:9090/ui/

# 3. Evaluate tool calls via REST API
curl -X POST http://localhost:9090/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"tool_name":"Bash","parameters":{"command":"ls -la"}}'
# ✓ {"permission":"Allow","tier":"MINIMAL","score":9,...}

curl -X POST http://localhost:9090/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"tool_name":"Bash","parameters":{"command":"sudo rm -rf /"}}'
# ✗ {"permission":"Deny","tier":"CRITICAL","score":100,...}
```

### Docker Deployment

```bash
docker compose up -d
# Visit http://localhost:9090/ui/
```

---

## Features

| Capability | Description | Status |
|------------|-------------|--------|
| **Policy Engine** | YAML DSL for normalizers + risk rules, 6-step hybrid scoring algorithm | Available |
| **Session Awareness** | Cross-call cumulative tracking, frequency detection, attack chain identification | Available |
| **Three-Layer Calibration** | Base → Profile (fintech/healthtech) → Org policy, safety guardrails cannot be bypassed | Available |
| **Compliance Audit** | Hash chain + ed25519 signatures, JSONL/CSV export, tamper-proof | Available |
| **Agent Review** | Medium-risk actions reviewed by LLM Agent first, escalated to human if uncertain | Available |
| **Human Approval** | Routes to Human-in-the-loop when Agent Review is uncertain, Web GUI or CLI approval | Available |
| **Admin Dashboard** | 6-tab Dashboard: audit log, approvals, policy editor, config, live monitor | Available |
| **Denylist / Allowlist** | norm_hash-based deny/allow lists, takes effect immediately | Available |
| **CLI Tools** | check / hook / gateway / serve / calibrate / audit commands | Available |
| **Python SDK** | PyO3 native bindings, `import permit0` directly | Available |
| **TypeScript SDK** | napi-rs native bindings, `@permit0/core` | Available |

---

## Fits Your Stack

### Agent Framework Integration

| Framework | Integration | Notes |
|-----------|-------------|-------|
| **Claude Code** | `PreToolUse` Hook | Native support, one-line config |
| **OpenAI Agents** | HTTP Sidecar | `POST /api/v1/check` |
| **LangChain** | Python SDK | `engine.get_permission(tool, params)` |
| **CrewAI** | Python SDK | Same as above |
| **AutoGen** | Python SDK / HTTP | Both methods work |
| **Custom Agent** | HTTP / Gateway | REST API or JSONL pipe |

### Run Modes

| Mode | Command | Use Case |
|------|---------|----------|
| **Hook** | `permit0 hook` | Claude Code PreToolUse hook |
| **Serve** | `permit0 serve --ui` | HTTP daemon + Web admin dashboard |
| **Gateway** | `permit0 gateway` | JSONL pipe, batch processing |
| **Check** | `permit0 check` | Single evaluation, debugging |

### Multi-Language SDKs

| Language | Install | Minimum Version |
|----------|---------|-----------------|
| **Rust** | `cargo add permit0-engine` | 1.85+ |
| **Python** | `pip install permit0` | 3.9+ |
| **TypeScript** | `npm install @permit0/core` | Node 18+ |

---

## Architecture

```
                         ┌─────────────────────────────────┐
                         │         permit0 Engine           │
                         ├─────────────────────────────────┤
  Tool Calls             │                                 │
  (Bash, HTTP,  ───────► │  1. Normalize (YAML Pack)       │
   Write, ...)           │  2. Denylist / Allowlist         │
                         │  3. Risk Scoring (6-step hybrid) │
                         │  4. Session Amplifier            │  ┌──────────┐
                         │  5. Tier Routing                 ├─►│  Allow   │
                         │     Minimal/Low  → Allow         │  │  Deny    │
                         │     High/Critical→ Deny          │  └──────────┘
                         │     Medium ──┐                   │
                         │              ▼                   │
                         │  6. Agent Review (LLM Review)    │
                         │     ├─ Rejected → Deny           │
                         │     └─ Uncertain→ Human-in-loop  │
                         │  7. Audit Log (hash chain + sig) │
                         └─────────────────────────────────┘
                                      ↑
                           Three-Layer Calibration
                        Base → Domain → Org Policy
```

### Decision Pipeline

1. **Normalize** — Raw tool call → standardized `NormAction` (`domain.verb` format)
2. **Denylist** — norm_hash hits denylist → immediate Deny
3. **Allowlist** — norm_hash hits allowlist → immediate Allow
4. **Policy Cache** — Cache hit → return cached decision
5. **Unknown Action** — No risk rule → Human-in-the-loop (conservative policy)
6. **Risk Scoring** — DSL rules + hybrid algorithm → score 0–100
7. **Session Amplification** — Historical actions, frequency patterns → adjust score
8. **Tier Routing** — Score → Tier → decision (Minimal/Low → Allow, High/Critical → Deny)
9. **Agent Review** — Medium-risk actions reviewed by LLM Agent: rejected → Deny, uncertain → escalate to Human-in-the-loop
10. **Audit Record** — Hash chain + ed25519 signature
11. **Return Result** — `{ permission, action_type, score, tier, source }`

### Risk Tiers

| Tier | Score | Decision | Example |
|------|-------|----------|---------|
| Minimal | 0–15 | Allow | `ls -la`, file reads |
| Low | 15–35 | Allow | Standard file writes |
| Medium | 35–55 | Agent Review → Human | Network requests, sensitive file ops |
| High | 55–75 | Deny | Large payments, permission changes |
| Critical | 75–100 | Deny | `rm -rf /`, SSH key writes |

---

## Integration Guide

### Option 1: Claude Code Integration (Recommended)

Add to `~/.claude/settings.json`:

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

Every tool call in Claude Code will be automatically evaluated by permit0.

### Option 2: HTTP API (Universal, any framework)

```bash
# Start the service
permit0 serve --ui --port 9090

# Evaluate a tool call
curl -X POST http://localhost:9090/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"tool":"Bash","input":{"command":"ls"}}'
```

**Response**:
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

**Python client**:
```python
import requests

def check_permission(tool_name: str, params: dict) -> dict:
    return requests.post("http://localhost:9090/api/v1/check",
        json={"tool_name": tool_name, "parameters": params}).json()

result = check_permission("Bash", {"command": "rm -rf /"})
if result["permission"] == "deny":
    print(f"Blocked: {result.get('block_reason')}")
```

### Option 3: Native SDK

**Python**:
```python
from permit0 import Engine

engine = Engine.from_packs("packs", profile="fintech")
result = engine.get_permission("Bash", {"command": "ls"})
print(result.permission)  # Allow | Human | Deny
```

**TypeScript**:
```typescript
import { Engine } from '@permit0/core';
const engine = Engine.fromPacks('packs', 'profiles/fintech.profile.yaml');
const result = engine.getPermission('Bash', { command: 'ls' });
```

---

## API Reference

### REST API (`permit0 serve --ui`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/check` | Evaluate a tool call |
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/stats` | Decision statistics |
| `GET` | `/api/v1/audit` | Query audit log |
| `GET` | `/api/v1/audit/export?format=jsonl\|csv` | Export audit data |
| `GET` | `/api/v1/approvals` | List pending approvals |
| `POST` | `/api/v1/approvals/decide` | Submit approval decision |
| `GET` | `/api/v1/packs` | List packs |
| `GET/PUT` | `/api/v1/packs/:name/normalizers/:file` | View/edit normalizer |
| `GET/PUT` | `/api/v1/packs/:name/risk_rules/:file` | View/edit risk rule |
| `GET` | `/api/v1/profiles` | List profiles |
| `GET/POST/DELETE` | `/api/v1/lists/denylist` | Manage denylist |
| `GET/POST/DELETE` | `/api/v1/lists/allowlist` | Manage allowlist |

---

## Admin Dashboard

Start `permit0 serve --ui --port 9090` and visit `http://localhost:9090/ui/`.

| Tab | Functionality |
|-----|---------------|
| **Dashboard** | Decision stats cards, recent decision feed, system status |
| **Audit Log** | Filterable audit table, detail expansion, JSONL/CSV export |
| **Approvals** | Pending approval queue, approve/deny, 2s auto-refresh |
| **Policies** | Pack editor — edit normalizers and risk rules online |
| **Config** | Profile viewer, Denylist/Allowlist management |
| **Live Monitor** | Real-time decision feed, Tier color-coded, rate stats |

Data persisted to `~/.permit0/permit0.db` (SQLite), survives service restarts.

---

## Pack Rule System

Packs are permit0's core extension unit. Each Pack = **normalizer** (standardization rules) + **risk rule** (risk evaluation rules).

### Built-in Packs

| Pack | Tools Covered | Normalizers | Risk Rules |
|------|---------------|-------------|------------|
| `claude_code` | Bash, Write, Edit, Read, Glob, Grep, Agent, Web | 9 | 4 |
| `stripe` | charges, refund | 2 | 1 |
| `gmail` | send | 1 | 1 |
| `bank_transfer` | wire, ACH | 1 | 1 |
| `bash` | shell commands | 1 | 1 |
| `filesystem` | read, write | 1 | 1 |

### Normalizer Example

```yaml
# packs/claude_code/normalizers/bash.yaml
permit0_pack: "permit0/claude_code"
id: "claude_code:bash"
priority: 200

match:
  tool: Bash                       # Match tool name

normalize:
  action_type: "process.shell"     # Standardize to domain.verb
  domain: "process"
  verb: "shell"
  channel: "claude_code"
  entities:
    command:
      from: "command"
      type: "string"
      required: true
```

### Risk Rule Example

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
      - gate: "ssh_directory_write"  # Hard block

session_rules:
  - when: { record_count: { gt: 8 } }
    then:
      - upgrade: { dim: scope, delta: 6 }
```

### Built-in Action Types

| Domain | Verb | Example |
|--------|------|---------|
| `process` | shell, exec | Execute commands |
| `files` | read, write, list, delete | File operations |
| `email` | send, forward | Email |
| `payments` | charge, refund, transfer | Payments |
| `network` | http_get, http_post | Network |
| `iam` | assign_role, generate_api_key | Identity |
| `db` | query, export, drop | Database |
| `secrets` | read, rotate | Secrets |

### Create Custom Packs

```bash
permit0 pack new my_service        # Create
permit0 pack validate packs/X/     # Validate
permit0 pack test packs/X/         # Test
```

---

## Risk Scoring

### 9 Risk Flags

| Flag | Weight | Description |
|------|--------|-------------|
| DESTRUCTION | 0.28 | Irreversible destruction |
| PHYSICAL | 0.26 | Physical world impact |
| EXECUTION | 0.22 | Code execution |
| PRIVILEGE | 0.20 | Privilege escalation |
| FINANCIAL | 0.20 | Financial impact |
| EXPOSURE | 0.16 | Data exposure |
| GOVERNANCE | 0.14 | Compliance concerns |
| OUTBOUND | 0.10 | Outbound communication |
| MUTATION | 0.10 | Data modification |

### 7 Amplifier Dimensions

| Dimension | Weight | Description |
|-----------|--------|-------------|
| destination | 0.155 | Target address |
| sensitivity | 0.136 | Sensitivity level |
| scope | 0.136 | Impact scope |
| amount | 0.117 | Monetary amount |
| session | 0.097 | Session accumulation |
| irreversibility | 0.097 | Irreversibility |
| boundary | 0.078 | Boundary crossing |

### 6-Step Hybrid Scoring

```
Template Gate → Block Rules → Category Weighting → Multiplicative Compound → Additive Boost → Tanh Compression
                                                                                                    ↓
                                                                                         raw ∈ [0, 1] → score ∈ [0, 100]
```

---

## Calibration

permit0 includes a golden test corpus (60 test cases) covering Bash commands, Stripe payments, Gmail emails, unknown tools, and more. Use it to verify that the scoring engine classifies tool calls into the expected tiers.

### Calibration Commands

| Command | Purpose |
|---------|---------|
| `permit0 calibrate test` | Run all golden test cases, verify Tier / Permission matches expectations |
| `permit0 calibrate diff --profile fintech` | Compare Profile vs. base configuration weight differences |
| `permit0 calibrate validate --profile fintech` | Verify Profile passes safety guardrail checks |

### Golden Test Case Format

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

### Running Calibration Tests

```bash
# Use default corpus
permit0 calibrate test

# Specify corpus directory
permit0 calibrate test --corpus corpora/calibration

# Calibrate with a specific Profile
permit0 calibrate test --profile fintech

# View Profile vs. baseline differences
permit0 calibrate diff --profile healthtech
```

Calibration tests evaluate each case against the full engine pipeline, comparing actual Tier and Permission output against expectations, and producing pass/fail statistics with detailed diff reports. Always run calibration tests after modifying Packs or Profiles to catch regressions.

---

## Domain Profiles

Same engine, different standards — Profiles layer domain-specific adjustments on top of the base scoring.

| Profile | Scenario | Characteristics |
|---------|----------|-----------------|
| `fintech` | PCI-DSS, SOX | FINANCIAL weight 1.5x, payments floor at Low |
| `healthtech` | HIPAA | EXPOSURE weight 1.8x, sensitivity amplifier 1.6x |
| *(default)* | General | Base configuration |

```bash
permit0 serve --profile fintech     # Use fintech profile
permit0 calibrate diff --profile X  # View diff from base config
```

**Safety Guardrails (cannot be bypassed)**:
- Weight multiplier range: 0.5x – 2.0x
- Threshold offset cap: ±10%
- Cannot zero out: DESTRUCTION, PHYSICAL, EXECUTION
- Block rules can only be made stricter

---

## Audit Log

- **Tamper-proof** — Hash chain, each record includes the previous record's hash
- **Verifiable** — ed25519 signatures
- **Compliance export** — JSONL / CSV

```bash
permit0 audit verify FILE --public-key <hex>   # Verify integrity
permit0 audit inspect FILE --limit 50          # View summary
```

The **Audit Log** tab in the Web GUI also supports online viewing and export.

---

## Project Structure

```
permit0-core/
├── crates/
│   ├── permit0-engine      # Core decision pipeline
│   ├── permit0-scoring     # 6-step hybrid scoring algorithm
│   ├── permit0-dsl         # YAML DSL parser
│   ├── permit0-normalize   # Normalizer registry & matching
│   ├── permit0-session     # Session context & pattern detection
│   ├── permit0-store       # Storage layer (InMemory / SQLite)
│   ├── permit0-types       # Shared types
│   ├── permit0-token       # Biscuit capability tokens
│   ├── permit0-agent       # LLM Agent reviewer
│   ├── permit0-ui          # Web admin dashboard (axum)
│   ├── permit0-cli         # CLI entry point
│   ├── permit0-py          # Python bindings (PyO3)
│   └── permit0-node        # TypeScript bindings (napi-rs)
├── packs/                  # Built-in YAML rule packs
├── profiles/               # Domain calibration profiles
└── corpora/calibration/    # 60 golden test cases
```

---

## Building

```bash
cargo build --release --workspace     # Release build
cargo test --workspace                # All tests
permit0 calibrate test                # Calibration tests
```

### CLI Quick Reference

```bash
permit0 check                         # Single evaluation
permit0 hook --profile fintech        # Claude Code hook
permit0 gateway                       # JSONL streaming gateway
permit0 serve --ui --port 9090        # HTTP service + Web GUI
permit0 pack new / validate / test    # Pack management
permit0 calibrate test / diff / validate  # Calibration
permit0 audit verify / inspect        # Audit
```

**Requirements**: Rust 1.85+, SQLite3

---

## License

Apache-2.0
