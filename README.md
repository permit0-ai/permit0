# permit0

**Runtime permission control framework for AI Agents — deterministic policy execution, risk scoring engine, session awareness, compliance audit**


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
git clone https://github.com/anthropics/permit0.git && cd permit0
cargo build --release

# 2. Start the admin dashboard
cargo run -- serve --ui --port 9090
# Open http://localhost:9090/ui/

# 3. Evaluate a norm action via REST API (no normalizer step)
curl -X POST http://localhost:9090/api/v1/check_action \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"email.send","entities":{"to":"alice@example.com","subject":"hi","body":"ok"}}'
# {"permission":"allow","tier":"LOW","score":17,"channel":"app",...}

# Or evaluate a raw tool call (goes through YAML normalizer first)
curl -X POST http://localhost:9090/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"tool_name":"outlook_send","parameters":{"to":"alice@external.com","subject":"hi","body":"my password is hunter2"}}'
# {"permission":"deny","tier":"CRITICAL","blocked":true,"block_reason":"Highly sensitive data sent to untrusted external destination",...}
```

---

## Email Quick Onboard — Claude Code + Outlook / Gmail

The fastest path to a real, useful permit0 deployment: gate every email
operation Claude Code performs on your **personal Outlook or Gmail account**
through a single PreToolUse hook. ~10 minutes, fully gated, fully audited.

> **Need a zero-to-running walkthrough?** Two formats:
>
> - [**docs/claude-code-integration.md**](docs/claude-code-integration.md) —
>   100-line static recipe you read top-to-bottom.
> - [**skills/permit0-claude-code-setup**](skills/permit0-claude-code-setup/SKILL.md) —
>   a Claude Code skill that walks you through interactively (symlink it
>   into `~/.claude/skills/` and tell Claude "set up permit0 with Claude
>   Code"). See [`skills/README.md`](skills/README.md) for install steps.

### Architecture (single-layer)

```
Claude Code
    │
    ▼  every tool call (built-in + MCP) goes through PreToolUse first
[permit0 hook]  ──▶  strip mcp__<server>__ prefix
                     normalize via packs/email/normalizers/*.yaml
                     score via packs/email/risk_rules/*.yaml
                     ↓
              allow / block / ask_user
                     ↓
         (Claude Code runs the tool only on allow)
                     ↓
        ┌────────────┴─────────────┐
        ▼                          ▼
permit0-outlook-mcp        permit0-gmail-mcp
  (plain MCP wrapper)        (plain MCP wrapper)
        ▼                          ▼
Microsoft Graph              Gmail API
```

The MCP servers are **plain** — they do not import permit0 or call any
policy API. All gating happens at the hook layer in front of Claude Code.

### 1. Start the daemon (calibration mode for first-time use)

```bash
cargo run -p permit0-cli -- serve --calibrate --port 9090
# Open http://localhost:9090/ui/  → Approvals tab will receive every action
```

`--calibrate` makes every fresh decision block on a human approval, so you
can audit each call and build a calibration corpus before flipping to
enforce mode.

### 2. Install the MCP servers

```bash
pip install -e clients/outlook-mcp         # 13 outlook_* tools
pip install -e clients/gmail-mcp           # 13 gmail_* tools  (skip if Gmail not needed)
```

(The `clients/python/` SDK is **optional** — only needed if you want to
write Python code that calls permit0 directly via `@permit0.guard(...)`.
The hook + plain MCP path doesn't need it.)

### 3. Authenticate to your provider

**Outlook (zero-config)** — uses Microsoft's public Graph PowerShell client_id;
no Azure App registration needed:

```bash
python demos/outlook/outlook_test.py list   # one-time device-code login
```

**Gmail** — Google requires a per-user OAuth app:

1. https://console.cloud.google.com/ → create project → enable Gmail API
2. Credentials → OAuth Client ID (Desktop app) → download JSON
3. Save as `~/.permit0/gmail_credentials.json`
4. Run `python -c "from permit0_gmail_mcp.auth import get_token; get_token()"` once

Both flows cache tokens in `~/.permit0/`.

### 4. Wire into Claude Code

**Two files**, different schemas. Use absolute paths
(`~` doesn't expand in JSON, and `permit0` / `permit0-*-mcp` may not
be on Claude Code's PATH).

**Hook** → `~/.claude/settings.json` (the nested-schema file Claude
Code actually reads for hooks):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [{
          "type": "command",
          "command": "/abs/path/to/permit0 hook --db /home/<user>/.permit0/sessions.db"
        }]
      }
    ]
  }
}
```

(Insert at index 0 so permit0 fires before any other PreToolUse hooks.
Omit `matcher` to gate all tool calls, both built-in and MCP-prefixed.)

**MCP servers** → `~/.claude.json`:

```json
{
  "mcpServers": {
    "permit0-outlook": { "command": "/abs/path/to/permit0-outlook-mcp" },
    "permit0-gmail":   { "command": "/abs/path/to/permit0-gmail-mcp" }
  }
}
```

Restart Claude Code. 26 new tools (`outlook_*` + `gmail_*`) appear; the
hook automatically strips the `mcp__<server>__` prefix Claude Code adds
so the bare tool name (`outlook_send`, `gmail_archive`, …) matches the
normalizer YAML.

#### Other agents / MCP hosts

The hook accepts a `--client` flag (or `PERMIT0_CLIENT` env var) to
match how each host namespaces MCP tool names:

| Client | Flag | Tool-name shape | Stripping |
|--------|------|-----------------|-----------|
| Claude Code (terminal) | `--client claude-code` (default) | `mcp__<server>__<tool>` | strips `mcp__X__` |
| Claude Desktop (GUI) | `--client claude-desktop` | `<tool>` (no prefix) | passthrough |
| Direct/test calls | `--client raw` | `<tool>` (no prefix) | passthrough |

When you adopt a new MCP host whose naming differs, run a test call
through the hook, see what the `tool_name` field contains, and either
add a new variant (open a PR) or use `--client raw` if the host already
hands you bare names.

### 5. Talk to Claude Code

> 列出我收件箱里最近 5 封邮件,把所有 newsletter 类的归档

> Send an email to alice@example.com with subject "review" and body
> "please take a look at the attached deck"

Every action shows up in the dashboard's **Approvals** tab in calibration
mode — you see permit0's tier recommendation alongside the full message
content (to / subject / body) and the risk flags that fired (`OUTBOUND`,
`EXPOSURE`, `GOVERNANCE`, …). Approve or deny; your decision is recorded
with engine-vs-human comparison in the **Calibration** tab for offline
analysis.

### 6. From calibration → enforce

After ~10–30 calibrated actions you'll see the agreement rate stabilize.
Switch the daemon to enforce mode:

```bash
cargo run -p permit0-cli -- serve --ui --port 9090   # no --calibrate
```

The policy_cache holds your earlier human decisions, so identical
`norm_hash`-equivalent calls auto-replay your verdict without re-asking.
Adjust `packs/email/risk_rules/*.yaml` to encode any patterns you noticed.

### Email norm actions (15)

The email pack lowers all 26 raw tools (Outlook + Gmail) to the **same**
unified norm action set:

| Action | Behavior |
|--------|----------|
| `email.search` | List/search inbox |
| `email.read` | Read one message |
| `email.read_thread` | Read whole conversation |
| `email.list_mailboxes` | List folders / labels |
| `email.draft` | Create / modify draft (4 sub-modes) |
| `email.send` | Send (4 sub-modes: new / reply / forward / from-draft) |
| `email.mark_read` | Toggle read/unread |
| `email.flag` | Toggle star |
| `email.move` | Move to folder/label |
| `email.archive` | Archive |
| `email.mark_spam` | Mark as spam |
| `email.delete` | Soft delete (Trash / Deleted Items) |
| `email.create_mailbox` | Create folder/label |
| `email.set_forwarding` | **CRITICAL gate** — never auto-allowed |
| `email.add_delegate` | **CRITICAL gate** — never auto-allowed |

The MCP servers do NOT expose `set_forwarding` / `add_delegate` to the
LLM — they're account-takeover vectors. The risk rules still exist so any
other code path that tries them is caught.

### Shadow mode (observe-only)

Want to wire permit0 into Claude Code's PreToolUse hook **before**
enforcing? Use shadow mode — every decision is logged to stderr +
audit log, but the hook always returns `allow`:

```bash
permit0 hook --shadow                              # CLI flag
PERMIT0_SHADOW=1 permit0 hook                      # or env var
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

# Evaluate a raw tool call (goes through YAML normalizer)
curl -X POST http://localhost:9090/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"tool_name":"outlook_send","parameters":{"to":"alice@example.com","subject":"hi","body":"ok"}}'

# Or evaluate a pre-normalized action directly
curl -X POST http://localhost:9090/api/v1/check_action \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"email.send","channel":"app","entities":{"to":"alice@example.com","subject":"hi","body":"ok"}}'
```

**Response**:
```json
{
  "permission": "allow",
  "action_type": "email.send",
  "channel": "outlook",
  "score": 17,
  "tier": "LOW",
  "blocked": false,
  "source": "Scorer"
}
```

### Option 3: Python SDK with `@guard` decorator

The cleanest pattern for application code — declare what your function
does, the decorator gates every call:

```python
import permit0

@permit0.guard("email.send")
def send_via_smtp(to, subject, body):
    smtp.send_message(to=to, subject=subject, body=body)

try:
    send_via_smtp(to="alice@example.com", subject="hi", body="ok")
except permit0.Denied as e:
    print(f"blocked by permit0: {e.decision.block_reason}")
```

The function's keyword arguments become entities; permit0's daemon scores
them against the email risk rules; on `allow` your function runs, on
`deny` / `human` the decorator raises `permit0.Denied`.

### Option 4: Native bindings (Rust / Python PyO3 / TypeScript napi-rs)

```python
from permit0 import Engine
engine = Engine.from_packs("packs")
result = engine.get_permission("outlook_send",
    {"to": "alice@example.com", "subject": "hi", "body": "ok"})
print(result.permission)
```

```typescript
import { Engine } from '@permit0/core';
const engine = Engine.fromPacks('packs');
const result = engine.getPermission('outlook_send',
    { to: 'alice@example.com', subject: 'hi', body: 'ok' });
```

---

## API Reference

### REST API (`permit0 serve --ui`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/check` | Evaluate a raw tool call (goes through YAML normalizer) |
| `POST` | `/api/v1/check_action` | Evaluate a pre-normalized norm action (skips normalizer) |
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/stats` | Decision statistics |
| `GET` | `/api/v1/audit` | Query audit log |
| `GET` | `/api/v1/audit/export?format=jsonl\|csv` | Export audit data |
| `GET` | `/api/v1/approvals` | List pending approvals (incl. entities + flags) |
| `POST` | `/api/v1/approvals/decide` | Submit approval decision |
| `GET` | `/api/v1/calibration/stats` | Calibration analytics (agreement rate, top reviewer, …) |
| `GET` | `/api/v1/calibration/records` | Filtered calibration records (`?agreement=matched\|overridden`) |
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
| **Dashboard** | Decision stats cards, recent decision feed (10s auto-refresh) |
| **Audit Log** | Filterable table with `permit0 said` / `human said` / match? columns; JSONL/CSV export (5s auto-refresh) |
| **Approvals** | Pending approvals showing **full message details** (to/subject/body) + risk flags; approve/deny with reason (2s auto-refresh) |
| **Calibration** | Stats cards (Total / Agreement Rate / Top Reviewer / Most Overridden Action) + filterable records table (matched / overridden) |
| **Policies** | Pack editor — edit normalizers and risk rules online |
| **Config** | Profile viewer, Denylist/Allowlist management |
| **Live Monitor** | Real-time decision feed, Tier color-coded, rate stats |

A login modal on first load asks for a reviewer name (stored in
localStorage) so every approval is attributed. All auto-refresh polls
pause when the browser tab is in the background or you're editing a
filter / approval form.

Data persisted to `~/.permit0/permit0.db` (SQLite), survives service restarts.

---

## Pack Rule System

Packs are permit0's core extension unit. Each Pack = **normalizer** (standardization rules) + **risk rule** (risk evaluation rules).

### Built-in Packs

| Pack | Coverage | Normalizers | Risk Rules |
|------|----------|-------------|------------|
| `email` | All 15 email norm actions × Outlook + Gmail backends | 30 | 15 |

The taxonomy declares **22 domains** total (`email`, `message`, `social`,
`cms`, `newsletter`, `calendar`, `task`, `file`, `db`, `crm`, `payment`,
`legal`, `iam`, `secret`, `infra`, `process`, `network`, `dev`, `browser`,
`device`, `ai`, `unknown`). Only `email` ships with full normalizers and
risk rules today; the rest are placeholders ready for new packs.

### Normalizer Example

```yaml
# packs/email/normalizers/outlook_send.yaml
permit0_pack: "permit0/email"
id: "email:outlook_send"
priority: 105

match:
  tool: outlook_send                       # Raw tool name from MCP server / agent

normalize:
  action_type: "email.send"                # Lower to canonical IR
  domain: "email"
  verb: "send"
  channel: "outlook"                       # Distinguishes backend in audit log
  entities:
    to:       { from: "to",       type: "string" }
    subject:  { from: "subject",  type: "string", optional: true }
    body:     { from: "body",     type: "string", optional: true }
    cc:       { from: "cc",       type: "string", optional: true }
    bcc:      { from: "bcc",      type: "string", optional: true }
    recipient_scope:
      compute: "recipient_scope"           # → "internal" | "external"
      args: ["to", "org_domain"]
```

The Gmail and Outlook backends both have `*_send` normalizers that lower
to the **same** `email.send` norm action — risk rules don't care which
backend the call came from.

### Risk Rule Example

```yaml
# packs/email/risk_rules/send.yaml (excerpt)
action_type: "email.send"

base:
  flags:
    OUTBOUND: primary
    MUTATION: primary
    EXPOSURE: secondary
  amplifiers:
    scope: 18
    irreversibility: 18
    sensitivity: 14
    destination: 28
    boundary: 14

rules:
  # Credentials in body → escalate to HIGH (HITL), not auto-deny
  - when:
      body:
        contains_any: ["password", "api_key", "credential", "token"]
    then:
      - add_flag: { flag: EXPOSURE,   role: primary }
      - add_flag: { flag: GOVERNANCE, role: primary }
      - add_flag: { flag: PRIVILEGE,  role: primary }
      - upgrade:  { dim: sensitivity, delta: 14 }
      - upgrade:  { dim: scope,       delta: 14 }

  # External recipient → escalate to MEDIUM (HITL)
  - when:
      recipient_scope:
        contains: "external"
    then:
      - add_flag: { flag: GOVERNANCE, role: primary }
      - upgrade:  { dim: scope,       delta: 12 }
      - upgrade:  { dim: destination, delta: 8 }

session_rules:
  - when: { emails_sent_today: { gt: 50 } }
    then:
      - upgrade: { dim: scope,  delta: 8 }
      - upgrade: { dim: amount, delta: 6 }
```

### Action Type Taxonomy (Selection)

| Domain | Verbs | Notes |
|--------|-------|-------|
| `email` | search, read, read_thread, list_mailboxes, draft, send, mark_read, flag, move, archive, mark_spam, delete, create_mailbox, set_forwarding, add_delegate | Fully detailed (15 verbs) |
| `payment` | charge, refund, transfer, get_balance, list, get, create, update, cancel_subscription | Placeholder — disambiguate via `resource_type` entity (invoice/subscription/payment_method) |
| `iam` | list, get, create, update, delete, assign_role, revoke_role, reset_password, generate_api_key, revoke_api_key | Placeholder — `resource_type=user|role|api_key` |
| `file` | list, get, read, create, update, delete, delete_recursive, move, copy, share, upload, download, export, search | Placeholder |
| `db` | select, insert, update, delete, create, alter, drop, truncate, grant_access, revoke_access, export, backup, restore | Placeholder — `resource_type=table|index|database` for create/alter/drop |
| `process` | run, invoke | Placeholder — `resource_type=shell|script|container|function` |
| `network` | get, post, put, delete, send_webhook | Placeholder |
| `dev` | list, get, create, update, close_issue, merge_pr, push_code, deploy, run_pipeline | Placeholder |
| `browser` | navigate, click, fill_form, submit_form, take_screenshot, download_file, execute_js, scrape | Placeholder |
| `ai` | prompt, embed, fine_tune, invoke_agent, generate_image | Placeholder |

Generic verbs (`get`, `list`, `create`, `update`, `delete`, `search`,
`export`) are reused across many domains. When a single verb covers
multiple resource types within a domain, the normalizer extracts a
`resource_type` entity rather than introducing per-type verbs — keeps
the verb space small and makes risk rules reusable.

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

permit0 has two layers of calibration:

1. **Golden test corpus** (`corpora/calibration/`) — YAML fixtures asserting
   `(tool_call, expected_tier, expected_permission)`. Run via
   `permit0 calibrate test`. Currently ships with 2 starter email cases;
   add your own as you expand packs.
2. **Live human-in-the-loop calibration** (`serve --calibrate`) — every
   fresh decision blocks on a human approval; the human's choice is
   recorded alongside permit0's recommendation so you can compute
   agreement rate, find disagreements, and tune risk rules from real
   workload. Dashboard's **Calibration** tab shows stats and lets you
   filter by `matched` vs `overridden`.

### Calibration Commands

| Command | Purpose |
|---------|---------|
| `permit0 calibrate test` | Run all golden test cases, verify Tier / Permission matches expectations |
| `permit0 calibrate diff --profile fintech` | Compare Profile vs. base configuration weight differences |
| `permit0 calibrate validate --profile fintech` | Verify Profile passes safety guardrail checks |

### Golden Test Case Format

```yaml
# corpora/calibration/001-gmail-simple-email.yaml
name: gmail_simple_email
tool_name: gmail_send
parameters:
  to: "bob@external.com"
  subject: "Hello"
  body: "Quick note"
expected_tier: "Minimal"
expected_permission: "Allow"
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
permit0/
├── crates/
│   ├── permit0-engine          # Core decision pipeline
│   ├── permit0-scoring         # 6-step hybrid scoring algorithm
│   ├── permit0-dsl             # YAML DSL parser
│   ├── permit0-normalize       # Normalizer registry & matching
│   ├── permit0-session         # Session context & pattern detection
│   ├── permit0-store           # Storage layer (InMemory / SQLite)
│   ├── permit0-types           # Shared types + action taxonomy
│   ├── permit0-token           # Biscuit capability tokens
│   ├── permit0-agent           # LLM Agent reviewer
│   ├── permit0-ui              # Web admin dashboard (axum)
│   ├── permit0-cli             # CLI entry point
│   ├── permit0-shell-dispatch  # Bash → tool-call dispatcher
│   ├── permit0-py              # Python bindings (PyO3)
│   └── permit0-node            # TypeScript bindings (napi-rs)
├── clients/
│   ├── python/                 # @permit0.guard decorator (HTTP SDK)
│   ├── outlook-mcp/            # Outlook MCP server (Microsoft Graph)
│   └── gmail-mcp/              # Gmail MCP server (Gmail API)
├── packs/
│   └── email/                  # 30 normalizers + 15 risk rules
├── profiles/                   # Domain calibration profiles
├── corpora/calibration/        # Golden test cases (YAML fixtures)
└── demos/outlook/              # Standalone CLI demo (no MCP)
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
permit0 check                            # Single evaluation
permit0 hook                             # PreToolUse hook (default --client claude-code)
permit0 hook --client claude-desktop     #   for Claude Desktop GUI
permit0 hook --client raw                #   no MCP prefix stripping
permit0 hook --shadow                    #   observe-only (always allow, log to stderr)
permit0 gateway                          # JSONL streaming gateway
permit0 serve --ui --port 9090           # HTTP daemon + Web admin dashboard
permit0 serve --calibrate                #   every fresh decision blocks on human approval
permit0 pack new / validate / test       # Pack management
permit0 calibrate test / diff / validate # Run golden test corpus
permit0 audit verify / inspect           # Audit chain verification
```

**Requirements**: Rust 1.85+, SQLite3

---

## License

Apache-2.0
