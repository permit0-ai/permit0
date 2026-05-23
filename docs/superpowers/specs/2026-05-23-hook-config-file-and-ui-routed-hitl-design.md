# Hook config file + UI-routed HITL

**Date:** 2026-05-23
**Status:** Approved design — ready for implementation plan
**Branch:** `extract-email-mcp`

## 1. Context & problem

Two related shortcomings in the permit0 hook today:

1. **HITL always prompts Claude Code inline.** When `permit0 hook --remote …`
   gets a `humanintheloop` verdict, it emits Claude Code's `permissionDecision:
   "ask"`. There is no way to route the decision to the existing dashboard at
   `:9090/approvals` and have the human resolve it there — even though the
   dashboard, the `GET /api/v1/approvals` endpoint, the `POST
   /api/v1/approvals/decide` endpoint, and `ApprovalManager` (with `oneshot`
   block-and-wait channels) already exist. The engine's `get_permission` never
   calls `ApprovalManager::create_pending`, so the approvals view is empty.

2. **Hook options are scattered across flags and env vars.** `--unknown`,
   `--org-domain`, `--client`, `--shadow`, `--remote`, and friends are passed
   on every invocation through `.claude/settings.local.json` or the CLI. There
   is no single per-user config file that holds these.

## 2. Goals & non-goals

**Goals**

1. A per-user TOML config file at `~/.config/permit0/config.toml` (overridable
   via `PERMIT0_CONFIG` env or a `--config <path>` CLI flag) holding all
   hook-side options.
2. A `hitl_routing` knob with two modes:
   - `cc-prompt` (default) — unchanged behavior; Claude Code's inline ask UI.
   - `ui-wait` — the hook blocks at the engine until a human approves or
     denies the request in the dashboard, then returns the resolved verdict
     to Claude Code as a definitive `allow` or `deny`.
3. Preserved backward compatibility: existing deployments keep working with
   no config file present.

**Non-goals**

- A daemon-side TOML config (env vars and CLI flags stay as the daemon's
  configuration surface).
- Project-local config files (per-user only, by user choice).
- Per-tool or per-tier routing overrides (one global `hitl_routing`).
- A "fire and deny" async mode (rejected during brainstorming in favor of
  block-and-wait, which preserves the agent flow).

## 3. Design — Part A: hook config file

### 3.1 Path and discovery

The hook resolves the config path in this order:

1. `--config <path>` CLI flag, if present.
2. `$PERMIT0_CONFIG`, if set.
3. `~/.config/permit0/config.toml`, if present.
4. No file — use defaults.

A missing file is fine. A file present but malformed is a fatal error — the
hook exits with a clear message rather than silently falling back. Mis-config
in a security tool must fail loud.

### 3.2 Schema

All fields are optional with the same defaults as today's CLI flags / env vars:

```toml
# Remote daemon URL. If unset, the hook uses --remote, then errors if neither.
remote = "http://127.0.0.1:9090"

# How HITL verdicts are routed.
#   "cc-prompt" (default) — Claude Code's inline ask UI
#   "ui-wait"             — block at the hook until a human approves
#                            in the dashboard at the remote URL
hitl_routing = "cc-prompt"

# ui-wait block timeout in seconds. On expiry → auto-deny.
hitl_timeout_secs = 300

# What permit0 emits when no pack matches.
#   "ask" | "allow" | "deny" | "defer" (default: "defer")
unknown_mode = "defer"

# Organization domain — drives internal/external recipient classification
# in the email pack.
org_domain = "example.com"

# MCP client format (prefix-stripping):
#   "claude-code" (default) | "claude-desktop" | "openclaw" | "raw"
client = "claude-code"

# Shadow mode — log decisions but never block (safe rollout).
shadow = false
```

### 3.3 Precedence

Per-field, lowest → highest wins:

`built-in default < config file < env var < CLI flag`

Each field falls through layers independently. Existing env vars
(`PERMIT0_SHADOW`, `PERMIT0_CONFIG`, etc.) keep their current semantics.

### 3.4 Implementation surface

- **New** `crates/permit0-cli/src/hook_config.rs`:
  - `pub struct HookConfig { fields: Option<T> }` derived `Deserialize`.
  - `pub fn load(explicit: Option<&Path>) -> Result<HookConfig>` — resolves
    the path per §3.1, parses TOML, returns the struct.
  - `pub fn merge_with_cli(self, cli: HookCliArgs) -> ResolvedHookConfig` —
    layers env vars and CLI flags over the file values.
- **Modify** `crates/permit0-cli/src/cmd/hook.rs::run()` — call
  `HookConfig::load()`, merge, use the resolved values throughout. Existing
  function signature unchanged externally.
- **Modify** `crates/permit0-cli/src/main.rs` — add a `--config <path>`
  optional global flag (or under the `hook` subcommand only — pick whichever
  matches existing patterns).

Toml is already a workspace dependency. No new external deps.

## 4. Design — Part B: UI-routed HITL ("ui-wait")

### 4.1 Mode selection: per-request

When `hitl_routing = "ui-wait"`, the hook adds two fields to its `POST
/api/v1/check` request body:

```json
{
  "tool_name": "...",
  "parameters": { ... },
  "hitl_routing": "ui-wait",
  "hitl_timeout_secs": 300
}
```

If `hitl_routing` is absent or `"cc-prompt"`, the engine behaves exactly as
today. Different clients (different projects, different operators) can
therefore run different routing against the same daemon.

### 4.2 Engine HTTP handler (`crates/permit0-ui/src/routes.rs`)

`CheckRequest` gains two optional fields: `hitl_routing: Option<String>` and
`hitl_timeout_secs: Option<u64>`.

The `check` handler:

1. Calls `engine.get_permission(...)` as today.
2. If `result.permission == HumanInTheLoop` **and**
   `req.hitl_routing == Some("ui-wait")`:
   1. `approval_id = approval_manager.create_pending(norm_action, risk_score)`
   2. Persist a `PendingApprovalRow` to `state.approval_create(...)` so the
      approval survives engine restart (`approval_list_pending` already
      drives the UI's listing).
   3. `decision = approval_manager.await_decision(approval_id, timeout)` —
      a `oneshot::Receiver` wrapped in `tokio::time::timeout`.
   4. On `Ok(d)`:
      - If `d.permission != HumanInTheLoop`, call
        `state.policy_cache_set(norm_hash, d.permission, Some(risk_score))`
        so future identical calls hit the cache.
      - Persist resolution via `state.approval_resolve(approval_id,
        HumanDecisionRow { ... })`.
      - Set `result.permission = d.permission`,
        `result.source = DecisionSource::HumanApproval`.
   5. On `Err(timeout)`:
      - `result.permission = Deny`.
      - `result.block_reason = "approval timed out after {N}s"`.
3. If the daemon is built without an `ApprovalManager` (e.g. running
   `serve` without `--ui`), return HTTP 400 with body
   `"ui-wait routing not supported by this daemon"`. The hook then surfaces
   this as a deny to Claude Code so the operator sees the mis-config.
4. Return the resulting `CheckResponse` (the existing JSON shape; the hook
   already knows how to translate it).

`Engine::get_permission` itself is unchanged. All wait logic lives in the
HTTP handler that already owns the `ApprovalManager`.

### 4.3 New `DecisionSource` variant

`crates/permit0-engine/src/engine.rs` — add `DecisionSource::HumanApproval`
with the audit-log string `"human_approval"`. Distinguishes a human-resolved
HITL from an auto-resolved one in the audit chain.

### 4.4 Hook-side response handling

`crates/permit0-cli/src/cmd/hook.rs` already maps the remote response's
`permission` to Claude Code's envelope:

- `"allow"` → `permissionDecision: "allow"`.
- `"deny"` → `permissionDecision: "deny"` with the block reason.
- `"humanintheloop"` → `permissionDecision: "ask"`.

No change is needed: in `ui-wait` mode the engine returns `allow` / `deny`
(the resolved verdict), and the hook emits the matching envelope. A
defensive `ask` fallback (engine returned `humanintheloop` despite the
client asking for `ui-wait`) keeps existing behavior.

## 5. Testing

### 5.1 Hook config

- TOML parse: empty file, all fields, partial file, unknown field (ignore
  per serde default).
- Path resolution: explicit `--config`, `$PERMIT0_CONFIG`, default path,
  none (use defaults).
- Precedence: one test per layer pair (default vs file, file vs env, env vs
  CLI) confirming the higher layer wins.
- Malformed TOML → fatal exit with a useful error message (not silent
  defaults).

### 5.2 UI-wait routing

- HTTP test against the in-process engine + `ApprovalManager`:
  - Request without `hitl_routing` → HITL verdict returned immediately (no
    behavior change).
  - Request with `"ui-wait"` + injected human approval → resolved verdict
    returned; subsequent identical request hits the policy cache.
  - Request with `"ui-wait"` + no decision within the timeout → response is
    `permission: "deny"` with the timeout `block_reason`.
- Daemon built without `ApprovalManager` (no `--ui`) → 400 with the
  "not supported" message.
- New `DecisionSource::HumanApproval` shows up in the audit entry's
  `source` field.

### 5.3 Workspace gate

- `cargo nextest run --workspace` (or `cargo test --workspace`) green.
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `cargo fmt --all --check` clean.
- `cargo run -- calibrate test` unchanged (no pack changes here).

## 6. Rollout

- New code on the current branch. No DB migration needed (the
  `pending_approvals` and `cache_meta` tables already exist).
- Hook is backward compatible: no file → defaults → identical to today.
- To enable `ui-wait`:
  1. Create `~/.config/permit0/config.toml` with `hitl_routing = "ui-wait"`.
  2. Rebuild the engine Docker image (handler code change).
  3. Bring up `serve --ui` (the dashboard must be running to surface
     pending approvals).
  4. Trigger a HITL — observe the approval card appear at
     `http://localhost:9090`, approve, see the agent's tool call proceed.

## 7. Risks & open questions

- **Claude Code hook timeout.** If CC's PreToolUse hook has an upper limit
  shorter than `hitl_timeout_secs`, the hook process will be killed before
  the human responds. Documented default is 300 s; operators with stricter
  CC environments should lower the value. The cached resolution (Allow/Deny
  after `policy_cache_set`) still benefits the *next* call.
- **Connection drop mid-wait.** If the hook's TCP connection drops while
  waiting, the engine's `await_decision` future is still active until the
  human responds or the timeout fires; the resolution is persisted via
  `approval_resolve` and the cache, so the next equivalent call gets the
  benefit. The dropped call surfaces a generic transport error in CC.
- **Multiple in-flight identical norm_hashes.** Two simultaneous calls with
  the same `norm_hash` create two separate pending approvals (different
  `approval_id`s). A future enhancement could coalesce them; not in scope.
- **`ApprovalManager` is in-process.** A multi-process daemon would lose
  the `oneshot` channel across instances. Single-process daemon today (one
  container) — fine. Out of scope to change.

## 8. Change inventory

| Area | Files |
|------|-------|
| Hook config | **new** `crates/permit0-cli/src/hook_config.rs` |
| Hook entry | `crates/permit0-cli/src/cmd/hook.rs`, `crates/permit0-cli/src/main.rs` |
| HTTP handler | `crates/permit0-ui/src/routes.rs` (extend `CheckRequest`, add wait path) |
| Audit source | `crates/permit0-engine/src/engine.rs` (new `DecisionSource::HumanApproval`) |
| (Already exists; just used) | `crates/permit0-ui/src/approval.rs`, the `/api/v1/approvals` routes, `index.html`'s approvals view |
