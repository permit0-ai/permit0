# 05 — Known Limitations and Future Work

**Status:** Draft
**Revised:** 2026-05-10
**Depends on:** 01-protocol, 02-implementation

## v1 Limitations

### 1. No Native HITL / Ask Verdict

**Problem:** Codex `PreToolUse` does not support `permissionDecision: "ask"`.
Unlike Claude Code, there is no way for a hook to trigger an interactive
approval prompt from within `PreToolUse`.

**v1 workaround:** `Permission::HumanInTheLoop` is mapped to `deny` with an
informative reason string that includes the action type, risk score, tier, and
active flags. The user sees the deny message and must manually re-authorize
(e.g., add the action to the allowlist via the dashboard, or re-run the
command).

**Impact:** Medium-tier and high-tier actions that Claude Code would show as
an approval prompt are instead hard-blocked in Codex. This is more
conservative (fail-closed) but less ergonomic. Users may need to interact
with the permit0 dashboard more frequently to approve actions.

**v2 plan:** Use the `PermissionRequest` hook (see below).

### 2. `permissionDecision: "allow"` Is Rejected

**Problem:** Codex explicitly rejects `permissionDecision: "allow"` in
`PreToolUse` hooks. If a hook accidentally outputs this, the tool executes
anyway (fail-open) with a warning, defeating the purpose.

**v1 workaround:** The hook exits 0 with empty stdout for allowed actions.
The implementation must never produce a JSON response containing
`"permissionDecision": "allow"`. Unit tests enforce this invariant.

**Risk:** If a code change accidentally emits `"allow"`, Codex will log a
warning but the tool still runs. The failure mode is silent governance bypass.
The test suite includes a specific test (`codex_output_never_contains_allow`)
to catch this at CI time.

### 3. `unified_exec` Shell Calls Are Not Intercepted

**Problem:** Codex's newer `unified_exec` mechanism provides richer streaming
stdin/stdout handling for shell commands, but `PreToolUse` hooks do not
intercept these calls. Only "simple" shell calls routed through the legacy
`Bash` tool path are intercepted.

**Impact:** Some shell commands may bypass permit0 entirely. The Codex team
has acknowledged this as an incomplete interception boundary.

**Mitigation:** None available at the hook level. Users should be aware that
permit0 on Codex is a guardrail, not a complete enforcement boundary, as
documented by Codex's own hook documentation.

### 4. WebSearch and Non-Shell/Non-MCP Tools Are Not Intercepted

**Problem:** `PreToolUse` hooks do not fire for `WebSearch` or other tool
types outside the shell/file-edit/MCP categories.

**Impact:** Web searches, image generation, and other built-in Codex tools
are invisible to permit0.

**Mitigation:** These tools are generally lower-risk (read-only web search,
no side effects). If governance of these tools is required, it must wait for
Codex to expand hook coverage.

### 5. `additionalContext` Not Injected Into Model

**Problem:** Codex parses the `additionalContext` field from `PreToolUse`
hook output, but does not inject it into model continuations. This means
permit0 cannot influence the model's subsequent behavior by providing context
about risk assessments.

**Impact:** Low. permit0's primary function is gate (allow/deny), not
influence. The `systemMessage` field is available as a partial alternative
but has similar injection limitations.

### 6. Multiple Hooks Cannot Coordinate

**Problem:** When multiple `PreToolUse` hooks match the same tool call,
Codex runs them concurrently. One hook cannot prevent another from starting,
and there is no ordering guarantee.

**Impact:** If other hooks are configured alongside permit0, there is no way
to ensure permit0 runs first. However, any single `deny` result blocks the
tool, so permit0's deny still takes effect regardless of other hooks.

### 7. Remote Mode Session Continuity

**Problem:** When using `--remote`, the hook POSTs bare `tool_name` and
`parameters` to the daemon. The Codex stdin payload's `session_id` is not
forwarded to the daemon (the current hook code does not include `metadata`
in the remote POST body).

**v1 workaround:** The daemon creates a fresh session context per request.
Cross-call pattern detection (velocity, attack chains) does not work in
remote mode unless the daemon independently tracks sessions.

**v2 plan:** Forward `session_id` and `task_goal` from the Codex stdin
payload as `metadata` fields in the remote POST body. This aligns with how
the OpenClaw integration passes session context.

## Future Work

### v2: PermissionRequest Hook Integration

The `PermissionRequest` hook fires when Codex is about to prompt the user for
approval (sandbox escalation, network access, side-effecting MCP tool calls).
Unlike `PreToolUse`, it supports both `allow` and `deny`:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": { "behavior": "allow" }
  }
}
```

**Approach:** Install both a `PreToolUse` and a `PermissionRequest` hook.

1. `PreToolUse` performs normalization and risk scoring:
   - `Allow` / `Low` / `Minimal` -> exit 0 (no objection, tool runs)
   - `Deny` / `Critical` / `blocked` -> deny (tool blocked)
   - `HumanInTheLoop` / `Medium` / `High` -> exit 0 with `systemMessage`
     injecting risk context (tool proceeds to approval prompt)

2. `PermissionRequest` intercepts the subsequent approval prompt:
   - Read the tool call details from stdin
   - Look up the cached risk assessment from step 1
   - `allow` if the risk is acceptable (e.g., Medium with favorable context)
   - `deny` if the risk is too high (e.g., High with unfavorable entities)

This enables true HITL routing through Codex's native approval UI, matching
Claude Code's `ask` behavior.

**Complexity:** Requires inter-hook state sharing (e.g., a shared temp file
or SQLite cache) since `PreToolUse` and `PermissionRequest` run as separate
subprocess invocations. The `session_id` + `tool_use_id` from the stdin
payload can key the cache.

**Race condition risk:** `PreToolUse` must finish writing its cache entry
before `PermissionRequest` reads it. Codex runs matching hooks concurrently
for the same event, but `PreToolUse` and `PermissionRequest` are different
events -- verify whether Codex guarantees sequential ordering between them.
Use file-system locking or atomic rename to avoid partial writes if ordering
is not guaranteed.

### v2: Forward Session Context in Remote Mode

Extend the remote POST body to include Codex metadata:

```json
{
  "tool_name": "gmail_send",
  "parameters": { ... },
  "metadata": {
    "session_id": "019dba93-...",
    "turn_id": "turn-7",
    "client_kind": "codex",
    "model": "gpt-5.4"
  }
}
```

The daemon request schema already accepts `metadata` and `client_kind`.
Adding this enables the daemon to track sessions per Codex thread, correlate
audit entries with model identity, and provide richer dashboard context.
Daemon-side session action persistence is also needed for cross-call pattern
detection to work in remote mode.

### v2: PostToolUse Hook for Execution-Result Audit Enrichment

The `PostToolUse` hook fires after a tool completes, providing the tool's
output. permit0 already has decision audit (every `get_permission` call writes
a `DecisionRecord` and optionally a signed `AuditEntry`). What `PostToolUse`
would add is **post-execution context**:

- Tool response content and exit status
- Anomalous output detection (e.g., error messages indicating exploitation)
- Session context enrichment with the action's actual result for future scoring

### v3: Codex Plugin Packaging

Package permit0 as a Codex plugin with:

- `plugin.toml` manifest declaring the hook
- Bundled MCP servers (Gmail, Outlook)
- Lifecycle config (hooks auto-configured on plugin install)
- `PLUGIN_ROOT` env var for portable paths

This would allow `codex plugin install permit0` as a single-command setup.

### v3: Codex Cloud Integration

Codex Cloud runs agents in isolated containers. A permit0 integration for
Codex Cloud would require:

- A sidecar daemon running alongside the agent container
- Network policy allowing the agent to reach the permit0 daemon
- Container-aware session tracking (container ID as session key)
- Integration with Codex Cloud's managed requirements system for
  enterprise-wide policy enforcement
