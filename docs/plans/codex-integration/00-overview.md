# 00 — Codex CLI Integration: Overview and Architecture

**Status:** Draft
**Revised:** 2026-05-10
**Depends on:** None
**Blocks:** 01-protocol, 02-implementation

## Goal

Replicate the existing **Claude Code integration** for
[OpenAI Codex CLI](https://github.com/openai/codex). The Claude Code
integration (`permit0 hook --client claude-code`, implemented in
[`crates/permit0-cli/src/cmd/hook.rs`](../../../crates/permit0-cli/src/cmd/hook.rs))
is the reference: it intercepts every tool call via a `PreToolUse` hook,
evaluates it through the permit0 engine, and returns an allow / deny / ask
verdict. The Codex integration provides the same governance for
**pack-covered actions** (currently email via Gmail/Outlook packs) plus the
configured `--unknown` policy for tools without packs. The hook I/O is
adapted to Codex's protocol differences; the engine and packs are unchanged.

Concretely, the integration must:

1. Intercept tool calls via Codex's `PreToolUse` hook.
2. Normalize, score, and route each call through the permit0 engine.
3. Block calls that exceed the configured risk threshold.
4. Pass through calls that the engine approves.
5. Maintain session context for cross-call pattern detection (local mode
   with `--db`; remote mode is stateless for session history in v1).
6. Work in both **local** (in-process engine) and **remote** (HTTP daemon) modes.

## Data Flow

```
Codex CLI conversation
  |
  |  Agent proposes: gmail_send({ to: "alice@example.com", ... })
  |
  v
Codex PreToolUse hook
  |  stdin: { "tool_name": "mcp__permit0-gmail__gmail_send",
  |           "tool_input": { "to": "alice@example.com", ... },
  |           "session_id": "019dba93-...",
  |           "turn_id": "turn-7",
  |           "cwd": "/home/user/project",
  |           "hook_event_name": "PreToolUse",
  |           "model": "gpt-5.4" }
  |
  v
permit0 hook --client codex [--remote http://127.0.0.1:9090]
  |  1. Parse Codex stdin JSON (superset of Claude Code's format)
  |  2. Strip MCP prefix: "mcp__permit0-gmail__gmail_send" -> "gmail_send"
  |  3. Extract session_id from stdin payload
  |  4. Build RawToolCall { tool_name: "gmail_send", parameters: {...} }
  |
  +--[remote]---> POST /api/v1/check -> daemon evaluates -> JSON response
  |
  +--[local]----> engine.get_permission() in-process
  |
  |  5. Map permit0 Permission to Codex output:
  |       Allow            -> exit 0, empty stdout (no objection)
  |       Deny             -> hookSpecificOutput with permissionDecision: "deny"
  |       HumanInTheLoop   -> hookSpecificOutput with permissionDecision: "deny"
  |                           (includes risk summary in reason; v1 limitation)
  |
  v
Codex reads hook result
  |  exit 0 + empty stdout  -> tool executes
  |  deny JSON on stdout    -> tool blocked, reason shown to user/agent
  |
  v
Tool executes (or is blocked)
```

## Comparison with Claude Code Integration

| Aspect | Claude Code | Codex CLI |
|--------|-------------|-----------|
| Hook mechanism | `PreToolUse` in `~/.claude/settings.json` | `PreToolUse` in `~/.codex/hooks.json` or `config.toml` |
| Feature flag | None required | `[features] codex_hooks = true` |
| Allow verdict | `permissionDecision: "allow"` | Exit 0 with empty stdout |
| Deny verdict | `permissionDecision: "deny"` | `permissionDecision: "deny"` (same) |
| Ask/HITL verdict | `permissionDecision: "ask"` | Not supported in PreToolUse; map to deny with informative reason |
| Defer (no opinion) | Omit `permissionDecision` key | Exit 0 with empty stdout |
| MCP tool prefix | `mcp__<server>__<tool>` | `mcp__<server>__<tool>` (same) |
| Session ID | `CLAUDE_SESSION_ID` env var | `session_id` in stdin JSON + `CODEX_THREAD_ID` env var |
| Matcher | None; hook runs for all tools | Regex matcher; omit or use `".*"` for all tools |
| Config format | JSON (`settings.json`) | TOML (`config.toml`) or JSON (`hooks.json`) |
| Timeout | Not configurable | `timeout` field in seconds (default 600) |
| Tool name sanitization | None beyond prefix strip | Codex may replace hyphens with underscores in MCP names |

## Scope

### v1 (this plan)

- `PreToolUse` hook adapter in `permit0 hook --client codex`
- Local and remote evaluation modes
- Session-aware mode with SQLite persistence
- Shadow mode for observation without enforcement
- `--unknown` mode for unrecognized tools (defer/ask/allow/deny)
- Configuration guide for `~/.codex/hooks.json` and `config.toml`
- Unit and integration tests

### Deferred to v2

- `PermissionRequest` hook: intercept Codex's approval prompts and
  allow/deny based on permit0's verdict (enables true HITL routing)
- `PostToolUse` hook: audit completed actions after execution
- Codex plugin packaging: bundle permit0 as an installable Codex plugin
  with hooks, MCP servers, and lifecycle config in a single manifest
- `unified_exec` interception: Codex's newer shell mechanism that hooks
  don't intercept yet

## Crate Dependencies

The Codex integration touches only the CLI hook adapter. No changes are needed
to the engine, scoring, packs, store, or daemon API surface:

```
permit0-cli (hook.rs)  <-- changes here
  |
  +-- permit0-engine   <-- no changes
  +-- permit0-normalize <-- no changes
  +-- permit0-session   <-- no changes (session store reused as-is)
  +-- permit0-types     <-- no changes
```

Note: `serve.rs` imports `ClientKind` from `hook.rs`. Adding the `Codex`
variant transitively makes the daemon accept `"client_kind": "codex"` in
`POST /api/v1/check` requests and apply the same MCP prefix stripping. No
`serve.rs` source lines are edited, but daemon behavior observably changes
for requests that include `client_kind: "codex"`.

The daemon's `POST /api/v1/check` endpoint is used for `--remote` mode.
A prerequisite fix is needed: the daemon serializes HITL as `"human"` but the
hook remote mapper currently only matches `"humanintheloop"` (see
`02-implementation.md` for details). Remote mode is stateless for session
history in v1 (the hook does not forward `session_id` in the POST body, and
the daemon does not persist session action records).

The only new code is in `crates/permit0-cli/src/cmd/hook.rs`:

1. A `Codex` variant on `ClientKind` (same MCP prefix stripping as `ClaudeCode`)
2. An `OutputFormat` enum (`ClaudeCode | Codex`) to branch output serialization
3. Codex-specific input deserialization (stdin carries `session_id`, `turn_id`, etc.)
4. Codex-specific output: exit-0-no-output for allow/defer, deny envelope for block
