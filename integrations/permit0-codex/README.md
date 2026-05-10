# permit0-codex

Gate every tool call OpenAI Codex makes — Bash, `apply_patch`, MCP servers —
through the permit0 policy engine.

This integration has no library code: it's a `permit0 hook --client codex`
CLI subcommand that ships in the `permit0` binary, plus a config recipe.
Same shape as the [Claude Code integration](../../docs/plans/codex-integration/00-overview.md).
The whole flow:

```
Codex agent turn
   ↓
Model proposes a tool call (Bash, apply_patch, mcp__<server>__<tool>)
   ↓
Codex fires PreToolUse hook → spawns `permit0 hook --client codex`
   ↓
permit0 normalizes the tool call through packs, scores it, returns
either empty stdout (no objection) or a deny envelope
   ↓
Codex either runs the tool or blocks it with permit0's reason
```

## Prerequisites

- macOS (the auto-trust setup uses macOS managed preferences). Linux/Windows
  paths exist but aren't covered here yet.
- [Codex CLI](https://developers.openai.com/codex) installed (verified
  against 0.130.0-alpha.5 from `/Applications/Codex.app`)
- This repo checked out and built:

  ```bash
  cargo build --release
  # produces ./target/release/permit0
  ```

## Setup (production-ish)

Add the hook to your Codex config and trust it once via the TUI.

1. Append this block to `~/.codex/config.toml`:

   ```toml
   [features]
   hooks = true

   [[hooks.PreToolUse]]
   matcher = ".*"

   [[hooks.PreToolUse.hooks]]
   type = "command"
   command = "/absolute/path/to/permit0/target/release/permit0 hook --client codex --packs-dir /absolute/path/to/permit0/packs --unknown defer"
   timeout = 30
   statusMessage = "permit0 safety check"
   ```

   See [`examples/config.toml.example`](./examples/config.toml.example) for
   a paste-ready snippet. The `hooks.json` alternative form is in
   [`examples/hooks.json.example`](./examples/hooks.json.example).

2. Launch Codex once interactively:

   ```bash
   codex
   ```

   You'll see "1 hook needs review before it can run. Open /hooks to
   review it." at the top of the TUI. Type `/hooks`, find the permit0
   entry, mark it trusted (single-letter shortcut shown in the footer).
   Exit Codex.

3. From now on every `codex` and `codex exec` session fires permit0 on
   every tool call. Re-trust is required if you edit the hook command
   (Codex tracks a content hash).

## Setup (unattended — macOS auto-trust)

For CI, scripts, or anywhere you can't open the TUI: install the hook
via macOS managed preferences. Codex treats these as MDM-sourced =
always trusted, no review needed.

```bash
bash integrations/permit0-codex/examples/install-managed-prefs.sh
```

The script reads the same TOML config layered into macOS user defaults
under `com.openai.codex/requirements_toml_base64`. To uninstall:

```bash
defaults delete com.openai.codex requirements_toml_base64
```

This is the path the live-demo launcher in `dev-test-rig/codex-demo`
uses internally.

## What permit0 actually intercepts

| Tool type | Gated? | `tool_name` permit0 sees |
|---|---|---|
| Bash / shell commands (simple path) | ✅ | `"Bash"` |
| File edits via `apply_patch` | ✅ | `"apply_patch"` |
| MCP server tool calls | ✅ | `"mcp__<server>__<tool>"` |
| `unified_exec` (Codex's newer shell mechanism) | ❌ (Codex limitation) | — |
| `WebSearch` | ❌ (Codex limitation) | — |
| Image generation | ❌ (Codex limitation) | — |

The Codex docs at <https://developers.openai.com/codex/hooks> explicitly
list these limitations as "still a guardrail rather than a complete
enforcement boundary." permit0 inherits them.

## Behavior under permit0's verdict tiers

| permit0 verdict | What permit0 emits to Codex | What Codex does |
|---|---|---|
| `Allow` / `Defer` | Zero stdout bytes | Tool runs |
| `Deny` | `permissionDecision: "deny"` envelope with reason | Tool blocked, model sees the reason |
| `HumanInTheLoop` (Medium/High tier) | `permissionDecision: "deny"` envelope with `" — requires human review"` marker appended to the reason | Tool blocked; the marker tells users this was a HITL action under Claude Code, not a hard Critical block |
| Internal error in permit0 | `permissionDecision: "deny"` envelope with `"permit0 internal error: <msg>"` | Tool blocked (fail-closed) |

Codex `PreToolUse` does **not** support `permissionDecision: "allow"` or
`"ask"`; both are explicitly rejected. permit0 never emits either.

## Verifying end-to-end

The full end-to-end test transcript is in
[`../../docs/plans/codex-integration/06-real-codex-testing.md`](../../docs/plans/codex-integration/06-real-codex-testing.md).
The condensed version:

- **Synthetic smoke (CI-safe, no Codex install needed):**

  ```bash
  ./scripts/test-codex-hook.sh
  ```

  9 canned scenarios pass against `target/release/permit0` in ~1 second.

- **Live Codex demo:**

  ```bash
  bash integrations/permit0-codex/dev-test-rig/codex-demo
  ```

  Opens an interactive Codex session with:
  - The hook auto-installed (managed prefs, no `/hooks` review needed)
  - A mock `gmail_send` MCP server wired in so you can exercise permit0's
    real Gmail pack without setting up Gmail credentials
  - An optional `watch` script (in the same dir) for a second terminal
    that tails events in real time

  See [`dev-test-rig/README.md`](./dev-test-rig/README.md) for the
  prompts to type and what to expect.

## Files in this directory

```
README.md                          ← you are here
examples/
  config.toml.example              copy-paste TOML for ~/.codex/config.toml
  hooks.json.example               equivalent JSON form for ~/.codex/hooks.json
  install-managed-prefs.sh         macOS auto-trust installer
dev-test-rig/
  README.md                        demo prompts and forensics tour
  codex-demo                       interactive demo launcher
  watch                            live event-log viewer
  cleanup                          removes managed-prefs hook
  wrap-permit0.sh                  instrumented hook wrapper
  mock-gmail-mcp.py                mock MCP server exposing gmail_send
  _watch_render.py                 internal: pretty-prints events.log rows
```

## Where the code lives

- Hook adapter: [`crates/permit0-cli/src/cmd/hook.rs`](../../crates/permit0-cli/src/cmd/hook.rs)
  — `ClientKind::Codex`, `OutputFormat::Codex`, `hook_output_to_codex`, fail-closed wrapper
- Unit tests: in `#[cfg(test)] mod tests` inside the same file
- Integration tests: [`crates/permit0-cli/tests/cli_tests.rs`](../../crates/permit0-cli/tests/cli_tests.rs)
- Smoke test: [`scripts/test-codex-hook.sh`](../../scripts/test-codex-hook.sh)

## Design docs

- [`docs/plans/codex-integration/`](../../docs/plans/codex-integration/) — overview, protocol, implementation, configuration, testing, limitations, and the verified end-to-end transcript
- [`docs/plan-reviews/codex-integration/`](../../docs/plan-reviews/codex-integration/) — pre-implementation reviews of the plan
- [`docs/code-reviews/codex-integration/`](../../docs/code-reviews/codex-integration/) — post-implementation code reviews
