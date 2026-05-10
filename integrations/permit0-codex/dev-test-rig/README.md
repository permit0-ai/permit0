# permit0 + Codex live demo rig

End-to-end exercise of the permit0 / Codex integration against a real
Codex install on macOS. Useful for:

- Smoke-testing the integration after permit0 changes
- Showing the integration working without setting up real Gmail/MCP creds
- Reproducing the test transcript in
  [`../../../docs/plans/codex-integration/06-real-codex-testing.md`](../../../docs/plans/codex-integration/06-real-codex-testing.md)

This rig is **not for end users** — for production setup see
[`../README.md`](../README.md). These scripts modify macOS user defaults
under `com.openai.codex/requirements_toml_base64` (recoverable with the
`cleanup` script in this dir).

## Two-terminal demo

**Terminal 1 — launch:**

```bash
bash integrations/permit0-codex/dev-test-rig/codex-demo
```

A banner appears, then Codex launches into its TUI. The hook is
installed automatically (managed prefs, no `/hooks` review needed) and a
mock-gmail MCP server is wired into the isolated `CODEX_HOME` at
`/tmp/permit0-codex-test/` (override with `PERMIT0_TRACE_DIR=...`).

**Terminal 2 — watch:**

```bash
bash integrations/permit0-codex/dev-test-rig/watch
```

Tails the event log and prints a colored row per hook fire:
green `ALLOW/DEFER`, red `DENY`.

## Prompts to try inside Codex

### 1. Permit0 waves a benign Bash command through

```
Run 'ls -la' and tell me what files you see
```

Codex's Bash tool fires → permit0 has no Bash pack → falls through
`--unknown defer` → empty stdout → command runs.

The `watch` terminal will show a green `ALLOW/DEFER` row with
`tool=Bash`.

### 2. Permit0 blocks an external Gmail send

```
Use the gmail_send tool to send a quick note to alice@external-customer.com
with subject "Meeting confirmation" and body "Hi Alice, confirming our 2pm
meeting tomorrow."
```

Codex packages this as `tool_name = "mcp__mock_gmail__gmail_send"`. permit0:

1. Strips `mcp__mock_gmail__` → `gmail_send`
2. Gmail pack normalizer matches → `action=email.send, channel=gmail`
3. Risk rules detect external recipient → Medium tier → `HumanInTheLoop`
4. Codex emitter maps HITL → deny envelope with `" — requires human review"` marker

Codex receives the deny, the mock MCP server is **never called for
`tools/call`**, and the model says something like *"the email send was
blocked for human review by the tool's permission hook"*.

The `watch` terminal will show a red `DENY` row with the MCP tool name.

### 3. Compare shadow mode

Exit Codex (Ctrl-C twice), then:

```bash
bash integrations/permit0-codex/dev-test-rig/codex-demo --shadow
```

Same setup, but `PERMIT0_SHADOW=1` propagates to the wrapper and permit0
runs in observe-only mode. Re-run the email prompt:

- permit0 logs `[permit0 shadow] WOULD ASK: email.send (gmail) — risk 43/100 Medium` to stderr
- Returns empty stdout to Codex (no objection)
- Codex proceeds to call the mock MCP, which returns its fake "Pretended to send..." response

This is the "observe before enforce" rollout pattern. The same hook
binary, just different flags.

## Forensics — what each file shows you

After a session, every hook fire writes a per-invocation directory:

```bash
ls /tmp/permit0-codex-test/inv-*/
```

Each contains:

| File | Contents |
|---|---|
| `stdin.json` | Exact bytes Codex sent to permit0 (the PreToolUse stdin schema) |
| `stdout` | Exact bytes permit0 returned to Codex (empty or deny envelope) |
| `stderr` | permit0's stderr — shadow logs, error breadcrumbs |
| `env` | Snapshot of env vars + paths at invocation time |

Plus repo-wide trace files:

| File | Contents |
|---|---|
| `events.log` | JSONL: one structured row per hook fire (used by `watch`) |
| `mock-mcp.log` | JSONL: every JSON-RPC frame the mock MCP server saw/sent. Notably the absence of `tools/call` entries proves permit0 stopped Codex before the MCP server was asked to actually act. |

## When you're done

```bash
bash integrations/permit0-codex/dev-test-rig/cleanup
```

Removes the macOS managed-prefs hook. Your normal `codex` sessions stop
firing permit0. The demo scripts stay in the repo for next time.

To wipe trace state:

```bash
rm -rf /tmp/permit0-codex-test
```

## File-by-file

| Script | Purpose |
|---|---|
| `codex-demo` | Installs the managed-prefs hook + isolated `CODEX_HOME` with mock-gmail MCP, then launches Codex |
| `watch` | Tails `events.log` with colored rows |
| `cleanup` | Removes managed-prefs hook |
| `wrap-permit0.sh` | Codex's hook command — invokes permit0 and captures per-invocation traces |
| `mock-gmail-mcp.py` | 180-line stdio MCP server exposing a fake `gmail_send` tool |
| `_watch_render.py` | Pretty-prints `events.log` rows (used by `watch`) |

## Troubleshooting

**`events.log` stays empty after a Codex session.**
Re-run `codex-demo` (it always re-installs the hook). If still empty,
verify the hook is installed:

```bash
defaults read com.openai.codex requirements_toml_base64 | base64 -d
```

Should print the TOML config.

**Codex prompts to trust the project directory.**
That's Codex's directory-trust prompt (separate from hook trust). Answer
yes or skip via `--skip-git-repo-check` — `codex-demo` already passes
that to launches.

**MCP tool call shows "user cancelled" instead of "blocked by hook".**
A Codex quirk when `approval_policy = "never"` is combined with
`codex exec` — Codex sometimes refuses MCP calls without surfacing the
approval prompt. Doesn't affect the interactive TUI that `codex-demo`
opens. If you hit it, retype the prompt in the TUI.
