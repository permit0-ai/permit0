---
name: permit0-claude-code-setup
description: "Walk a user through integrating permit0 with Claude Code from a fresh machine — install Rust, build permit0, install Outlook/Gmail MCP servers, set up OAuth, configure ~/.claude.json hooks + mcpServers, verify, and switch from calibration to enforce mode. Activate when the user says they want to set up / install / integrate permit0 with Claude Code, or asks how to get email policy gating working."
---

# permit0 ↔ Claude Code Integration

Goal: from a fresh machine to "every email tool call Claude Code makes
is gated by permit0", in ~10–15 minutes. Single-layer enforcement —
the PreToolUse hook is the only gate; MCP servers are plain wrappers.

## When to activate

The user says any of:

- "set up permit0 with Claude Code"
- "install permit0", "integrate permit0", "wire up the permit0 hook"
- "I want Claude Code to gate my email"
- "how do I get this working with my Outlook / Gmail"

Or they ask follow-up questions while in the middle of an integration
attempt.

## Pre-flight: figure out what they have

Before walking them through, ask (or detect via commands) which:

1. **OS** — macOS or Linux? (different install commands for prereqs)
2. **Email provider(s)** — Outlook, Gmail, or both?
   - Outlook is zero-config; Gmail requires a 5-min Google Cloud Console
     OAuth setup. If they only need Outlook, skip Gmail.
3. **Existing tooling** — do they have `cargo`, `python3`, `claude`?
   Run `which cargo python3 claude && cargo --version && python3 --version`.

Skip steps they've already done. If they haven't installed prereqs,
point them at the matching block in step 0 below.

## The 6 steps

### 0. Prereqs (if missing)

**macOS**:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
brew install python sqlite
brew install --cask claude-code   # or: npm install -g @anthropic-ai/claude-code
```

**Linux (Debian/Ubuntu)**:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
sudo apt update && sudo apt install -y python3 python3-pip python3-venv sqlite3 build-essential pkg-config libssl-dev
curl -fsSL https://claude.ai/install.sh | sh
```

Verify with `cargo --version`, `python3 --version`, `claude --version`.

### 1. Build permit0 + start daemon (calibrate mode)

```bash
git clone https://github.com/anthropics/permit0-core.git
cd permit0-core
cargo build --release
export PATH="$PATH:$(pwd)/target/release"
permit0 serve --calibrate --port 9090
```

Expected output:
```
permit0 server listening on 0.0.0.0:9090
  admin dashboard at http://0.0.0.0:9090/ui/
```

User opens http://localhost:9090/ui/ → enters reviewer name → leaves
**Approvals tab** open. Daemon stays running in this terminal.

### 2. Install MCP servers (in a new terminal)

```bash
cd permit0-core
pip install -e clients/outlook-mcp
pip install -e clients/gmail-mcp     # skip if Gmail not needed
```

Verify: `which permit0-outlook-mcp` returns a path.

### 3. Authenticate

**Outlook (1 minute)**:
```bash
python demos/outlook/outlook_test.py list
```
Opens device-login URL; sign in; approve `Mail.ReadWrite` + `Mail.Send`.
Token caches to `~/.permit0/outlook_token.json`. Verify by re-running
the same command — should list inbox without re-prompting.

**Gmail (5 minutes one-time)**:

1. https://console.cloud.google.com → new project
2. **APIs & Services → Library** → search "Gmail API" → Enable
3. **OAuth consent screen** → External → add user's own email as test user
4. **Credentials → Create credentials → OAuth Client ID** →
   **Application type: Desktop app** → download JSON
5. Save downloaded JSON as `~/.permit0/gmail_credentials.json`
6. First-time login:
   ```bash
   python -c "from permit0_gmail_mcp.auth import get_token; get_token()"
   ```

Browser opens, user picks account, clicks "Advanced → Go to … (unsafe)"
(it's their own Cloud project, not actually unsafe), grants Gmail
permissions. Token caches to `~/.permit0/gmail_token.json`.

### 4. Configure Claude Code

**Two files** — different schemas:

**4a. Hook → `~/.claude/settings.json`** (NOT `~/.claude.json`).
Schema is *nested* — `{ matcher, hooks: [{ type, command }] }`.
Use absolute paths (PATH and `~` expansion can't be relied on):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/abs/path/to/permit0 hook --db /home/<user>/.permit0/sessions.db"
          }
        ]
      }
    ]
  }
}
```

Omit `matcher` → match all tool calls (built-in + MCP). Insert at
**index 0** so permit0 fires before other hooks. **Merge** with
existing `PreToolUse` entries; don't overwrite.

**4b. MCP servers → `~/.claude.json`**:

```json
{
  "mcpServers": {
    "permit0-outlook": { "command": "/abs/path/to/permit0-outlook-mcp" },
    "permit0-gmail":   { "command": "/abs/path/to/permit0-gmail-mcp" }
  }
}
```

Resolve abs paths via `which permit0`, `which permit0-outlook-mcp`, etc.

**Tell the user to fully quit and relaunch Claude Code** — reload-window
does not reload hooks or MCP config.

> **Common trap**: putting hooks in `~/.claude.json` (wrong file) or
> using flat `{ "command": "..." }` schema (wrong shape) → hook is
> silently ignored, no error message. Verify by checking
> `~/.claude/settings.json` after editing and confirm the schema looks
> like other working hooks already in that file.

### 5. Verify

In a new Claude Code session, ask:

> List my 5 most recent inbox messages.

Expected flow:
1. Claude Code calls `mcp__permit0-outlook__outlook_search`
2. PreToolUse hook fires, strips prefix → `outlook_search` →
   normalizes to `email.search`
3. In calibrate mode, hook blocks; daemon creates pending approval
4. **Dashboard's Approvals tab** shows a card with the action,
   tier, risk flags, and full entity preview (`query`, `top`, etc.)
5. User clicks Approve → Claude Code unblocks, shows the inbox

If step 4 doesn't happen, see [Troubleshooting](#troubleshooting) below.

### 6. Switch to enforce when ready

After 10–30 calibrated approvals (visible on the **Calibration tab**),
restart daemon without `--calibrate`:

```bash
# Ctrl+C the calibrate daemon, then:
permit0 serve --ui --port 9090
```

Decisions auto-route by tier; cache holds the user's prior decisions.

## Troubleshooting

Walk the user through diagnostic commands when something doesn't work:

| Symptom | Diagnosis | Fix |
|---------|-----------|-----|
| MCP tools don't appear in Claude Code | `which permit0-outlook-mcp` empty, OR didn't fully quit Claude Code | Add pip's bin dir to PATH (or use absolute path in `~/.claude.json`); fully quit + relaunch |
| Hook returns `ask_user` for every MCP call | Likely the hook can't find packs or normalizer doesn't match | `echo '{"tool_name":"mcp__permit0-outlook__outlook_send","tool_input":{"to":"a@b.com","subject":"x","body":"y"}}' \| permit0 hook` — should NOT say `unknown.unclassified`. If it does, check working dir contains `packs/` or add `--packs-dir /abs/path` to the hook command |
| `Hook returns ask_user` for built-in tools (Bash etc.) | Expected — only the `email` pack ships normalizers; built-in tools fall through to unknown | Either accept (default deny → ask user), or add normalizers/risk rules under `packs/<your-domain>/` for the built-ins you use |
| Daemon not reachable | `curl http://localhost:9090/api/v1/health` fails | Daemon crashed or was killed; restart in terminal 1. Or port collision — try a different port and update the hook URL via `PERMIT0_URL` env var |
| Outlook auth: "AADSTS65001" | Work/school account requires admin consent for the public Graph PowerShell client | Use personal `@outlook.com` account, OR register own Azure App and set `MSGRAPH_CLIENT_ID` |
| Gmail OAuth "redirect_uri_mismatch" | OAuth client was created as Web app instead of Desktop | Delete the credential, create a new **Desktop app** type, re-download |
| Different MCP host (Cursor / Cline / OpenClaw / …) | Hook strips Claude Code's `mcp__X__Y` prefix by default | Add `--client claude-desktop` (passthrough) or `--client raw` to the hook command. If the host uses a different prefix shape, run a test call through the hook, see what `tool_name` looks like, and add a new variant to `crates/permit0-cli/src/cmd/hook.rs::ClientKind` |

## Key files & locations

| Path | Purpose |
|------|---------|
| `~/.claude.json` | Claude Code config (hooks + mcpServers) |
| `~/.permit0/permit0.db` | SQLite — audit log, policy cache, deny/allow lists |
| `~/.permit0/sessions.db` | SQLite — per-session action history (for hook session-aware scoring) |
| `~/.permit0/outlook_token.json` | MSAL token for Outlook |
| `~/.permit0/gmail_credentials.json` | User-provided Google OAuth client |
| `~/.permit0/gmail_token.json` | Google OAuth token cache |
| `<repo>/packs/email/` | Risk rules + normalizers (edit to tune policy) |

## Reset for a fresh calibration

```bash
rm ~/.permit0/permit0.db ~/.permit0/sessions.db
```

(Also wipes audit log — only do this when starting calibration over.)

## Reference docs

- `<repo>/README.md` — full feature overview
- `<repo>/docs/claude-code-integration.md` — same recipe in static doc form
- `<repo>/clients/outlook-mcp/README.md` — Outlook MCP details
- `<repo>/clients/gmail-mcp/README.md` — Gmail MCP details

## Style guidance for this skill

When walking the user through:

- **Verify after each step**, don't dump all 6 at once. Run the
  expected command, check the output, confirm before moving on.
- **Don't assume their OS** — ask or detect.
- **Skip auth they've already done** — check token files in `~/.permit0/`
  before sending them through the OAuth dance.
- **Surface the calibrate→enforce decision explicitly** at the end.
  Some users will want to stay in calibrate mode forever for full
  audit visibility; others want to flip after ~20 actions.
- **If something fails**, use the troubleshooting table — give them
  the specific diagnostic command, parse its output, then suggest
  the fix that matches their symptom.
