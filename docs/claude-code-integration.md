# Claude Code + permit0 — Zero-to-Running Integration Guide

A step-by-step walkthrough for installing and wiring permit0 into Claude
Code so every email tool call (Outlook + Gmail) is gated by policy.
**Time required: ~15 minutes** (5 of which is the one-time Gmail OAuth setup,
skip if you only need Outlook).

The goal: when you ask Claude Code to send / archive / delete email,
permit0 evaluates each call against a YAML policy. In **calibration mode**
it pauses for you to approve; in **enforce mode** it auto-allows or auto-
denies based on the cached calibration data.

---

## Architecture (single-layer)

```
Claude Code  ──┐
               │  every tool call (built-in + MCP)
               ▼
        [PreToolUse hook]
        permit0 hook
               │  strip mcp__<server>__ prefix → bare name
               │  normalize via packs/email/normalizers/*.yaml
               │  score via packs/email/risk_rules/*.yaml
               │
               ▼
       allow / block / ask_user
               │
               ▼ (only on allow)
   Claude Code runs the tool
               │
               ├──▶ Built-in tools (Bash, Edit, Read, …)
               │
               ├──▶ MCP: permit0-outlook-mcp ──▶ Microsoft Graph
               │
               └──▶ MCP: permit0-gmail-mcp   ──▶ Gmail API
```

The MCP servers are **plain wrappers** — no policy logic. All gating
happens at the PreToolUse hook in front of Claude Code.

---

## 0. Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust toolchain | 1.85+ | https://rustup.rs |
| Python | 3.10+ | system or pyenv |
| Claude Code | latest | https://docs.claude.com/en/docs/claude-code/setup |
| SQLite3 | any (system) | `apt install sqlite3` / `brew install sqlite` |

Check:

```bash
cargo --version    # cargo 1.85.0 (or newer)
python3 --version  # Python 3.10+
claude --version   # any
sqlite3 --version  # any
```

---

## 1. Clone and build permit0

```bash
git clone https://github.com/anthropics/permit0-core.git
cd permit0-core
cargo build --release
```

First build takes 2–5 min. After that the binary lives at
`./target/release/permit0`. Add it to your PATH:

```bash
# bash / zsh — append to ~/.bashrc or ~/.zshrc
export PATH="$PATH:$(pwd)/target/release"
```

Verify:

```bash
permit0 --version
permit0 hook --help    # should list --shadow, --client flags
```

---

## 2. Start the daemon (in calibration mode)

The daemon serves the dashboard, runs the engine, and acts as the synchronous
backstop for the hook. Keep it running in its own terminal:

```bash
mkdir -p ~/.permit0
permit0 serve --calibrate --port 9090
```

You should see:

```
  database at /home/you/.permit0/permit0.db
permit0 server listening on 0.0.0.0:9090
  API mounted at /api/v1/
  admin dashboard at http://0.0.0.0:9090/ui/
```

Open the dashboard at **http://localhost:9090/ui/** in a browser.

A login modal appears the first time — enter your name (e.g. `alice`) →
stored in browser localStorage and used as your `reviewer` identity in
the audit log. Switch to the **Approvals** tab; this is where pending
actions will queue up.

> **What `--calibrate` does**: every fresh decision blocks on a human
> approval (max 5 min wait). Engine's recommendation is shown alongside
> the message details so you can audit and override. Your decisions are
> recorded with engine-vs-human comparison for offline analysis.

---

## 3. Install the MCP servers

In a third terminal (the daemon stays running in terminal 1, dashboard
stays open in your browser):

```bash
cd permit0-core
pip install -e clients/outlook-mcp
pip install -e clients/gmail-mcp     # skip if only using Outlook
```

The `permit0-outlook-mcp` and `permit0-gmail-mcp` console scripts are now
on your PATH. Verify:

```bash
which permit0-outlook-mcp
which permit0-gmail-mcp
```

> The Python SDK at `clients/python/` is **optional** — only needed if
> you want to write Python code that calls permit0 directly via
> `@permit0.guard(...)`. The hook + plain-MCP path doesn't need it.

---

## 4. Authenticate to your email provider

### 4a. Outlook (zero-config — 1 minute)

Outlook uses Microsoft's public Graph PowerShell client_id, so you don't
need to register an Azure App. Run the demo CLI once to log in:

```bash
python demos/outlook/outlook_test.py list
```

It prints a Microsoft device-login URL like
`https://microsoft.com/devicelogin` and a code. Open the URL in any
browser, enter the code, sign in with your personal Outlook account
(`@outlook.com` or work/school), and approve `Mail.ReadWrite` +
`Mail.Send` permissions.

Token caches to `~/.permit0/outlook_token.json` and is shared with the
MCP server. Subsequent calls refresh silently — you won't be prompted
again unless the refresh token expires (~90 days idle).

Verify the token works (lists your most recent inbox messages):

```bash
python demos/outlook/outlook_test.py list
```

### 4b. Gmail (one-time OAuth app setup — 5 minutes)

Google requires every app to register its own OAuth credentials — there's
no public client equivalent to Microsoft's. ~5 minutes one-time:

1. Open https://console.cloud.google.com/
2. Create a new project (top-left dropdown → **New Project**), pick any
   name (e.g. `permit0-personal`).
3. With the new project selected: **APIs & Services** → **Library** →
   search "Gmail API" → **Enable**.
4. **APIs & Services** → **OAuth consent screen** → **External** →
   fill in app name, your email as developer contact, **Save and Continue**.
   On the **Test users** step, add your own Gmail address. (You can leave
   the app in "Testing" mode forever for personal use.)
5. **APIs & Services** → **Credentials** → **+ Create credentials** →
   **OAuth client ID** → **Application type: Desktop app** → name it
   anything → **Create**.
6. **Download JSON** from the popup. Save the file as
   `~/.permit0/gmail_credentials.json`.

Run the first-time login (opens browser for consent):

```bash
python -c "from permit0_gmail_mcp.auth import get_token; print('ok' if get_token() else 'fail')"
```

A browser tab opens, asks you to choose your Google account, then warns
"this app isn't verified" — click **Advanced** → **Go to permit0-personal
(unsafe)** (it's only unsafe in the sense that you're trusting your own
Cloud project). Grant `Gmail.modify` + `Gmail.send`. Token caches to
`~/.permit0/gmail_token.json`.

Verify:

```bash
python -c "
from permit0_gmail_mcp.gmail import call
import json
r = call('GET', '/labels')
print('labels:', len(r.get('labels', [])))
"
# labels: 14   (or however many your Gmail has)
```

---

## 5. Configure Claude Code

Claude Code's config lives at `~/.claude.json`. We add **two** things:

1. A `PreToolUse` hook → `permit0 hook` (the gate)
2. `mcpServers` → outlook + gmail (the actuators)

Open `~/.claude.json` in an editor. Add or merge these top-level keys:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "command": "permit0 hook --db ~/.permit0/sessions.db",
        "description": "permit0 — gate every tool call (built-in + MCP)"
      }
    ]
  },
  "mcpServers": {
    "permit0-outlook": {
      "command": "permit0-outlook-mcp"
    },
    "permit0-gmail": {
      "command": "permit0-gmail-mcp"
    }
  }
}
```

If `~/.claude.json` already has `hooks` or `mcpServers` keys with other
content, merge — don't replace. The hook runs in addition to whatever
hooks you already have; the MCP servers add to whatever else you've
registered.

> If `permit0-outlook-mcp` / `permit0-gmail-mcp` aren't on Claude Code's
> PATH (which can differ from your shell's PATH), use absolute paths:
>
> ```json
> "command": "/full/path/to/permit0-outlook-mcp"
> ```
>
> Find them with `which permit0-outlook-mcp` in your shell.

**Restart Claude Code completely** (quit + relaunch, not just reload) for
the MCP config and hook to take effect.

---

## 6. First test

In a Claude Code session, ask:

> What tools do you have available?

You should see 26 new tools (`outlook_*` × 13 + `gmail_*` × 13) listed
under MCP servers, plus Claude Code's usual built-ins.

Now try a real action:

> List my 5 most recent inbox messages.

Watch what happens:

1. Claude Code calls `mcp__permit0-outlook__outlook_search` (or gmail).
2. The PreToolUse hook fires:
   - Strips `mcp__permit0-outlook__` → bare `outlook_search`.
   - Normalizes against `packs/email/normalizers/outlook_search.yaml` →
     `email.search`.
   - In **calibration mode**, blocks on human approval.
3. **Your dashboard's Approvals tab** shows a pending card with:
   - Action type, channel, tier, score, risk flags
   - Full message details (whatever entities the agent passed)
4. Click **Approve** (with a reason like "looks fine") → submit.
5. Claude Code's call unblocks, the MCP server fetches Microsoft Graph,
   you see the inbox in the chat.

If you don't see the Approvals card appear, see [Troubleshooting](#troubleshooting).

---

## 7. Calibrate the policy (10–30 actions)

Run a few different actions and approve/deny based on what each one
*should* do in your environment:

> Read the first message.
> Archive that newsletter.
> Send an email to alice@example.com with subject "ping".
> Search for messages from "billing@" in the last 7 days.
> Move the third message to junk.
> Delete that one.

Each fresh action lands in your Approvals tab. After 10–30 decisions,
switch to the **Calibration** tab in the dashboard:

- **Total Calibrated**: how many actions you've decided
- **Agreement Rate**: percentage where engine's recommendation matched
  your decision. >90% = engine is well-tuned for your patterns. <70% =
  the engine and you disagree often → adjust risk rules or accept that
  most decisions need human review.
- **Most Overridden Action**: which action types you flip most often
- **Top Reviewer**: usually you, useful when multiple people share the
  daemon

Filter the records table by `agreement = overridden` to find specific
decisions where engine and you disagreed. Read the entity details and
adjust `packs/email/risk_rules/*.yaml` if you spot a pattern (e.g. "I
keep allowing credentials in body for these specific cases — soften
the rule").

---

## 8. Switch to enforce mode

Once your agreement rate is acceptable (typically >85%), drop the
`--calibrate` flag:

```bash
# Stop the calibrate daemon (Ctrl+C in terminal 1)
# Restart without --calibrate:
permit0 serve --ui --port 9090
```

Now decisions auto-route based on tier:

| Tier | Permission |
|------|------------|
| Minimal / Low | Allow (no prompt) |
| Medium / High | Human-in-the-loop (still prompts) |
| Critical | Deny (auto-blocked) |

Cache hits also replay your earlier human decisions: identical
`norm_hash` calls auto-allow/auto-deny based on what you decided during
calibration. To re-run calibration on a specific action, clear its cache
entry:

```bash
# Find the norm_hash from the audit log, then:
sqlite3 ~/.permit0/permit0.db "DELETE FROM policy_cache WHERE norm_hash = X'...';"
```

To start a totally fresh calibration:

```bash
rm ~/.permit0/permit0.db ~/.permit0/sessions.db
```

(Audit log is also stored in `~/.permit0/permit0.db` — wipe with caution.)

---

## 9. (Optional) Shadow mode

If you want permit0 to **observe** all tool calls without enforcing —
useful for finding unexpected actions before turning on enforcement:

```bash
permit0 hook --shadow      # CLI flag
# or
PERMIT0_SHADOW=1 permit0 hook
```

In shadow mode the hook always returns `allow`, but writes the
*would-be* decision to stderr and the audit log. You'll see lines like:

```
[permit0 shadow] WOULD BLOCK: email.send (outlook) score=44/100  Highly sensitive ...
```

in Claude Code's hook output stream. Once you're comfortable with what
you'd be blocking, drop `--shadow`.

---

## Troubleshooting

### "I don't see the new tools in Claude Code"

- Did you fully **quit and relaunch** Claude Code? Reload-window doesn't
  reload MCP config.
- Verify the MCP commands are on Claude Code's PATH:
  ```bash
  which permit0-outlook-mcp
  ```
  If `~/.local/bin` (or wherever pip installed it) isn't on the PATH
  Claude Code sees, use absolute paths in `~/.claude.json`.
- Inspect Claude Code's MCP startup logs (location varies by platform).

### "Hook returns ask_user for everything"

- Is `permit0` on Claude Code's PATH? Test:
  ```bash
  echo '{"tool_name":"outlook_send","tool_input":{"to":"a@b.com","subject":"hi","body":"ok"}}' \
    | permit0 hook
  ```
- Is the daemon running on port 9090? `curl localhost:9090/api/v1/health`
- Check that the action lowers correctly:
  ```bash
  echo '{"tool_name":"mcp__permit0-outlook__outlook_send","tool_input":{"to":"a@b.com","subject":"hi","body":"ok"}}' \
    | permit0 hook
  ```
  Should produce `{"decision":"allow"}` or similar — **not**
  `unknown.unclassified` (that means the prefix wasn't stripped or the
  normalizer doesn't match).

### "Hook can't find packs"

The hook looks for packs in `./packs/` (current directory) or
`~/.permit0/packs/` by default. If your shell's working directory varies
when Claude Code launches the hook, set `--packs-dir`:

```json
"command": "permit0 hook --packs-dir /absolute/path/to/permit0-core/packs --db ~/.permit0/sessions.db"
```

### "Outlook OAuth: 'AADSTS65001: The user or administrator has not consented'"

Your work/school account requires admin consent for the public Graph
PowerShell client. Use a personal `@outlook.com` account, or register
your own Azure App with `Mail.ReadWrite` / `Mail.Send` delegated
permissions and set `MSGRAPH_CLIENT_ID=<your-id>` env var.

### "Gmail OAuth: 'Error 400: redirect_uri_mismatch'"

The InstalledAppFlow uses `http://localhost:<random>`. Make sure your
Cloud project's OAuth client is type **Desktop app** (not Web app).
If you accidentally created a Web app type, delete it and create a
new Desktop one.

### "Hook is too slow / blocks normal Claude Code work"

- Are you in `--calibrate` mode and forgot to switch back? It blocks
  every fresh decision for up to 5 min waiting on you.
- If non-calibrate is still slow: check if the daemon is overloaded.
  `curl localhost:9090/api/v1/health` should return immediately.
- The session DB grows unbounded. Periodically:
  ```bash
  sqlite3 ~/.permit0/sessions.db "DELETE FROM session_actions WHERE timestamp < ?;" $(date -d '7 days ago' +%s)
  ```

### "I want to use a different MCP host (Cursor / Cline / OpenClaw / …)"

The hook's `--client` flag controls how MCP tool-name prefixes are
stripped:

```bash
permit0 hook --client claude-code      # default — strips mcp__X__Y
permit0 hook --client claude-desktop   # passthrough (no prefix used)
permit0 hook --client raw              # passthrough (alias)
```

If your host uses a different prefix shape, run a test call through the
hook, look at what the `tool_name` field contains, and either add a new
variant to `crates/permit0-cli/src/cmd/hook.rs::ClientKind` or use
`--client raw` if the host hands you bare names already.

---

## What gets gated

The **email pack** ships with normalizers for these 26 raw tools, all
lowering to a unified set of 15 `email.*` norm actions:

| Outlook tool | Gmail tool | Norm action |
|--------------|------------|-------------|
| `outlook_search` | `gmail_search` | `email.search` |
| `outlook_read` | `gmail_read` | `email.read` |
| `outlook_read_thread` | `gmail_read_thread` | `email.read_thread` |
| `outlook_list_mailboxes` | `gmail_list_mailboxes` | `email.list_mailboxes` |
| `outlook_draft` | `gmail_draft` | `email.draft` |
| `outlook_send` | `gmail_send` | `email.send` |
| `outlook_mark_read` | `gmail_mark_read` | `email.mark_read` |
| `outlook_flag` | `gmail_flag` | `email.flag` |
| `outlook_move` | `gmail_move` | `email.move` |
| `outlook_archive` | `gmail_archive` | `email.archive` |
| `outlook_mark_spam` | `gmail_mark_spam` | `email.mark_spam` |
| `outlook_delete` | `gmail_delete` | `email.delete` |
| `outlook_create_mailbox` | `gmail_create_mailbox` | `email.create_mailbox` |

The two account-takeover vectors (`email.set_forwarding`,
`email.add_delegate`) are **declared in the catalog with CRITICAL gates**
but **deliberately not exposed as MCP tools** — the LLM never has a
legitimate need to set up email auto-forwarding or grant delegate
access. If any other code path attempts these operations, permit0
auto-denies.

Built-in Claude Code tools (Bash, Edit, Read, Write, etc.) currently
have **no normalizers** in this repo's email-only pack. They fall through
to `unknown.unclassified` → `ask_user`. To gate them too, add normalizers
in `packs/<your-domain>/normalizers/` and risk rules in
`packs/<your-domain>/risk_rules/`.

---

## File locations summary

| Where | What |
|-------|------|
| `~/.permit0/permit0.db` | SQLite — audit log, policy cache, deny/allow lists |
| `~/.permit0/sessions.db` | SQLite — session-aware action history (for hook) |
| `~/.permit0/outlook_token.json` | MSAL token cache for Outlook |
| `~/.permit0/gmail_credentials.json` | Your Google Cloud OAuth client (you create this) |
| `~/.permit0/gmail_token.json` | Google OAuth token cache for Gmail |
| `~/.claude.json` | Claude Code config (hooks + mcpServers) |
| `<repo>/packs/email/` | Risk rules + normalizers (edit to tune policy) |
| `<repo>/profiles/` | Domain profiles (fintech, healthtech) |

---

## Next steps

- **Tune risk rules**: edit `packs/email/risk_rules/send.yaml` etc. to
  encode patterns you noticed during calibration.
- **Add a domain**: see `docs/pack-contribution-guide.md` to create a
  new pack (e.g. for Slack, GitHub, your internal API).
- **Audit log export**: `permit0 audit verify` and `permit0 audit
  inspect`, or use the dashboard's **Audit Log** tab → Export JSONL/CSV.
- **Dashboard tour**: see all 7 tabs at http://localhost:9090/ui/.
