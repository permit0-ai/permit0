# permit0-gmail-mcp

MCP server that exposes Gmail tools (Gmail API v1) to agent hosts. With
Codex and Claude Code, permit0 enforcement happens at the host
`PreToolUse` hook layer: the host proposes
`mcp__permit0-gmail__gmail_send`, the permit0 hook sends it to the
daemon, and the Gmail API call only runs when the hook allows it.
Mirrors `clients/outlook-mcp` — same 13 tools, same norm actions, same
risk rules.

## Architecture

```text
Agent host ──PreToolUse hook──▶ permit0 hook --client <host> --remote :9090
   │                                  │
   │                                  └─▶ permit0 daemon/dashboard
   │                                        (allow/deny/human)
   │
   └─MCP/stdio, only if allowed──────▶ permit0-gmail-mcp
                                          └─▶ Gmail API
```

For hosts without a hook layer, add an equivalent pre-tool gate before
starting this MCP server. The server itself is plain MCP and does not
call permit0 internally.

## Tools exposed

Same 13 tools as outlook-mcp — same parameters, same norm actions:

| Tool | Norm action | Description |
|------|-------------|-------------|
| `gmail_search` | `email.search` | Search messages with Gmail query syntax |
| `gmail_read` | `email.read` | Read full content of one message |
| `gmail_read_thread` | `email.read_thread` | Read all messages in a thread |
| `gmail_list_mailboxes` | `email.list_mailboxes` | List labels (Gmail's mailbox equivalent) |
| `gmail_draft` | `email.draft` | Create / modify / reply / forward draft |
| `gmail_send` | `email.send` | Send (new / reply / forward / from-draft) |
| `gmail_mark_read` | `email.mark_read` | Mark read / unread (UNREAD label) |
| `gmail_flag` | `email.flag` | Star / unstar (STARRED label) |
| `gmail_move` | `email.move` | Move to label (adds dest, removes INBOX) |
| `gmail_archive` | `email.archive` | Remove INBOX label |
| `gmail_mark_spam` | `email.mark_spam` | Add SPAM label |
| `gmail_delete` | `email.delete` | Trash (recoverable) |
| `gmail_create_mailbox` | `email.create_mailbox` | Create label |

## One-time setup

### 1. Get OAuth credentials from Google

Unlike Outlook (which has a public client_id), Gmail requires a per-user
OAuth app. ~5 minutes:

1. Go to https://console.cloud.google.com/
2. Create a new project (or select an existing one)
3. **APIs & Services** → **Library** → search "Gmail API" → **Enable**
4. **APIs & Services** → **OAuth consent screen** → set up (External user
   type is fine for personal use; add yourself as a test user)
5. **APIs & Services** → **Credentials** → **Create credentials** →
   **OAuth client ID** → **Application type: Desktop app**
6. Download the JSON, save as `~/.permit0/gmail_credentials.json`

(Or set `GMAIL_CREDENTIALS=/some/other/path.json`.)

### 2. Install the MCP server

```bash
# From repo root
pip install -e clients/python clients/gmail-mcp
```

### 3. First-time login (interactive consent)

The first call from Claude Code (or the line below) will pop a browser to
ask for Google consent. The token caches at `~/.permit0/gmail_token.json`
and silent-refreshes after that.

```bash
python -c "from permit0_gmail_mcp.auth import get_token; print(bool(get_token()))"
```

### 4. Wire into Codex or Claude Code

Both Codex and Claude Code enforce Gmail tools through a host-level
`PreToolUse` hook. The MCP server config only exposes the tools; the hook
is what calls permit0 before Gmail runs.

#### Codex

Start the permit0 daemon and install the Codex hook in remote mode:

```bash
cd /path/to/permit0
cargo run -p permit0-cli -- serve --ui --port 9090
PERMIT0_URL=http://127.0.0.1:9090 bash integrations/permit0-codex/examples/install-managed-prefs.sh
```

Add the Gmail MCP server to your Codex config:

```toml
[mcp_servers.permit0-gmail]
command = "/absolute/path/to/permit0-gmail-mcp"
```

Restart Codex. The 13 `gmail_*` tools appear, and every Gmail MCP tool
call is enforced by the daemon-backed Codex hook before the MCP server
is called.

#### Claude Code

Start the same daemon:

```bash
cd /path/to/permit0
cargo run -p permit0-cli -- serve --ui --port 9090
```

Add the permit0 hook to Claude Code, for example in
`~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{ "hooks": [{
      "type": "command",
      "command": "/absolute/path/to/permit0/target/release/permit0 hook --remote http://127.0.0.1:9090 --unknown defer"
    }]}]
  }
}
```

If you are using Claude Code, wire the server under top-level
`mcpServers`:

```json
{
  "mcpServers": {
    "permit0-gmail": {
      "command": "permit0-gmail-mcp"
    }
  }
}
```

Restart Claude Code. The same `gmail_*` tools appear, and the hook gates
each call before it reaches Gmail.

You can have **both** `permit0-outlook` and `permit0-gmail` configured at
the same time. With the host's permit0 hook configured, both lower to the
same `email.*` norm actions and are evaluated by the same daemon, using
the same risk rules.

## Try it

In Claude Code:

> Search my Gmail for "newsletter" emails from the past 7 days and archive all results.

Claude Code will call `gmail_search(query="newsletter newer_than:7d")` →
the host hook evaluates each `gmail_archive(message_id=...)` before it
reaches the MCP server.

> Read that entire thread.

→ `gmail_read_thread(thread_id=...)` (Gmail has native threads, no
conversationId stitching needed).

## What this is NOT

- **Not a security boundary.** A misbehaving agent could call Gmail API
  directly with the cached token. permit0 + MCP is a policy layer for
  cooperating clients, not a sandbox. For adversarial settings, restrict
  the OAuth scopes when registering the app.
- **Not a permanent-delete tool.** `gmail_delete` only trashes. If you
  need permanent deletion, add a separate `email.permanent_delete` norm
  action with a CRITICAL gate per the spec.

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `GMAIL_CREDENTIALS` | `~/.permit0/gmail_credentials.json` | OAuth app credentials |

## Cross-backend invariant

If you have both Gmail and Outlook MCP servers configured behind a
permit0 hook, **both** lower to the same `email.*` norm actions. permit0
sees one unified IR. The dashboard's audit log shows `channel=gmail` vs
`channel=outlook`, but the risk rule and the human reviewer's decision
applies regardless.
