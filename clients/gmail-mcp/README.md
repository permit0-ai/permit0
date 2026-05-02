# permit0-gmail-mcp

MCP server that exposes Gmail tools (Gmail API v1) to Claude Code, **each
call gated by permit0**. Mirrors `clients/outlook-mcp` — same 13 tools, same
norm actions, same risk rules.

## Architecture

```
Claude Code  ──MCP/stdio──▶  permit0-gmail-mcp
                               │
                               ├─▶ @permit0.guard("email.X")
                               │    └─ POST /api/v1/check_action ──▶ permit0 daemon
                               │                                       (allow/deny/human)
                               │
                               └─▶ Gmail API (gmail.googleapis.com/gmail/v1)
                                    (only on allow)
```

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

### 4. Wire into Claude Code

Add to `~/.claude.json` under top-level `mcpServers`:

```json
{
  "mcpServers": {
    "permit0-gmail": {
      "command": "permit0-gmail-mcp",
      "env": {
        "PERMIT0_URL": "http://localhost:9090"
      }
    }
  }
}
```

Restart Claude Code. The 13 `gmail_*` tools appear.

You can have **both** `permit0-outlook` and `permit0-gmail` configured at
the same time — both gate through the same permit0 daemon, both lower to
the same `email.*` norm actions, same risk rules.

## Try it

In Claude Code:

> Search my Gmail for "newsletter" emails from the past 7 days and archive all results.

Claude Code will call `gmail_search(query="newsletter newer_than:7d")` →
permit0 evaluates each result's `gmail_archive(message_id=...)`.

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
| `PERMIT0_URL` | `http://localhost:9090` | permit0 daemon URL |
| `GMAIL_CREDENTIALS` | `~/.permit0/gmail_credentials.json` | OAuth app credentials |

## Cross-backend invariant

If you have both Gmail and Outlook MCP servers configured, **both** lower
to the same `email.*` norm actions. permit0 sees one unified IR. The
dashboard's audit log shows `channel=gmail` vs `channel=outlook`, but the
risk rule and the human reviewer's decision applies regardless.
