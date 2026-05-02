# permit0-outlook-mcp

MCP server that exposes Outlook tools (Microsoft Graph) to Claude Code, **each
call gated by permit0** so policy is enforced before any email is sent, moved,
or deleted.

## Architecture

```
Claude Code  ──MCP/stdio──▶  permit0-outlook-mcp
                               │
                               ├─▶ @permit0.guard("email.X")
                               │    └─ POST /api/v1/check_action ──▶ permit0 daemon
                               │                                       (allow/deny/human)
                               │
                               └─▶ Microsoft Graph API
                                    (only on allow)
```

## Tools exposed

| Tool | permit0 norm action | Description |
|------|---------------------|-------------|
| `outlook_list` | _(read-only metadata, no check)_ | List recent inbox messages |
| `outlook_read` | `email.read` | Read full content of one message |
| `outlook_send` | `email.send` | Send an email immediately |
| `outlook_draft` | `email.draft` | Save as draft (does not send) |
| `outlook_move` | `email.move` | Move to a destination folder |
| `outlook_archive` | `email.archive` | Move to Archive |
| `outlook_mark_spam` | `email.mark_spam` | Move to Junk Email |
| `outlook_delete` | `email.delete` | Move to Deleted Items |
| `outlook_create_folder` | `email.create_folder` | Create a new mail folder |

## Setup

### 1. Make sure the permit0 daemon is running

```bash
cd /path/to/permit0
cargo run -p permit0-cli -- serve --ui --port 9090
```

### 2. Install this MCP server + the Python SDK

```bash
# From repo root:
pip install -e clients/python          # permit0 SDK
pip install -e clients/outlook-mcp     # this server
```

### 3. Log in to Outlook once (creates token cache)

The MCP server runs as a subprocess of Claude Code, where interactive login is
clunky. Pre-populate the token cache by running the demo CLI once:

```bash
python demos/outlook/outlook_test.py list
```

Visit the Microsoft device-login URL it prints, sign in with your personal
Outlook account, approve `Mail.ReadWrite` + `Mail.Send`. Token caches to
`~/.permit0/outlook_token.json` and is reused by this MCP server.

### 4. Wire into Claude Code

Add to your Claude Code config (typically `~/.claude.json` or a project-local
`.mcp.json`):

```json
{
  "mcpServers": {
    "permit0-outlook": {
      "command": "permit0-outlook-mcp",
      "env": {
        "PERMIT0_URL": "http://localhost:9090"
      }
    }
  }
}
```

Restart Claude Code. The 9 tools above appear in its tool list.

## Try it

In Claude Code:

> 列出我收件箱里最近的 5 封邮件，归档所有上周的促销邮件。

Claude Code will call `outlook_list` (no permit0 check), then for each
candidate message, call `outlook_archive(message_id=...)`. Each archive call
hits permit0 — you'll see the decisions live in the dashboard at
http://localhost:9090/ui/ under the **Audit** tab.

> 发一封邮件给 bob@example.com，主题是 "测试"，内容是 "hi"。

Claude Code calls `outlook_send(to=..., subject=..., body=...)`. permit0
evaluates `email.send` against its risk rule. A clean send → ALLOW. Embedding
something like `password is hunter2` in the body → DENY (the SDK raises
`permit0.Denied`, the MCP layer reports the block to Claude Code).

## Combining with shadow mode

If you want to **observe** without enforcement while you tune the risk rules:

```bash
export PERMIT0_SHADOW=1   # for `permit0 hook` use
```

Note: this env var is read by the **`permit0 hook`** subcommand
(Claude Code PreToolUse). The MCP server itself enforces directly via
`@permit0.guard` — there's no built-in shadow flag yet. If you want shadow
mode for MCP tools too, ask and we'll add it.

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `PERMIT0_URL` | `http://localhost:9090` | permit0 daemon URL |
| `MSGRAPH_CLIENT_ID` | Microsoft Graph PowerShell public client | Override with your own Azure App reg |

## What this is NOT

- **Not a security boundary by itself.** The agent could in principle bypass
  the MCP server and call Graph directly. permit0 + this MCP wrapper assume a
  cooperating client — they're a policy layer for well-behaved agents, not a
  sandbox. For adversarial settings you also need to control the Graph token's
  scopes via Azure App registration.
- **Not a full email client.** Only the 9 verbs above are exposed. Add more by
  copying an existing tool definition in `server.py`.
