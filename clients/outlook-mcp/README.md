# permit0-outlook-mcp

MCP server that exposes Outlook tools (Microsoft Graph) to agent hosts.
With Codex and Claude Code, permit0 enforcement happens at the host
`PreToolUse` hook layer: the host proposes
`mcp__permit0-outlook__outlook_send`, the permit0 hook sends it to the
daemon, and the Graph API call only runs when the hook allows it.

## Architecture

```text
Agent host ──PreToolUse hook──▶ permit0 hook --client <host> --remote :9090
   │                                  │
   │                                  └─▶ permit0 daemon/dashboard
   │                                        (allow/deny/human)
   │
   └─MCP/stdio, only if allowed──────▶ permit0-outlook-mcp
                                          └─▶ Microsoft Graph API
```

For hosts without a hook layer, add an equivalent pre-tool gate before
starting this MCP server. The server itself is plain MCP and does not
call permit0 internally.

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
clunky. Pre-populate the token cache by triggering the auth flow once:

```bash
python -c "from permit0_outlook_mcp.auth import get_token; get_token()"
```

Visit the Microsoft device-login URL it prints, sign in with your personal
Outlook account, approve `Mail.ReadWrite` + `Mail.Send`. Token caches to
`~/.permit0/outlook_token.json` and is reused by this MCP server.

### 4. Wire into Codex or Claude Code

Both Codex and Claude Code enforce Outlook tools through a host-level
`PreToolUse` hook. The MCP server config only exposes the tools; the hook
is what calls permit0 before Microsoft Graph runs.

#### Codex

Install the daemon-backed Codex hook:

```bash
PERMIT0_URL=http://127.0.0.1:9090 bash integrations/permit0-codex/examples/install-managed-prefs.sh
```

For Codex, add the Outlook MCP server to your Codex config:

```toml
[mcp_servers.permit0-outlook]
command = "/absolute/path/to/permit0-outlook-mcp"
```

#### Claude Code

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

For Claude Code, add it to `~/.claude.json` or project-local `.mcp.json`:

```json
{
  "mcpServers": {
    "permit0-outlook": {
      "command": "permit0-outlook-mcp"
    }
  }
}
```

Restart the host. The 9 tools above appear in its tool list, and each
mutating Outlook MCP call is enforced by the daemon-backed host hook
before the MCP server is called.

## Try it

In your agent host:

> List the 5 most recent emails in my inbox and archive all promotional emails from last week.

The host will call `outlook_search` or `outlook_list`, then for each
candidate message, call `outlook_archive(message_id=...)`. Each archive
call is evaluated by the hook before it reaches the MCP server; you'll
see the decisions live in the dashboard at <http://localhost:9090/ui/>.

> Send an email to bob@example.com with subject "test" and body "hi".

The host calls `outlook_send(to=..., subject=..., body=...)`. permit0
evaluates `email.send` against its risk rule. A clean send can run.
Sensitive content or risky recipients return a deny envelope from the
hook, so the host blocks the tool call before the MCP layer reaches
Microsoft Graph.

## Combining with shadow mode

If you want to **observe** without enforcement while you tune the risk rules:

```bash
export PERMIT0_SHADOW=1   # for `permit0 hook` use
```

Note: this env var is read by the **`permit0 hook`** subcommand. The MCP
server itself is plain MCP, so shadow/enforcement behavior is controlled
by the host hook command.

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `MSGRAPH_CLIENT_ID` | Microsoft Graph PowerShell public client | Override with your own Azure App reg |

## What this is NOT

- **Not a security boundary by itself.** The agent could in principle bypass
  the MCP server and call Graph directly. permit0 + this MCP wrapper assume a
  cooperating client — they're a policy layer for well-behaved agents, not a
  sandbox. For adversarial settings you also need to control the Graph token's
  scopes via Azure App registration.
- **Not a full email client.** Only the 9 verbs above are exposed. Add more by
  copying an existing tool definition in `server.py`.
