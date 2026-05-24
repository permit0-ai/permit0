# Installation

permit0 has two pieces: a long-running **engine + dashboard** daemon (one
per org / one per machine) and a per-call **hook binary** that Claude
Code spawns on every tool invocation. Optionally, MCP servers (Gmail,
Outlook) that translate Google / Microsoft APIs into the canonical
taxonomy.

Pick the path that matches what you have on the host:

|  | Docker (recommended) | From source |
|---|---|---|
| Host prereqs | Docker 24+, Compose v2 | Rust 1.85+, `pkg-config`, `build-essential` (Linux) |
| Engine + dashboard | `docker compose up -d --build` | `cargo run -p permit0-cli -- serve --ui --port 9090` |
| Hook binary | `docker cp` out of image (or build locally) | `cargo install --path crates/permit0-cli --locked` |
| MCP servers | `docker compose up -d --build` (in permit0-mcp) | `pip install -e permit0-mcp/{gmail,outlook}-mcp` + run the entry points |
| State / audit DBs | Postgres in containers | SQLite under `~/.permit0/` |
| Roughly | 1.5 GB disk, ~3 min first build | ~5 GB Cargo cache, ~5 min first build |

## Path A — Docker

### 1. Engine + dashboard

```bash
git clone https://github.com/permit0-ai/permit0.git
cd permit0
docker compose up -d --build
docker compose logs -f permit0-engine    # wait for the "listening on 0.0.0.0:9090" line
```

This starts three containers: `permit0-state-db` (Postgres for
denylist / allowlist / cache / HITL queue), `permit0-audit-db`
(Postgres for the signed hash chain), and `permit0-engine` (the CLI
in `serve --ui` mode). The engine waits for both DBs to pass
`pg_isready` and runs sqlx migrations on startup. Verify:

```bash
curl http://localhost:9090/api/v1/health
# {"ok":true,"service":"permit0"}
```

Dashboard: <http://localhost:9090/ui/>

### 2. MCP servers (optional, for Gmail / Outlook governance)

```bash
git clone https://github.com/permit0-ai/permit0-mcp.git
cd permit0-mcp
docker compose up -d --build
```

Endpoints: Gmail `http://localhost:8000/mcp`, Outlook
`http://localhost:8001/mcp` (MCP streamable-http transport).

**OAuth one-time setup** lives in the MCP repo's per-server READMEs:

- Gmail needs `~/.permit0/gmail_credentials.json` (a Google OAuth
  desktop-app JSON) seeded into the `gmail-state` volume, plus a
  one-time interactive login to mint `gmail_token.json`. See
  [`permit0-mcp/gmail-mcp/README.md`](https://github.com/permit0-ai/permit0-mcp/tree/main/gmail-mcp).
- Outlook does an MSAL device-code login on first call — `docker
  compose logs -f outlook` to see the URL + code.

### 3. Host hook binary

The hook is spawned by Claude Code per tool call, so it has to live on
the host. Easiest path: copy it out of the engine image (no Rust
toolchain required):

```bash
docker create --name _p0tmp permit0-engine:latest
docker cp _p0tmp:/usr/local/bin/permit0 ~/.local/bin/permit0
docker rm _p0tmp
chmod +x ~/.local/bin/permit0
permit0 --help    # confirm $PATH picks it up
```

Or build it locally with `cargo install --path crates/permit0-cli
--locked` if you already have Rust.

Continue to [Wire Claude Code](#wire-claude-code).

## Path B — From source

### Prereqs

- Rust 1.85+ (`rustup update stable`)
- `pkg-config` + a C compiler — Debian/Ubuntu: `sudo apt install -y
  pkg-config build-essential`; macOS: Xcode Command Line Tools

### 1. Engine + dashboard

```bash
git clone https://github.com/permit0-ai/permit0.git
cd permit0
cargo run -p permit0-cli --release -- serve --ui --port 9090
```

In release mode the engine evaluates noticeably faster than a debug
build — worth the longer compile. State and audit live in
`~/.permit0/state.db` and `~/.permit0/audit.db` (SQLite) unless you
export `PERMIT0_STATE_URL` / `PERMIT0_AUDIT_URL` to point at Postgres
instances.

### 2. MCP servers

```bash
git clone https://github.com/permit0-ai/permit0-mcp.git
pip install -e permit0-mcp/gmail-mcp     # 13 gmail_* tools
pip install -e permit0-mcp/outlook-mcp   # 13 outlook_* tools
# OAuth setup per server (see READMEs above)
```

With this path the MCP servers run as **stdio** subprocesses spawned
by Claude Code, not long-lived HTTP services. The `~/.claude/settings.json`
snippet later uses the `command:` form rather than the `url:` form.

### 3. Hook binary

```bash
cargo install --path crates/permit0-cli --locked
which permit0    # → ~/.cargo/bin/permit0
```

## Wire Claude Code

The hook reads `~/.permit0/config.yaml` on every call:

```yaml
# ~/.permit0/config.yaml
remote: "http://127.0.0.1:9090"   # the engine — omit for local in-process mode
hitl_routing: "ui-wait"            # "ui-wait" blocks at the dashboard; "cc-prompt" inline
hitl_timeout_secs: 300             # auto-deny after this many seconds
org_domain: "yourcompany.com"      # internal/external recipient classification
client: "claude-code"              # MCP tool-name prefix stripping
unknown: "bypass"                  # "bypass" / "ask" / "allow" / "deny" — fallback for unpacked tools
shadow: false                      # true → log decisions, always allow
```

`unknown: "bypass"` lets Claude Code's own permission UI handle tools
permit0 has no pack for — recommended so unknown tools don't pile up in
the human queue. They surface in the dashboard's `bypass` filter so you
can still audit what flowed through. Override per-invocation with
`--config`, `--remote`, `--unknown`, `--shadow`, etc.

Then wire the hook + MCPs into Claude Code. Pick the matching `mcpServers`
shape for your path:

```jsonc
// ~/.claude/settings.json — gates every tool call before it runs
{
  "hooks": {
    "PreToolUse": [{ "hooks": [{
      "type": "command",
      "command": "/abs/path/to/permit0 hook"
    }]}]
  },
  "mcpServers": {
    // Path A — MCP servers in Docker, exposed over HTTP
    "permit0-gmail":   { "type": "http", "url": "http://localhost:8000/mcp" },
    "permit0-outlook": { "type": "http", "url": "http://localhost:8001/mcp" }

    // Path B — pip-installed, stdio subprocess
    // "permit0-gmail":   { "command": "/abs/path/to/permit0-gmail-mcp" },
    // "permit0-outlook": { "command": "/abs/path/to/permit0-outlook-mcp" }
  }
}
```

Restart Claude Code. The PreToolUse hook now fires before every tool
call, posts to the engine, and emits an `allow` / `deny` / `ask`
envelope based on the engine's verdict.

## Verify end-to-end

In Claude Code:

> List my recent emails

You should see the call show up in the dashboard's **Recent Decisions**
tab (`http://localhost:9090/ui/`). Then:

> Send alice@external.com a one-line note saying hi

If `hitl_routing: "ui-wait"` is set, the call **blocks** until you
approve at the dashboard's **Approvals** tab. The card shows the full
normalized action (domain.verb, surface tool, norm_hash) plus the
parameters (to, subject, body).

Shadow mode (`permit0 hook --shadow` or set `PERMIT0_SHADOW=1`) logs
decisions to stderr without ever blocking — useful for observing what
permit0 *would* do before enforcing.

## Common issues

**Hook returns "ask" + `permit0 remote unavailable: …`**
The engine isn't reachable at `remote:`. Check `docker compose ps`
(Path A) or that `cargo run -- serve --ui` is still up (Path B).

**Hook returns "deny" + `HTTP 400: ui-wait routing not supported`**
The engine was started without `--ui`. `ui-wait` needs the dashboard's
ApprovalManager. Pass `--ui` (Path B) or check `docker compose logs
permit0-engine` shows the admin-dashboard line (Path A).

**Approval cards only show `message_id` for delete / archive / etc.**
Known limitation: the MCP server only sees the agent's tool parameters,
which for these verbs is just an opaque ID. The reviewer sees domain,
verb, channel, surface tool, and norm_hash on the card — but not the
message's subject or body. Enriching this requires a pre-fetch in the
MCP server before the PreToolUse hook fires; tracked separately.

**`hook --help` doesn't show `--config`**
You're running an older binary. Re-copy from the engine image (Path A)
or `cargo install --path crates/permit0-cli --locked` again (Path B).

## Production deltas

The default `docker-compose.yml` is dev-grade. Before shipping:

1. Replace every `POSTGRES_PASSWORD` (`.env` or your secrets manager).
2. Add TLS at a reverse proxy in front of `:9090` (nginx / caddy /
   traefik).
3. Add auth in front of the dashboard — OIDC is wired but the
   defaults are open. See `permit0-ui/src/oidc/`.
4. Back up the `audit-key` named volume (the ed25519 signing seed)
   together with `audit-db-data` — losing the seed means the old
   chain becomes unverifiable.
5. Consider promoting the two Postgres instances to managed
   services (RDS / Cloud SQL).

The Chinese-language operational guide at
[`docs/docker-quickstart.md`](docker-quickstart.md) has more verification
recipes (audit-chain export, CloudTrail-style digest verification,
OTel collector tee).
