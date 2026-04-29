# Claude Code + permit0 — Quick Test Recipe

Get someone else to a working setup. ~10 min (Outlook) or ~15 min (with Gmail).

## 0. Install prereqs

Need: `cargo` 1.85+, `python` 3.10+, `sqlite3`, `claude` (Claude Code CLI).

### macOS

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Python + sqlite3 (system Python is fine; or via Homebrew)
brew install python sqlite

# Claude Code
brew install --cask claude-code   # or: npm install -g @anthropic-ai/claude-code
```

### Linux (Debian / Ubuntu)

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Python + sqlite3
sudo apt update && sudo apt install -y python3 python3-pip python3-venv sqlite3 build-essential pkg-config libssl-dev

# Claude Code (official install script — works on glibc Linux)
curl -fsSL https://claude.ai/install.sh | sh
# or via npm: npm install -g @anthropic-ai/claude-code
```

### Linux (other distros)

Use your package manager's equivalents (`dnf`, `pacman`, etc.) for python3 + sqlite3 + build tools, then run the same `rustup` and Claude Code installer lines above.

### Verify

```bash
cargo --version    # 1.85.0+
python3 --version  # 3.10+
sqlite3 --version
claude --version
```

## 1. Build + start daemon (calibrate mode)

```bash
git clone https://github.com/anthropics/permit0-core.git && cd permit0-core
cargo build --release
export PATH="$PATH:$(pwd)/target/release"
permit0 serve --calibrate --port 9090
```

Open http://localhost:9090/ui/ → enter a reviewer name → leave **Approvals** tab open.

## 2. Install MCP servers

```bash
pip install -e clients/outlook-mcp        # Outlook
pip install -e clients/gmail-mcp          # Gmail (skip if not needed)
```

## 3. Authenticate

**Outlook** (zero-config):

```bash
python demos/outlook/outlook_test.py list
```

Open the device-login URL it prints, sign in, approve `Mail.ReadWrite` + `Mail.Send`.

**Gmail** (one-time Google Cloud setup):

1. https://console.cloud.google.com/ → new project → enable **Gmail API**
2. **OAuth consent screen** → External → add yourself as test user
3. **Credentials** → Create OAuth Client ID → **Desktop app** → download JSON → save as `~/.permit0/gmail_credentials.json`
4. First-time login:
   ```bash
   python -c "from permit0_gmail_mcp.auth import get_token; get_token()"
   ```

## 4. Configure Claude Code

Add to `~/.claude.json` (merge if these keys already exist):

```json
{
  "hooks": {
    "PreToolUse": [{ "command": "permit0 hook --db ~/.permit0/sessions.db" }]
  },
  "mcpServers": {
    "permit0-outlook": { "command": "permit0-outlook-mcp" },
    "permit0-gmail":   { "command": "permit0-gmail-mcp" }
  }
}
```

If `permit0-outlook-mcp` isn't on Claude Code's PATH, replace with the absolute path from `which permit0-outlook-mcp`.

**Fully quit and relaunch** Claude Code.

## 5. Test

In Claude Code:

> List my 5 most recent inbox messages.

→ dashboard's **Approvals** tab shows a pending card (`email.search`, channel + tier + flags + entity preview) → click **Approve** → Claude Code unblocks and shows your inbox.

Try a few more (`archive that one`, `send an email to alice@example.com saying hi`, `delete that newsletter`) to populate the **Calibration** tab.

## 6. Switch to enforce when ready

Stop the calibrate daemon (Ctrl+C), restart without `--calibrate`:

```bash
permit0 serve --ui --port 9090
```

Now Allow/Deny route by tier; identical norm_hash calls auto-replay your earlier human decisions from cache.

## Common gotchas

- **Tools don't appear in Claude Code** → didn't fully quit/relaunch, OR MCP commands not on Claude Code's PATH (use absolute paths).
- **Hook returns ask_user for everything** → check `curl localhost:9090/api/v1/health` and that `which permit0` resolves where Claude Code can find it.
- **Hook can't find packs** → add `--packs-dir /absolute/path/to/permit0-core/packs` to the hook command.
- **Different MCP host (Cursor / Cline / …)** → `permit0 hook --client {claude-code|claude-desktop|raw}`. Default is `claude-code` (strips `mcp__<server>__` prefix).

## Reset for a fresh calibration

```bash
rm ~/.permit0/permit0.db ~/.permit0/sessions.db
```

(Wipes audit log too.)
