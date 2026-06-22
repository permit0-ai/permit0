#!/usr/bin/env bash
# Install the agent harnesses this fork actually uses. Always installs claude.
# When polis.yml is present, installs yq and every harness referenced under
# backends[].harness (deduped). Idempotent; safe to run at the top of every job.
set -euo pipefail
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# Restore Codex's ChatGPT-subscription credentials (what `codex login` writes to
# ~/.codex/auth.json) from the CODEX_AUTH secret, so the codex harness can use a
# subscription instead of a metered OPENAI_API_KEY — the analog of CLAUDE_CODE_OAUTH_TOKEN.
# No-op when CODEX_AUTH is unset. Honors CODEX_HOME (codex's own location override).
# Note: codex refreshes the token in-run only; it can't persist back to the secret,
# so re-export auth.json into CODEX_AUTH if it expires.
restore_codex_auth() {
  [[ -n "${CODEX_AUTH:-}" ]] || return 0
  local dir="${CODEX_HOME:-$HOME/.codex}"
  mkdir -p "$dir"
  printf '%s' "$CODEX_AUTH" > "$dir/auth.json"
  chmod 600 "$dir/auth.json"
  echo "install-harnesses: restored Codex auth to $dir/auth.json"
}

npm install -g @anthropic-ai/claude-code

CONFIG="$REPO_ROOT/polis.yml"
[[ -f "$CONFIG" ]] || { echo "install-harnesses: no polis.yml, claude only"; exit 0; }

if ! command -v yq >/dev/null 2>&1; then
  _os="$(uname -s)" _arch="$(uname -m)"
  case "$_os" in
    Linux*)
      case "$_arch" in
        x86_64)        _yq="yq_linux_amd64" ;;
        aarch64|arm64) _yq="yq_linux_arm64" ;;
        *) echo "install-harnesses: unsupported Linux arch '$_arch'; install yq manually" >&2; exit 1 ;;
      esac
      sudo wget -qO /usr/local/bin/yq \
        "https://github.com/mikefarah/yq/releases/latest/download/${_yq}"
      sudo chmod +x /usr/local/bin/yq ;;
    Darwin*)
      brew install yq ;;
    *)
      echo "install-harnesses: unsupported OS '$_os'; install yq manually (https://github.com/mikefarah/yq)" >&2
      exit 1 ;;
  esac
fi

# Process substitution (not a pipe) keeps the loop in the current shell, so the
# unknown-harness `exit 1` aborts the job. No mapfile → runs on bash 3.2 too.
while IFS= read -r h; do
  case "$h" in
    claude|"") : ;;  # claude already installed; "" = backend with no harness field
    codex)  npm install -g @openai/codex; restore_codex_auth ;;
    aider)  pipx install aider-chat || pip install --user aider-chat ;;
    *) echo "install-harnesses: unknown harness '$h' in polis.yml" >&2; exit 1 ;;
  esac
done < <(yq -r '.backends[].harness' "$CONFIG" 2>/dev/null | sort -u)

# Auto-skill download: when skills.auto is true in polis.yml, detect the project's tech
# stack and fetch each skill's SKILL.md from the everything-claude-code GitHub repo.
# Idempotent: already-present SKILL.md files are not re-downloaded.
install_auto_skills() {
  [[ "$(yq -r '.skills.auto // false' "$CONFIG" 2>/dev/null)" == "true" ]] || return 0
  local skill_base="https://raw.githubusercontent.com/affaan-m/everything-claude-code/main/skills"
  local skills_dir="$REPO_ROOT/skills"
  local detected; detected="$(bash "$REPO_ROOT/scripts/detect-skills.sh" | sort -u)"
  [[ -z "$detected" ]] && { echo "install-harnesses: no skills auto-detected"; return 0; }
  while IFS= read -r skill; do
    [[ -z "$skill" ]] && continue
    local target="$skills_dir/$skill/SKILL.md"
    if [[ -f "$target" ]]; then
      echo "install-harnesses: skill $skill already present, skipping"
      continue
    fi
    mkdir -p "$(dirname "$target")"
    if curl -fsSL "$skill_base/$skill/SKILL.md" -o "$target" 2>/dev/null; then
      echo "install-harnesses: downloaded skill $skill"
    else
      echo "install-harnesses: skill $skill not found in registry, skipping" >&2
      rm -f "$target"; rmdir "$(dirname "$target")" 2>/dev/null || true
    fi
  done <<< "$detected"
}
install_auto_skills
