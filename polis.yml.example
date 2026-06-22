# Polis pipeline configuration — copy to `polis.yml` to customize.
# With NO polis.yml, the pipeline runs claude everywhere, 3 review rounds, and the
# reviewer-correctness + reviewer-design reviewers (identical to the pre-config default).

# Named backends: harness + optional model + optional endpoint/credential.
backends:
  claude:                          # built-in; listed here only to set a model
    harness: claude                # claude | codex | aider
    model: claude-opus-4-8         # optional; omit to use the harness default
  codex-gpt:
    harness: codex
    model: gpt-5-codex
  deepseek:
    harness: aider                 # aider = universal (litellm): DeepSeek, Ollama, etc.
    model: deepseek/deepseek-chat
    api_key_env: DEEPSEEK_API_KEY  # add the secret in repo Settings, and a matching
                                   # env line in .github/workflows/agent-pipeline.yml
  local-qwen:
    harness: aider
    model: ollama/qwen2.5-coder
    base_url: http://localhost:11434   # only reachable with a self-hosted runner (feature #1)

# Global default backend, then per-role overrides.
defaults:
  backend: claude
roles:
  architect: { backend: claude }
  spec:      { backend: claude }
  code:      { backend: codex-gpt }
  fix:       { backend: claude }

# Review loop: number of rounds + an arbitrary list of independently-backed reviewers.
review:
  max_rounds: 3
  reviewers:
    - { persona: reviewer-correctness, backend: claude }
    - { persona: reviewer-design,      backend: deepseek }

# Skills to inject into agent system prompts (optional).
# Each entry is a sub-directory under skills/ that contains a SKILL.md file.
# For claude: skill content is appended via --append-system-prompt.
# For codex/aider: skill content is prepended to the task prompt.
#
# Option A — auto-detect (recommended for new projects):
#   Set auto: true and run install-harnesses.sh. It will call scripts/detect-skills.sh,
#   fingerprint the repo (CMakeLists.txt → C++, go.mod → Go, Cargo.toml → Rust, etc.),
#   and download the relevant SKILL.md files from everything-claude-code into skills/.
#   All downloaded skills are then available to every role automatically.
skills:
  auto: true               # detect stack + download from everything-claude-code on job start

# Option B — explicit list (for fine-grained control):
# skills:
#   global: [drive]          # skills/drive/SKILL.md — available to all roles
#   roles:
#     code: [drive, docs]    # code role also gets the docs skill

# Pipeline mode (optional). Default is "human" — a human must add the next label at
# each gate (spec→code, arch→decompose) and merge the final PR.
# Set to "auto" to skip all human gates: the pipeline applies agent:code / agent:decompose
# itself after each stage, and auto-merges the PR when reviews converge and tests pass.
# If tests fail or reviews don't converge, it still falls back to needs-human-review.
pipeline:
  mode: human   # human (default) | auto

# Review modes & named profiles (optional). The default code review is the `review:`
# block above; `review.mode` is `iterate` (revise+re-review) unless set to `comment`.
# Trigger a profile or a single backend with a label suffix, e.g.
#   agent:code_review:thorough   agent:spec_review:codex   agent:arch_review
# bootstrap-labels.sh creates one label per configured backend and per valid profile.
review_profiles:
  quick:                         # post comments and stop
    mode: comment
    reviewers: [ { backend: claude } ]
  thorough:                      # revise + re-review, two backends
    mode: iterate
    max_rounds: 3
    reviewers: [ { backend: codex-gpt }, { backend: deepseek } ]
