#!/usr/bin/env bash
# Idempotently create every label the agent pipeline needs.
# Safe to re-run; --force updates existing labels. Requires gh auth + issues:write.
set -euo pipefail

label() { gh label create "$1" --color "$2" --description "$3" --force; }

# Trigger labels (human-applied)
label "agent:arch"       "5319E7" "Planning: write architecture doc"
label "agent:rearch"     "5319E7" "Revise architecture doc from human comments"
label "agent:decompose"  "5319E7" "Materialize the approved breakdown into issues"
label "agent:spec"       "1D76DB" "Execution: write spec for this issue"
label "agent:respec"     "1D76DB" "Revise spec from human comments"
label "agent:code"       "0E8A16" "Implement code + tests and run AI review"
label "agent:fix"        "0E8A16" "Revise code from human comments"
# Status labels (pipeline-applied)
label "arch-review"        "FBCA04" "Architecture doc awaiting human review"
label "spec-review"        "FBCA04" "Spec awaiting human review"
label "needs-human-review" "0E8A16" "PR ready; awaiting human review"
label "agent:cap-reached"  "D93F0B" "AI review loop hit the round cap"
label "tests-failing"      "B60205" "Tests are failing on the PR"
label "agent:failed"       "B60205" "Agent pipeline run errored"

# --- Config-driven review labels ----------------------------------------------
# One per artifact (bare = default recipe) + one per configured backend + one per
# profile whose backends are all configured. Sourced from polis.yml; claude-only
# when there is no config. yq is only invoked when polis.yml exists.
POLIS_CONFIG="${POLIS_CONFIG:-$(cd "$(dirname "$0")/.." && pwd)/polis.yml}"
REVIEW_COLOR="FBCA04"

_backends_list() {
  { [[ -f "$POLIS_CONFIG" ]] && yq -r '.backends // {} | keys | .[]' "$POLIS_CONFIG" 2>/dev/null
    echo claude; } | sort -u
}

_valid_profiles() {   # profiles whose every reviewer backend is configured
  [[ -f "$POLIS_CONFIG" ]] || return 0
  local valid p b ok
  valid="$(_backends_list)"
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    ok=1
    while IFS= read -r b; do
      [[ -z "$b" ]] && continue
      grep -qxF "$b" <<<"$valid" || ok=0
    done < <(yq -r ".review_profiles.\"$p\".reviewers[].backend // \"claude\"" "$POLIS_CONFIG" 2>/dev/null)
    [[ "$ok" == 1 ]] && echo "$p"
  done < <(yq -r '.review_profiles // {} | keys | .[]' "$POLIS_CONFIG" 2>/dev/null)
}

for artifact in code spec arch; do
  label "agent:${artifact}_review" "$REVIEW_COLOR" "AI review of the ${artifact} (default recipe)"
  while IFS= read -r b; do
    [[ -z "$b" ]] && continue
    label "agent:${artifact}_review:${b}" "$REVIEW_COLOR" "AI review of the ${artifact} on backend ${b}"
  done < <(_backends_list)
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    label "agent:${artifact}_review:${p}" "$REVIEW_COLOR" "AI review of the ${artifact} via profile ${p}"
  done < <(_valid_profiles)
done
