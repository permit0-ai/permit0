#!/usr/bin/env bash
# Project tests. The pipeline runs this to gate every PR.
# Auto-seeded by Polis onboarding from the detected stack — edit to match your project,
# or apply agent:fix and let the agent refine it.
set -euo pipefail
cargo test
