#!/usr/bin/env bash
# Dependency / toolchain setup. Runs BEFORE scripts/test.sh in CI and the pipeline.
# Auto-seeded by Polis onboarding from the detected stack — edit to match your project,
# or apply agent:fix and let the agent refine it.
set -euo pipefail
cargo build
