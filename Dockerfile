# syntax=docker/dockerfile:1.6
#
# Multi-stage build for the permit0 server image.
#
# Stage 1 (`builder`): pulls the workspace, fetches deps, builds the
# `permit0` CLI binary in release mode against musl-free GNU libc.
#
# Stage 2 (`runtime`): distroless cc-debian12 (about 25MB) with the
# binary + bundled rule packs. Distroless means no shell — all
# configuration must come from env vars or mounted files.

FROM rust:1.85-slim-bookworm AS builder

# Native deps for `rusqlite` (bundled SQLite still wants a C compiler)
# and for sqlx-postgres (no extra system deps; pure Rust + rustls).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the workspace. .dockerignore keeps target/, node_modules, .git,
# and other build artifacts out of the build context.
COPY . .

# Build only the CLI (and its transitive deps). `--locked` ensures the
# image is pinned to Cargo.lock for reproducibility.
RUN cargo build --release --locked -p permit0-cli

# ── Runtime image ────────────────────────────────────────────────────

FROM gcr.io/distroless/cc-debian12 AS runtime

LABEL org.opencontainers.image.title="permit0"
LABEL org.opencontainers.image.description="Deterministic permission engine for AI agent tool calls"
LABEL org.opencontainers.image.source="https://github.com/permit0-ai/permit0"

# The binary.
COPY --from=builder /build/target/release/permit0 /usr/local/bin/permit0

# Bundle the default rule packs and profiles. Operators can override the
# packs path with `PERMIT0_PACKS_DIR` and bind-mount their own.
COPY --from=builder /build/packs    /etc/permit0/packs
COPY --from=builder /build/profiles /etc/permit0/profiles

# Defaults documented at the top of `crates/permit0-cli/src/cmd/serve.rs`.
ENV PERMIT0_PACKS_DIR=/etc/permit0/packs \
    PERMIT0_AUDIT_KEY_PATH=/var/lib/permit0/audit_signing.key \
    HOME=/var/lib/permit0

EXPOSE 9090

# distroless has no shell, so use exec form. Operators add `--profile`,
# `--port`, etc. as docker run / compose args.
ENTRYPOINT ["/usr/local/bin/permit0"]
CMD ["serve", "--ui", "--port", "9090"]
