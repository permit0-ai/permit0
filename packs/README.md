# Packs

permit0 packs bundle the pieces that teach the engine how to govern a
domain: normalizers (raw tool call → canonical action), risk rules
(action → score), aliases (foreign names → canonical), and metadata.

## Layout

```
packs/
├── permit0/                ← first-party packs (built-in tier)
│   └── email/              ← unified Gmail + Outlook governance
│       ├── pack.yaml
│       ├── normalizers/
│       │   ├── gmail/
│       │   │   ├── _channel.yaml
│       │   │   ├── aliases.yaml
│       │   │   └── <verb>.yaml × 16
│       │   └── outlook/
│       │       ├── _channel.yaml
│       │       ├── aliases.yaml
│       │       └── <verb>.yaml × 16
│       └── risk_rules/
│           └── <verb>.yaml × 16  (channel-agnostic)
├── _template/              ← scaffold for new packs (skipped by discovery)
└── community/              ← Phase 2 placeholder; empty in Phase 1
```

## How packs become decisions

```
                        WORLD                        PACK                       POLICY
                    ┌──────────┐         ┌─────────────────────────┐     ┌────────────────┐
  agent calls ────► │   Tool   │ ──match──► Normalizer (YAML)      │ ───► │  ActionType    │
                    │ (vendor) │ (1 file) │  per raw tool          │ N:1  │  domain.verb   │
                    └──────────┘          │  normalizers/<ch>/<verb>.yaml │     │
                    e.g.                  └─────────────────────────┘           │ 1:1
                    gmail_send                                                   ▼
                    outlook_send                                       ┌────────────────┐
                                                                       │ Risk rule (YAML)│
                                                                       │  risk_rules/    │
                                                                       │  <verb>.yaml    │
                                                                       └────────────────┘
```

- **N tools → 1 action_type.** Two tools that mean the same thing
  share an action type (gmail_send + outlook_send → email.send).
- **1 normalizer → 1 tool.** Each raw tool name needs its own mapper
  because vendor parameter shapes differ.
- **1 risk rule → 1 action_type.** Rules score the canonical action,
  channel-agnostic.
- **1 pack → many normalizers + many risk rules,** grouped by domain.

Write your policy once at the action_type level and it covers every
tool any pack maps into it.

## Trust tiers

The engine derives the authoritative tier from `permit0_pack`'s owner
prefix. The `trust_tier:` field in `pack.yaml` is informational; the
validator flags mismatches.

| Tier | Path / source | Required signoff |
|---|---|---|
| `built-in` | `packs/permit0/<name>/` (first-party) | permit0 core team |
| `verified` | community + permit0 co-sign | **Phase 2** (needs signing infra) |
| `community` | everywhere else (default) | validation only |
| `experimental` | hidden by default | **Phase 2** |

## Adding a pack

```bash
# Copy the template
cp -r packs/_template packs/permit0/<name>     # first-party
# or
cp -r packs/_template packs/<your-org>/<name>  # community

# Edit pack.yaml, normalizers/, risk_rules/
$EDITOR packs/<owner>/<name>/pack.yaml

# Validate
permit0 pack validate packs/<owner>/<name>

# Run fixtures
permit0 pack test packs/<owner>/<name>
```

## What lives where

- **Normalizer YAML** under `normalizers/<channel>/<verb>.yaml`.
  Maps a raw tool call to a canonical action_type and extracts entities.
- **Channel metadata** in `normalizers/<channel>/_channel.yaml`.
  Captures the MCP server, auth model, and `tool_pattern` the validator
  enforces against every YAML in the directory.
- **Foreign-tool aliases** in `normalizers/<channel>/aliases.yaml`.
  Rewrites third-party MCP tool names onto canonical permit0
  normalizer names so policies route correctly.
- **Risk rule YAML** under `risk_rules/<verb>.yaml`. One file per
  action type; channel-agnostic. Defines the base flags + amplifiers
  and conditional rules.
- **`pack.yaml`** at the pack root. Schema v2 manifest; the
  validator's source of truth.
- **`tests/`** for fixtures: `<channel>/` for per-vendor goldens,
  `shared/` for cross-channel scenarios, `security/` for known-attack
  patterns (required for verified+ tier).

## Reading the existing pack

The first-party email pack (`packs/permit0/email/`) is the
reference implementation. 32 normalizers + 16 risk rules covering
Gmail and Outlook. Production-tested and the model every new pack
should follow.
