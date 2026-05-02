# Pack Taxonomy Refactor (Phase 1)

> Status: Design accepted via `/plan-eng-review` on 2026-05-01.
> Source discussion: `discussion-pack-taxonomy.md` (working doc, not in repo).
> This document captures the refined plan after engineering review and
> outside-voice challenge.

## Goal

Restructure permit0's pack system so:

- Packs are owner-namespaced (`packs/<owner>/<pack>/`) — first-party and community
  packs share the same path shape.
- Normalizers are grouped by channel/vendor (`normalizers/<channel>/<verb>.yaml`)
  so adding a vendor is a single-directory drop.
- Trust tier is **derived** (path + signature), not declared, eliminating the
  self-attestation footgun.
- Pack discovery is lockfile-driven for repeatability and supply-chain hygiene.
- The catalog/taxonomy distinction is reflected in code (rename
  `catalog.rs → taxonomy.rs`, `CatalogError → TaxonomyError`).

## Cardinality (the architectural point)

```
                      WORLD                           PACK                    POLICY
                  ┌──────────┐               ┌───────────────────┐      ┌──────────────┐
  agent calls ──► │   Tool   │ ────match───► │ Normalizer (YAML) │ ───► │  ActionType  │
                  │ (vendor) │   (1 file     │  per raw tool     │  N:1 │  domain.verb │
                  └──────────┘    per tool)  └───────────────────┘      └──────┬───────┘
                  e.g.                       e.g.                              │
                  outlook_send               outlook/send.yaml                 │ 1:1
                  gmail_send                 gmail/send.yaml ─────────────┐    │
                                                                          ▼    ▼
                                                                  ┌──────────────────┐
                                                                  │ Risk rule (YAML) │
                                                                  │   send.yaml      │
                                                                  └──────────────────┘
```

- **N tools → 1 action_type.** Two tools meaning the same thing share a verb.
- **1 normalizer → 1 tool.** Each raw tool needs its own mapper (parameter names differ).
- **1 risk rule → 1 action_type.** Rules live at the canonical layer.
- **1 pack → many normalizers + many risk rules**, grouped by domain.

Write your policy once at the action_type level; it applies to every tool any pack
maps into it.

## Refined PR sequence

```
PR 1 — Rename catalog → taxonomy (cosmetic + types)
       ├── crates/permit0-types/src/catalog.rs → taxonomy.rs
       ├── docs/norm_actions/norm_actions.md → docs/taxonomy.md
       ├── README headers ("Action Type Catalog" → "Action Type Taxonomy")
       ├── Rename CatalogError → TaxonomyError; bump permit0-types minor
       ├── Update permit0-py + permit0-node SDK callers in same PR
       └── Introduce test fixture helper `load_test_fixture()` replacing 4
           include_str! sites in 3 crates:
           - crates/permit0-engine/src/engine.rs:899-902 (3 sites)
           - crates/permit0-dsl/src/validate.rs:401
           - crates/permit0-dsl/tests/pack_integration.rs:21-23

PR 2 — Schema v2 + discovery + lockfile (on the OLD layout)
       ├── pack.yaml schema v2:
       │   ├── pack_format: 2  (engine refuses to load format=1)
       │   ├── trust_tier:     (informational; engine derives from path/signature)
       │   ├── permit0_engine: ">=0.5.0,<0.6"
       │   ├── taxonomy: "1.x"
       │   ├── action_types: [...]
       │   ├── maintainers: [{github: "@..."}]
       │   ├── channels: {gmail: {...}, outlook: {...}}
       │   ├── signature: <reserved, optional, empty Phase 1>
       │   ├── provenance: <reserved, optional, empty Phase 1>
       │   ├── content_hash: <reserved, optional, empty Phase 1>
       │   ├── (drop) vendor:
       │   └── (drop) explicit normalizers / risk_rules lists
       ├── pack.lock.yaml (Cargo.lock-style; committed)
       ├── Engine: lockfile-driven load (filesystem fallback in dev with warn)
       │   - Lazy hash verification by default
       │   - --strict-lockfile flag for CI
       │   - Strict mandatory for community-tier loads
       ├── Shared `discover_packs()` helper in permit0-engine, used by all
       │   5 consumers (engine_factory, permit0-py, permit0-node,
       │   permit0-shell-dispatch, permit0-ui)
       ├── Trust tier derivation:
       │   - packs/permit0/* → built-in
       │   - everywhere else → community
       │   - verified, experimental → DEFERRED until signing infrastructure
       ├── permit0 pack validate gains 11 checks (schema, naming, taxonomy
       │   compliance, coverage, orphan, channel pattern, determinism,
       │   calibration, coverage minimum, security lint, license)
       └── Validator unit tests for each check

PR 3 — File restructure (channel-grouped + owner-namespaced)
       ├── packs/email/ → packs/permit0/email/
       ├── normalizers/{gmail_,outlook_}<verb>.yaml
       │   → normalizers/{gmail,outlook}/<verb>.yaml
       ├── _channel.yaml (gmail, outlook) — declares tool_pattern, mcp_server
       ├── aliases.yaml split: pack-root → normalizers/{gmail,outlook}/aliases.yaml
       │   (alias resolver merges per-channel files at registry build)
       ├── + outlook_list_drafts.yaml (mirrors outlook_search.yaml)
       ├── + risk_rules/list_drafts.yaml (mirrors search.yaml)
       ├── Update pack.yaml channels: section
       ├── Regenerate pack.lock.yaml
       ├── DSL loader globs normalizers/<channel>/*.yaml
       └── Engine snapshot test (insta or hand-rolled): byte-identical
           NormAction across migration

PR 4 — Community contribution scaffolding
       ├── packs/_template/
       ├── packs/community/.gitkeep + README
       ├── packs/README.md (cardinality diagram + tier explanation)
       ├── docs/pack-contribution-guide.md (rewritten end-to-end)
       └── .github/PULL_REQUEST_TEMPLATE/new-pack.md with security checklist

PR 5 — Calibration discovery
       ├── corpora/calibration/ stays top-level (cross-pack integration corpus)
       ├── packs/permit0/email/tests/shared/ created (per-pack goldens convention)
       └── permit0 calibrate test discovers from BOTH locations
```

**Sequencing rationale:** PR 2 lands the schema and discovery machinery on the
OLD pack layout so PR 3 can move files *under* the new schema rather than
creating a transient state. The shared `discover_packs()` helper ships once
in PR 2 (lockfile-driven from the start), avoiding a rewrite if PR 2 had
landed a filesystem-walk version first.

## Pack internal layout (after PR 3)

```
packs/<owner>/<pack>/
├── pack.yaml
├── README.md
├── CHANGELOG.md
├── pack.lock.yaml                   ← committed; Cargo.lock-style
│
├── normalizers/
│   ├── gmail/
│   │   ├── _channel.yaml            ← channel metadata + tool_pattern
│   │   ├── aliases.yaml             ← per-channel foreign-MCP aliasing
│   │   ├── send.yaml
│   │   ├── archive.yaml
│   │   └── ... (16 files incl. list_drafts)
│   ├── outlook/
│   │   ├── _channel.yaml
│   │   ├── aliases.yaml
│   │   └── ... (16 files incl. list_drafts)
│   └── yahoo/                       ← future
│
├── risk_rules/                      ← per action_type
│   ├── send.yaml
│   ├── archive.yaml
│   ├── list_drafts.yaml
│   └── ...
│
└── tests/
    ├── gmail/                       ← per-channel fixtures
    ├── outlook/
    ├── shared/                      ← per-pack cross-channel goldens
    └── security/                    ← known-attack patterns (verified+ tier)
```

Cross-pack calibration corpora remain top-level under `corpora/calibration/`.

## Pack manifest example (pack_format: 2)

```yaml
pack_format: 2

permit0_pack: "permit0/email"        # <owner>/<name>; matches directory
name: email
version: "0.3.0"
description: "Unified email actions across Gmail, Outlook, and more"
license: Apache-2.0

permit0_engine: ">=0.5.0,<0.6"
taxonomy: "1.x"

trust_tier: built-in                 # informational; engine derives from path
maintainers:
  - github: "@permit0-team"

# Forward-compat (Phase 2 fields, empty in Phase 1)
signature: ""
provenance: ""
content_hash: ""

action_types:
  - email.search
  - email.send
  - email.archive
  - email.list_drafts
  # ...

channels:
  gmail:
    mcp_server: clients/gmail-mcp
  outlook:
    mcp_server: clients/outlook-mcp
```

`permit0 pack validate` enumerates `normalizers/<channel>/*.yaml` automatically.
`pack.lock.yaml` records every loaded file + sha256 so CI catches stowaway YAMLs.

## What we are NOT changing

- The pack ABI (DSL schema for normalizers and risk rules).
- The engine pipeline.
- The Rust type names `Domain`, `Verb`, `NormAction`.
- The shared-risk-rules-across-channels architecture.
- The `permit0_pack:` field naming convention.
- The CLI surface (`permit0 pack new / validate / test`).

## NOT in scope (deferred with rationale)

| Item | Rationale |
|---|---|
| Trust tier `verified` and `experimental` | Need signing infrastructure first; tier is derived, so without signatures only `built-in` (path-based) and `community` (default) exist |
| Federated registry / `permit0 pack install` | Phase 2; trigger is ≥10 community packs OR external publishing demand |
| Distribution pipeline (publish/sign/install) | No artifact distribution yet; packs live in-tree |
| MCP server bundling with packs | Reference in `_channel.yaml`, don't bundle (separation of concerns: pack = policy, MCP = adapter) |
| Action-type-string migration tooling | Refactor preserves all action_types byte-identical |
| Versioned taxonomy bump | `taxonomy: "1.x"` reserved; bump deferred to first taxonomy change |
| Domain pack beyond `permit0/email` | Vendors are channels under domain packs (`gmail`+`outlook` under `permit0/email`); next domain pack is its own engineering effort |

## Failure modes

| Codepath | Failure | Test? | Error handling? | User signal? |
|---|---|---|---|---|
| `discover_packs()` 2-level walk | Symlink loop | unit test (PR 2) | depth cap | clear error |
| `pack.lock.yaml` verify | Hash mismatch | unit test (PR 2) | reject load | "Pack X tampered" |
| Lockfile-driven load | Lockfile lists missing file | unit test (PR 2) | reject load | "Lockfile drift; run pack lock" |
| Channel pattern check | Cross-channel poisoning (`gmail/` contains `match.tool: outlook_send`) | unit test (PR 2) | validator reject | clear test |
| Per-channel alias merge | Two channels alias same foreign tool name | unit test (PR 3) | reject at registry build | "Conflict: both gmail and outlook claim 'create_message'" |
| `permit0_engine` semver | Engine 0.6.0 vs pack pinned `<0.6` | unit test (PR 2) | refuse load | "Pack X requires engine 0.5.x, you have 0.6.0" |
| Security lint | `email.set_forwarding` with `allow: true` | unit test (PR 2) | validator reject | "Cannot auto-allow critical action" |

## Critical regression tests (mandatory)

1. **PR 1**: SDK callsite update — `permit0-py` and `permit0-node` parse expected
   error variants after `CatalogError → TaxonomyError`.
2. **PR 2**: `pack_format` version gate — format=1 rejected, format=99
   forward-compat error, malformed semver range rejected.
3. **PR 2**: Engine snapshot test scaffolding — load packs from new path with
   schema v2, assert engine builds with identical normalizer set.
4. **PR 3**: Engine snapshot test (byte-identical NormAction) — same RawToolCalls
   produce byte-identical NormActions before/after the file restructure.
5. **PR 5**: `permit0 calibrate test` discovers fixtures from new locations and
   produces same pass/fail as before.

## Worktree parallelization

| Step | Modules touched | Depends on |
|---|---|---|
| PR 1 | `crates/permit0-types/`, `crates/permit0-py/`, `crates/permit0-node/`, `docs/` | — |
| PR 2 | `crates/permit0-cli/`, `crates/permit0-engine/`, `crates/permit0-dsl/`, `crates/permit0-normalize/` | PR 1 |
| PR 3 | `packs/`, `crates/permit0-engine/` (snapshot test) | PR 2 |
| PR 4 | `packs/community/`, `packs/_template/`, `docs/`, `.github/` | PR 2 |
| PR 5 | `crates/permit0-cli/src/cmd/calibrate.rs`, `corpora/`, `packs/.../tests/shared/` | PR 3 |

```
Lane A (sequential):  PR 1 → PR 2 → PR 3
Lane B (after PR 2):  PR 4    (docs/scaffolding only, no code conflict)
Lane C (after PR 3):  PR 5

Order: Land PR 1. Land PR 2. Launch PR 3 + PR 4 in parallel worktrees.
Land PR 3, land PR 4. Land PR 5.
```

**Conflict flag:** PR 4 touches `docs/pack-contribution-guide.md`; PR 2 may also
touch it for schema docs. Coordinate by having PR 2 only update the validator
rules section; PR 4 owns the full rewrite.

## Decisions captured (16 total)

| # | Decision | Outcome |
|---|---|---|
| A1 | aliases.yaml location | Per-channel: `normalizers/<channel>/aliases.yaml` |
| A2 | Pack discovery API | Shared `discover_packs()` helper in `permit0-engine` |
| A3 | vendor field | Drop; owner derived from `permit0_pack:` prefix |
| A4 | CatalogError rename | `TaxonomyError` + minor bump + same-PR SDK update |
| A5 | Manifest discipline | Auto-discover + committed `pack.lock.yaml` |
| A6 | list_drafts asymmetry | Fix in PR 3 (add `outlook_list_drafts.yaml` + `risk_rules/list_drafts.yaml`) |
| C1 | include_str! paths | Replace with `load_test_fixture()` helper |
| C2 | Calibration fixtures | Top-level `corpora/calibration/` (cross-pack) + per-pack `tests/shared/` |
| C3 | Schema versioning | `pack_format: 2` field; engine refuses format=1 |
| T1 | Snapshot test strictness | Byte-identical NormAction (excluding deliberate timestamp/uuid fields) |
| P1 | Discovery cost | Lockfile-driven engine load; filesystem fallback in dev |
| X1 | PR ordering | Hybrid: 1 → (2 = old PR 2 + PR 4 combined) → 3 → 5 (formerly PR 5) → 6 (formerly PR 6) |
| X2 | Tier source | Derived from path + signature, not declared |
| X3 | Tier name | `TrustTier` / `trust_tier:` field (avoids collision with `permit0_types::Tier`) |
| X4 | catalog→taxonomy rename | Keep DECIDED |
| X5 | Phase 2 reserved fields | `signature`, `provenance`, `content_hash` reserved in `pack_format: 2` |

## Phase 2 trigger conditions

Move to a federated registry when ANY of:

- ≥10 community packs in-tree.
- A community contributor wants to ship outside our release cadence.
- Someone wants to ship a private/internal pack their employer can't open-source.

Phase 2 plan sketch lives in the working discussion doc;
signing-infrastructure design is tracked in
[#18](https://github.com/permit0-ai/permit0-core/issues/18) as a
prerequisite.

## Related artifacts

- [#18](https://github.com/permit0-ai/permit0-core/issues/18) — pack
  signing infrastructure (Phase 2 prerequisite).
- [#19](https://github.com/permit0-ai/permit0-core/issues/19) — taxonomy
  version-resolver semantics for multi-pack installs.
- `~/.gstack/projects/permit0-ai-permit0-core/sufu-claudequirky-ritchie-4ae70b-eng-review-test-plan-20260501-150322.md`
  — test plan artifact consumable by `/qa` and `/qa-only`.
