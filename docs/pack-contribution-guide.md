# Pack Contribution Guide

This guide walks you through contributing a new pack to permit0. The
end product is a directory under `packs/permit0/<name>/` (first-party)
or `packs/<your-org>/<name>/` (community, Phase 2) that the engine
loads to govern a domain of tool calls.

## What is a pack?

A pack teaches the engine how to govern one domain. Each pack ships:

- **Normalizers** — YAML rules that map raw tool calls (e.g.
  `gmail_send`, `outlook_send`) onto a canonical `NormAction` with the
  same `action_type` (e.g. `email.send`). Grouped by channel
  (`normalizers/<channel>/<verb>.yaml`) so adding a vendor is one
  directory drop.
- **Risk rules** — YAML rules that score actions by `action_type`,
  channel-agnostic. One file per verb under `risk_rules/`.
- **Aliases** — Per-channel YAML tables that remap foreign MCP tool
  names onto canonical permit0 normalizer names.
- **Tests** — Fixture YAMLs under `tests/` (per-channel + shared +
  security) the validator and `permit0 pack test` exercise.
- **Manifest** — `pack.yaml` (schema v2) with metadata, channel
  declarations, action type list, version, and trust tier.

The full layout reference lives at
[`packs/README.md`](../packs/README.md). The reference implementation
is `packs/permit0/email/` — 32 normalizers + 16 risk rules covering
Gmail + Outlook. Read it before writing your own.

## Workflow

### 1. Open an issue

Before writing code, file an issue describing the pack:

- Domain + service (e.g. "Slack — message domain")
- Why permit0 needs this (concrete threat scenarios, not "it'd be nice")
- Action types the pack will cover (must be valid `domain.verb` pairs
  from `docs/taxonomy.md`)
- Maintainer commitment (who keeps this alive)

A core maintainer will triage. Possible outcomes: APPROVE, REQUEST_CHANGES,
or DECLINE. If your action types aren't in the taxonomy yet, the
maintainer will direct you to a taxonomy-update PR first.

### 2. Scaffold

```sh
# Copy the template into the right location.
# First-party packs (built-in tier):
cp -r packs/_template packs/permit0/<name>

# Community packs (Phase 2 placement; Phase 1 only first-party):
# cp -r packs/_template packs/<your-org>/<name>

cd packs/permit0/<name>
```

Replace every `TODO` marker in `pack.yaml`, the channel metadata,
the example normalizer/risk-rule YAMLs, and the README. The
validator rejects packs with unfilled TODOs.

### 3. Iterate

```sh
# Validate after every change. Fast; runs in milliseconds.
permit0 pack validate packs/permit0/<name>

# Smoke test with a sample call once at least one normalizer +
# risk rule pair is wired up.
permit0 check --input '{"tool_name":"<your_tool>","parameters":{...}}'

# Run the full fixture suite.
permit0 pack test packs/permit0/<name>
```

The validator checks 9 invariants (schema version, manifest hygiene,
trust-tier consistency, taxonomy compliance, action-type coverage,
normalizer/risk-rule orphans, security lint on critical actions). Run
it after every meaningful change.

### 4. Add fixtures

Place test cases under `tests/`:

- `tests/<channel>/` — per-channel goldens (one YAML per scenario)
- `tests/shared/` — cross-channel scenarios that should produce the
  same canonical action regardless of vendor
- `tests/security/` — known-attack patterns (required for verified+
  tier; optional for community)

Aim for ≥3 fixtures per `action_type`: one happy path (allow), one
denial path (deny), one edge case.

### 5. Open a PR

```sh
git checkout -b pack/<name>
git add packs/permit0/<name>
git commit -m "feat: add <name> pack"
git push origin pack/<name>
gh pr create --base main --template new-pack.md
```

The PR template captures the security checklist, threat model, and
calibration data. Fill it in honestly — gaps are flagged at review.

## What the validator checks

`permit0 pack validate` runs 9 manifest-level checks plus per-file
schema validation:

| Check | What it catches |
|---|---|
| Schema version | `pack_format` missing or != 2 |
| Legacy vendor field | `vendor:` from schema v1 still present |
| Malformed `permit0_pack` | missing `<owner>/<name>` slash |
| Trust tier mismatch | declared tier != derived from owner; or Phase 2 tier declared in Phase 1 |
| Unknown action type | entry not in the taxonomy |
| Missing normalizer / risk rule | listed action type has no implementation |
| Orphan normalizer / risk rule | implementation has no manifest entry |
| Missing gate on critical action | `email.set_forwarding`, `iam.*`, `secret.*`, `payment.*` lacks any `gate:` mutation |

Every check is a hard error except coverage / orphan codes, which
surface as warnings during the migration window.

## Common pitfalls

- **Priority collisions.** Each normalizer's `priority:` must be
  unique within the registry. The engine errors at build time if two
  share a value. Convention: 100 + N.
- **Cross-channel poisoning.** A normalizer in `normalizers/gmail/`
  with `match.tool: outlook_send` wrongly claims Outlook traffic. A
  follow-up PR will wire a CI check that enforces `_channel.yaml`'s
  `tool_pattern`. Until then, it's a manual review item.
- **Critical actions without gates.** `email.set_forwarding`,
  `email.add_delegate`, `iam.*`, `secret.*`, and `payment.*` MUST
  include at least one `gate:` mutation in the rule's `rules:` or
  `session_rules:`. The validator's security lint flags violations.
- **`include_str!` paths.** Test fixtures load via
  `permit0_test_utils::load_test_fixture("packs/<owner>/<name>/...")`
  resolved at runtime — paths are workspace-relative. Don't use
  `include_str!` with `../../../packs/...`; it breaks silently when
  layouts move.
- **Forgetting to update `action_types:`.** Adding a normalizer and
  risk rule isn't enough — list the action_type in `pack.yaml` too.
  The validator's coverage check catches this.

## Versioning

Pack versions follow SemVer:

- **Major bump** when:
  - Removing an action_type the pack used to cover
  - Loosening a deny rule (allowing what was previously denied)
  - Renaming an entity field that risk rules reference
- **Minor bump** when:
  - Adding action_type coverage
  - Tightening rules (more denies)
  - Adding new entities
- **Patch bump** when:
  - Fixing a bug in a rule
  - Improving entity extraction without changing decisions
  - Fixture additions

## Trust tiers

The engine derives the authoritative tier from `permit0_pack`'s
owner prefix. Your declaration in `pack.yaml` is informational.

| Tier | Reachable | How |
|---|---|---|
| `built-in` | Phase 1 | place under `packs/permit0/` |
| `community` | Phase 1 | default for non-permit0 owners |
| `verified` | Phase 2 | community + signing co-sign |
| `experimental` | Phase 2 | hidden, opt-in install |

## Related docs

- [`packs/README.md`](../packs/README.md) — layout overview + cardinality
- [`docs/taxonomy.md`](taxonomy.md) — closed list of valid `domain.verb`
- [`docs/dsl.md`](dsl.md) — DSL reference for normalizers + risk rules
- [`packs/_template/`](../packs/_template/) — drop-in scaffold
- [`packs/permit0/email/`](../packs/permit0/email/) — reference pack
