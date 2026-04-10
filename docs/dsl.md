# permit0 YAML DSL Specification

**Version:** `permit0_pack: v1`

This document is the authoritative reference for the permit0 YAML DSL — the language-agnostic surface for defining normalizers, risk rules, domain profiles, org policies, and fixtures.

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Common Conventions](#2-common-conventions)
3. [Pack Manifest](#3-pack-manifest)
4. [Normalizer DSL](#4-normalizer-dsl)
5. [Risk Rule DSL](#5-risk-rule-dsl)
6. [Domain Profile Schema](#6-domain-profile-schema)
7. [Org Policy Schema](#7-org-policy-schema)
8. [Fixture Format](#8-fixture-format)
9. [Closed Helper Registry](#9-closed-helper-registry)
10. [Static Validation](#10-static-validation)
11. [Versioning & Compatibility](#11-versioning--compatibility)

---

## 1. Design Principles

- **Declarative, not imperative.** YAML files describe *what* should happen, not *how*. The Rust interpreter decides execution strategy.
- **Closed world.** Only primitives listed in this spec are valid. No arbitrary code execution, no `eval`, no plugin loading. The set of helpers is fixed at compile time.
- **Deterministic.** Given the same input and the same DSL file, the output is always identical. No randomness, no network calls, no timestamps in evaluation.
- **Contributor-first.** A developer who has never seen Rust should be able to write a pack by copying an existing one, modifying it, and running `permit0 pack test` — in under 30 minutes.

---

## 2. Common Conventions

### File Naming

| File type | Pattern | Example |
|---|---|---|
| Normalizer | `<action>.norm.yaml` | `charges.create.norm.yaml` |
| Normalizer (versioned) | `<action>.<api-version>.norm.yaml` | `charges.create.v2024-11-20.norm.yaml` |
| Risk rule | `<action_type>.risk.yaml` | `payments.charge.risk.yaml` |
| Fixture | `<action>.fixtures.yaml` | `charges.create.fixtures.yaml` |
| Pack manifest | `pack.yaml` | `pack.yaml` |
| Domain profile | `<id>.profile.yaml` | `fintech.profile.yaml` |
| Org policy | `org-policy.yaml` | `org-policy.yaml` |

### Field Access Paths

Throughout the DSL, dotted paths reference fields in the input data:

| Prefix | Resolves to | Example |
|---|---|---|
| `arg.<path>` | Field in `raw_tool_call.arguments` | `arg.body.amount` |
| `arg.headers.<name>` | HTTP header value | `arg.headers.Stripe-Version` |
| `entity.<field>` | Field in the normalized `entities` map | `entity.recipient_scope` |
| `ctx.<field>` | Value from `NormalizeCtx` (org-provided) | `ctx.org_domain` |
| `session.<method>` | Session query (risk rules only) | `session.rate_per_minute` |

Paths are case-sensitive. Missing intermediate fields resolve to `null` (not an error).

### Value Types

| Type | YAML representation | Notes |
|---|---|---|
| `string` | `"hello"` or `hello` | Unquoted strings are valid YAML |
| `int` | `5000` | Always integer, never float |
| `float` | `0.85` | Used only in profiles/policies |
| `bool` | `true` / `false` | |
| `list` | `[a, b, c]` | Homogeneous |
| `null` | `null` or omitted | Missing field = null |

---

## 3. Pack Manifest

Every pack has a `pack.yaml` at its root.

```yaml
# Required
name: permit0-pack-stripe          # unique identifier, kebab-case
version: 0.3.1                     # semver
permit0_pack: v1                   # DSL version
vendor: stripe                     # vendor identifier
description: Stripe payments integration

# File lists (order does not matter — priority is per-file)
normalizers:
  - normalizers/charges.create.norm.yaml
  - normalizers/charges.create.v2024-11-20.norm.yaml
  - normalizers/refunds.create.norm.yaml

risk_rules:
  - risk-rules/payments.charge.risk.yaml
  - risk-rules/payments.refund.risk.yaml

# Optional metadata
homepage: https://github.com/permit0/pack-stripe
license: Apache-2.0
min_engine_version: 0.5.0          # minimum permit0 engine version
```

### Required Fields

| Field | Type | Description |
|---|---|---|
| `name` | string | Unique pack name. Convention: `permit0-pack-<vendor>` |
| `version` | string | Semver version of the pack |
| `permit0_pack` | string | DSL version. Must be `v1` |
| `vendor` | string | Vendor/integration identifier |
| `normalizers` | list\<string\> | Paths to normalizer YAML files (relative to pack root) |
| `risk_rules` | list\<string\> | Paths to risk rule YAML files (relative to pack root) |

### Optional Fields

| Field | Type | Description |
|---|---|---|
| `description` | string | Human-readable description |
| `homepage` | string | URL to pack documentation |
| `license` | string | SPDX license identifier |
| `min_engine_version` | string | Minimum compatible engine version |

---

## 4. Normalizer DSL

A normalizer matches a raw tool call and transforms it into a `NormAction`.

### Full Schema

```yaml
permit0_pack: v1                   # required — DSL version
id: stripe.charges.create          # required — unique normalizer ID
priority: 100                      # required — higher = checked earlier

# Optional — version-aware normalizer
extends: ./charges.create.norm.yaml
api_version:
  vendor: stripe
  range: ">=2024-11-20"
  detected_from: arg.headers.Stripe-Version

# Required — what to match
match:
  <match-expression>

# Required — what to produce
normalize:
  action_type: payments.charge     # required — domain.verb format
  domain: payments                 # required
  verb: charge                     # required
  channel: stripe                  # required — vendor/surface
  entities:
    <entity-definitions>
```

### Match Expressions

Match expressions are boolean conditions evaluated against the raw tool call. They compose with `all`, `any`, and `not`.

#### Combinators

```yaml
# All conditions must be true (logical AND)
match:
  all:
    - <condition>
    - <condition>

# At least one condition must be true (logical OR)
match:
  any:
    - <condition>
    - <condition>

# Condition must be false (logical NOT)
match:
  not:
    <condition>
```

Combinators nest arbitrarily:

```yaml
match:
  all:
    - tool: http
    - any:
        - arg.method: POST
        - arg.method: PUT
    - not:
        arg.url:
          contains: /internal/
```

#### Condition Primitives

| Primitive | Syntax | Matches when |
|---|---|---|
| Exact match | `field: value` | `field == value` (string, int, bool) |
| String contains | `field: { contains: substr }` | `field` contains `substr` |
| String starts with | `field: { starts_with: prefix }` | `field` starts with `prefix` |
| String ends with | `field: { ends_with: suffix }` | `field` ends with `suffix` |
| Regex | `field: { regex: pattern }` | `field` matches regex (RE2 / linear-time) |
| In list | `field: { in: [a, b, c] }` | `field` is one of the listed values |
| Not in list | `field: { not_in: [a, b, c] }` | `field` is not in the listed values |
| Exists | `field: { exists: true }` | `field` is present and non-null |
| Not exists | `field: { exists: false }` | `field` is null or absent |
| Greater than | `field: { gt: N }` | `field > N` (numeric) |
| Greater or equal | `field: { gte: N }` | `field >= N` (numeric) |
| Less than | `field: { lt: N }` | `field < N` (numeric) |
| Less or equal | `field: { lte: N }` | `field <= N` (numeric) |
| URL match | `field: { matches_url: { host, path } }` | Parsed URL matches host and path |
| Not empty | `field: { not_empty: true }` | `field` is a non-empty list/string |
| Any element matches | `field: { any_match: { field, value } }` | Any element in list has `field` matching `value` |

#### `matches_url` Details

```yaml
arg.url:
  matches_url:
    host: api.stripe.com           # exact host match
    path: /v1/charges              # exact path match (no trailing slash)
```

- `host` is matched exactly (no wildcards). Use `regex` for subdomain patterns.
- `path` is matched as a prefix by default. Add `path_exact: true` for exact match.
- Query parameters are ignored.

```yaml
# Prefix match (default) — matches /v1/charges, /v1/charges/ch_123, etc.
arg.url:
  matches_url:
    host: api.stripe.com
    path: /v1/charges

# Exact match — only /v1/charges
arg.url:
  matches_url:
    host: api.stripe.com
    path: /v1/charges
    path_exact: true
```

#### `tool` Shorthand

The `tool` field is a shorthand for matching `raw_tool_call.tool`:

```yaml
# These are equivalent:
match:
  tool: http

match:
  all:
    - tool: http
```

When `tool` appears alongside other conditions at the top level, it is implicitly wrapped in `all`:

```yaml
# Implicit all:
match:
  tool: http
  arg.method: POST

# Equivalent to:
match:
  all:
    - tool: http
    - arg.method: POST
```

### Normalize Section

The `normalize` section defines the output `NormAction`.

#### Static Entity Fields

```yaml
normalize:
  entities:
    amount:
      from: arg.body.amount        # extract from input path
      type: int                    # cast to type
      required: true               # fail normalization if missing
    currency:
      from: arg.body.currency
      type: string
      default: usd                 # use if missing
      lowercase: true              # normalize to lowercase
    customer:
      from: arg.body.customer
      type: string
      optional: true               # null if missing (no error)
```

#### Entity Field Properties

| Property | Type | Default | Description |
|---|---|---|---|
| `from` | string | — | Input path to extract from. Required unless `compute` is used |
| `type` | string | `string` | Target type: `string`, `int`, `bool`, `float`, `list` |
| `required` | bool | `false` | If true, normalization fails when field is missing |
| `optional` | bool | `false` | If true, field is null when missing (no error). Mutually exclusive with `required` |
| `default` | any | — | Value to use when field is missing. Incompatible with `required` |
| `lowercase` | bool | `false` | Normalize string to lowercase |
| `uppercase` | bool | `false` | Normalize string to uppercase |
| `trim` | bool | `true` | Strip leading/trailing whitespace |
| `compute` | string | — | Name of a closed helper function (see §9) |
| `args` | list | — | Arguments to the compute helper |

#### Computed Entities

Some entity values cannot be extracted from a single field — they require logic. The `compute` field invokes a **closed helper** from the fixed registry:

```yaml
entities:
  destination_scope:
    compute: classify_destination
    args: [arg.body.destination.account, ctx.org_stripe_account_id]
  recipient_scope:
    compute: recipient_scope
    args: [arg.body.to, ctx.org_domain]
  pipe_count:
    compute: count_pipes
    args: [arg.command]
```

Helper arguments are field access paths or literal values. See §9 for the full helper registry.

### API Version Handling

Version-aware normalizers extend a base normalizer and override specific fields:

```yaml
permit0_pack: v1
id: stripe.charges.create@2024-11-20
extends: ./charges.create.norm.yaml    # path relative to pack root

api_version:
  vendor: stripe
  range: ">=2024-11-20"                # semver range or date range
  detected_from: arg.headers.Stripe-Version  # where to read the version
  sunset: "2026-06-01"                 # optional — warn after this date

# Only override fields that changed
normalize:
  entities:
    payment_source:
      from: arg.body.payment_method    # was arg.body.source in base
```

**Rules:**

- `extends` is a relative path to the base normalizer file.
- The extended normalizer inherits all `match`, `normalize`, and metadata from the base.
- Only fields present in the override replace the base. Omitted fields are inherited.
- `api_version.range` supports: `>=DATE`, `<=DATE`, `>=DATE,<DATE`, exact `DATE`.
- When multiple version-aware normalizers match, the one with the most specific (narrowest) range wins.
- Both versions produce the **same `action_type`** and entity shape. Vendor field moves are hidden from the scorer.
- Past `sunset`, the normalizer logs a deprecation warning but still works. Removal only in major engine releases.

---

## 5. Risk Rule DSL

Risk rules define how each `action_type` is scored. They declare the base risk template and entity-driven mutation rules.

### Full Schema

```yaml
permit0_pack: v1                   # required
action_type: email.send            # required — must match an action_type from a normalizer

base:
  flags:                           # required — at least one flag
    <FLAG_NAME>: primary | secondary
  amplifiers:                      # required — all 10 dimensions
    irreversibility: <0-30>
    boundary:        <0-30>
    destination:     <0-30>
    sensitivity:     <0-30>
    environment:     <0-30>
    session:         <0-30>
    actor:           <0-30>
    scope:           <0-30>
    volume:          <0-30>
    amount:          <0-30>

rules:                             # required — ordered list
  - when: <condition>
    then: [<mutation>, ...]

session_rules:                     # optional
  - when: <session-condition>
    then: [<mutation>, ...]
```

### Risk Flags

The fixed set of risk flags:

| Flag | Meaning |
|---|---|
| `OUTBOUND` | Data or commands cross a trust boundary outward |
| `EXPOSURE` | Sensitive data may be revealed |
| `MUTATION` | State is changed (write, delete, update) |
| `DESTRUCTION` | Irreversible data loss (delete, overwrite) |
| `FINANCIAL` | Money or financial instruments involved |
| `PRIVILEGE` | Elevated permissions or role changes |
| `EXECUTION` | Arbitrary code or command execution |
| `PHYSICAL` | Physical-world effects (IoT, robotics, medical devices) |
| `GOVERNANCE` | Regulatory or compliance implications |

Each flag has a role: `primary` (structurally always true for this action type) or `secondary` (conditionally added by rules).

### Amplifier Dimensions

All 10 dimensions must be present in `base.amplifiers`. Values are integers 0–30.

| Dimension | What it measures |
|---|---|
| `irreversibility` | How hard it is to undo |
| `boundary` | Trust boundaries crossed |
| `destination` | Risk of the target/recipient |
| `sensitivity` | Sensitivity of data involved |
| `environment` | Production vs. dev/staging |
| `session` | Session history risk (auto-derived if session present) |
| `actor` | Actor privilege level |
| `scope` | Blast radius |
| `volume` | Rate / quantity |
| `amount` | Financial magnitude |

### Rule Conditions (`when`)

Rule conditions in the `rules` section operate on entity values. They use the same condition primitives as match expressions (§4), with `entity.` and `ctx.` prefixes.

```yaml
# Simple equality
- when:
    entity.recipient_scope: external

# Numeric comparison
- when:
    entity.amount: { gt: 10000 }

# String content check
- when:
    entity.body:
      contains_any: [password, secret, "api key"]

# Boolean check
- when:
    entity.is_forward: true

# Existence check
- when:
    entity.attachments:
      not_empty: true

# List element check
- when:
    entity.attachments:
      any_match:
        field: classification
        value: [confidential, secret]

# Combined conditions
- when:
    all:
      - entity.verb: transfer
      - entity.destination_is_external: true

# Context comparison
- when:
    entity.original_sender_domain:
      equals_ctx: org_domain
```

#### Additional Condition Primitives (Risk Rules Only)

| Primitive | Syntax | Matches when |
|---|---|---|
| `contains_any` | `field: { contains_any: [a, b] }` | `field` contains any substring in list |
| `equals_ctx` | `field: { equals_ctx: ctx_field }` | `field == ctx.<ctx_field>` |
| `not_in_set` | `field: { not_in_set: set_name }` | `field` is not in the named org-provided set |
| `in_set` | `field: { in_set: set_name }` | `field` is in the named org-provided set |

Sets (`approved_payees`, `internal_domains`, etc.) are provided by the org policy at engine startup.

### Mutation Actions (`then`)

Each rule's `then` is an ordered list of mutations applied to the `RiskTemplate`.

| Action | Syntax | Effect |
|---|---|---|
| `add_flag` | `add_flag: { flag: FLAG, role: primary\|secondary }` | Add a flag if not already present |
| `remove_flag` | `remove_flag: FLAG` | Remove a flag. Cannot remove immutable flags |
| `promote_flag` | `promote_flag: FLAG` | Promote from secondary to primary |
| `upgrade` | `upgrade: { dim: DIM, delta: N }` | `amplifier[dim] += N` (capped at 30) |
| `downgrade` | `downgrade: { dim: DIM, delta: N }` | `amplifier[dim] -= N` (floored at 0) |
| `override` | `override: { dim: DIM, value: N }` | `amplifier[dim] = N` (clamped 0–30) |
| `gate` | `gate: "reason string"` | Hard block — forces CRITICAL tier immediately. Evaluation halts |
| `split` | `split: { flags: {...}, amplifiers: {...} }` | Create an independent child risk assessment. Final score = `max(parent, child)` |

#### `gate` — Hard Block

```yaml
- when:
    entity.amount: { gt: 100000 }
  then:
    - gate: "Large financial transaction exceeds autonomous limit"
```

A `gate` immediately stops rule evaluation and forces `tier = CRITICAL`. The reason string is included in the `RiskScore` and audit log. Place gates **before** the mutations they protect — rules after a fired gate are never evaluated.

#### `split` — Independent Sub-Assessment

```yaml
- when:
    all:
      - entity.is_forward: true
      - entity.recipient_scope: external
  then:
    - split:
        flags:
          EXPOSURE: primary
          OUTBOUND: primary
        amplifiers:
          destination: 40
          sensitivity: 25
          irreversibility: 20
```

A split creates a separate `RiskTemplate` scored independently. The final score is `max(parent_score, split_score)`. Splits are used when a single action contains an independent sub-risk (e.g., forwarding an internal email to an external recipient is a separate exposure event).

Split amplifiers are **absolute values**, not deltas. They define a complete sub-template. Missing amplifier dimensions default to 0.

### Session Rule Conditions (`session_rules`)

Session rules operate on the `SessionContext` — the history of prior actions in the current session. They enable risk decisions that depend on cumulative state, temporal patterns, and cross-action relationships.

```yaml
session_rules:
  - when:
      session.rate_per_minute:
        action_type: email.send      # count this action type
        gte: 20                      # threshold
    then:
      - gate: "Email send rate exceeds 20/min"
```

All session condition primitives support an optional `within_minutes` field to scope the query to a time window. When omitted, the entire session history is considered.

#### Basic Primitives

| Primitive | Syntax | Matches when |
|---|---|---|
| `session.rate_per_minute` | `{ action_type, gte, within_minutes? }` | Actions/minute of given type >= threshold |
| `session.preceded_by` | `{ action_types: [...], within: N }` | Any of the listed types appeared in the last N actions |
| `session.max_tier` | `{ gte: TIER }` | Highest tier in session >= threshold |
| `session.flag_sequence` | `{ last_n: N, contains: FLAG }` | FLAG appears in flags of last N actions |
| `session.count` | `{ action_type?, flag?, gte }` | Total count matching type or flag >= threshold |

#### Numeric Aggregation

These primitives aggregate numeric entity fields across matching session records.

| Primitive | Syntax | Matches when |
|---|---|---|
| `session.sum` | `{ entity_field, action_type?, action_types?, within_minutes?, gte/lte/gt/lt }` | Sum of field values meets threshold |
| `session.max` | `{ entity_field, action_type?, within_minutes?, gte/lte/gt/lt }` | Maximum field value meets threshold |
| `session.min` | `{ entity_field, action_type?, within_minutes?, gte/lte/gt/lt }` | Minimum field value meets threshold |
| `session.avg` | `{ entity_field, action_type?, within_minutes?, gte/lte/gt/lt }` | Average field value meets threshold |

```yaml
# Cumulative transfer amount exceeds $500k
- when:
    session.sum:
      entity_field: amount
      action_type: payments.transfer
      gte: 50000000
  then:
    - gate: "Cumulative transfers exceed $500k in session"

# Largest single charge exceeds $50k
- when:
    session.max:
      entity_field: amount
      action_type: payments.charge
      gte: 5000000
  then:
    - upgrade: { dim: amount, delta: 12 }

# Detects micro-transaction card testing (charges under $2)
- when:
    session.min:
      entity_field: amount
      action_type: payments.charge
      within_minutes: 60
      lte: 200
  then:
    - upgrade: { dim: scope, delta: 10 }

# Sum across multiple action types
- when:
    session.sum:
      entity_field: amount
      action_types: [payments.charge, payments.transfer, payments.refund]
      within_minutes: 1440
      gte: 200000000
  then:
    - gate: "24h cumulative financial operations exceed $2M"
```

#### Advanced Counting

| Primitive | Syntax | Matches when |
|---|---|---|
| `session.count_where` | `{ action_type?, entity_match: {...}, within_minutes?, gte }` | Count of records matching entity conditions >= threshold |
| `session.distinct_count` | `{ entity_field, action_type?, within_minutes?, gte }` | Count of unique field values >= threshold |

```yaml
# 5+ external emails sent
- when:
    session.count_where:
      action_type: email.send
      entity_match:
        recipient_scope: external
      gte: 5
  then:
    - upgrade: { dim: destination, delta: 12 }
    - add_flag: { flag: GOVERNANCE, role: secondary }

# Transfers to 5+ distinct recipients within an hour
- when:
    session.distinct_count:
      entity_field: recipient
      action_type: payments.transfer
      within_minutes: 60
      gte: 5
  then:
    - upgrade: { dim: destination, delta: 18 }
```

`entity_match` uses the same condition syntax as regular rule `when` clauses, but scoped to entity fields (without the `entity.` prefix):

```yaml
entity_match:
  recipient_scope: external          # exact match
  amount: { lt: 200 }               # numeric comparison
```

#### Temporal Patterns

| Primitive | Syntax | Matches when |
|---|---|---|
| `session.duration_minutes` | `{ gte }` | Session has been active >= N minutes |
| `session.idle_then_burst` | `{ idle_minutes, burst_count, burst_window_minutes }` | No activity for N minutes, then M actions in K minutes |
| `session.accelerating` | `{ action_type, window_count, rate_increase_factor }` | Action frequency increasing by factor over sliding windows |

```yaml
# Long-running session — risk drifts upward
- when:
    session.duration_minutes:
      gte: 120
  then:
    - upgrade: { dim: session, delta: 8 }

# Agent was idle 30 min then suddenly fires 10 actions in 5 min
- when:
    session.idle_then_burst:
      idle_minutes: 30
      burst_count: 10
      burst_window_minutes: 5
  then:
    - upgrade: { dim: volume, delta: 15 }
    - upgrade: { dim: session, delta: 10 }

# Transfer frequency is doubling over 3 sliding windows
- when:
    session.accelerating:
      action_type: payments.transfer
      window_count: 3
      rate_increase_factor: 2.0
  then:
    - upgrade: { dim: volume, delta: 12 }
    - add_flag: { flag: GOVERNANCE, role: secondary }
```

#### Set & Sequence Operations

| Primitive | Syntax | Matches when |
|---|---|---|
| `session.sequence` | `{ pattern: [...], within: N, ordered: bool }` | Action types appear as subsequence in last N actions |
| `session.distinct_flags` | `{ within_minutes?, gte }` | Number of distinct risk flags observed >= threshold |
| `session.ratio` | `{ numerator: {...}, denominator: {...}, gte/lte }` | Ratio of counts between two filtered groups meets threshold |

```yaml
# Classic attack chain: escalate → steal secret → exfiltrate
- when:
    session.sequence:
      pattern: [iam.assign_role, secrets.read, payments.transfer]
      within: 10
      ordered: true
  then:
    - gate: "Privilege escalation → secret read → transfer sequence detected"

# Session has triggered 4+ distinct flag types — broad suspicious activity
- when:
    session.distinct_flags:
      within_minutes: 30
      gte: 4
  then:
    - upgrade: { dim: session, delta: 12 }

# Read-to-write ratio > 10:1 over 15+ actions — reconnaissance pattern
- when:
    all:
      - session.ratio:
          numerator:
            action_types: [files.read, db.select, secrets.read]
          denominator:
            action_types: [files.write, db.insert]
          gte: 10.0
      - session.count:
          gte: 15
  then:
    - upgrade: { dim: sensitivity, delta: 15 }
    - upgrade: { dim: boundary, delta: 10 }
```

#### Combining Session Conditions

Session conditions compose with `all` and `any`, just like regular rule conditions:

```yaml
# Card testing: 3+ small charges to 3+ distinct customers
- when:
    all:
      - session.count_where:
          action_type: payments.charge
          entity_match:
            amount: { lt: 200 }
          gte: 3
      - session.distinct_count:
          entity_field: customer
          action_type: payments.charge
          gte: 3
  then:
    - gate: "Multiple small charges to different customers — possible card testing"

# Privilege escalation followed by cumulative large transfer
- when:
    all:
      - session.preceded_by:
          action_types: [iam.assign_role, iam.generate_api_key]
          within: 5
      - session.sum:
          entity_field: amount
          action_type: payments.transfer
          gte: 1000000
  then:
    - gate: "Large transfer after privilege escalation"
```

Session rules produce the same mutations as regular rules (`upgrade`, `downgrade`, `gate`, etc.).

### Evaluation Order

1. Construct `RiskTemplate` from `base`.
2. Evaluate `rules` top-to-bottom. Stop on first `gate`.
3. If `SessionContext` is present, evaluate `session_rules` top-to-bottom. Stop on first `gate`.
4. Pass completed `RiskTemplate` to `compute_hybrid()`.

**Order matters.** Authors control precedence by rule ordering. This is intentional and explicit.

---

## 6. Domain Profile Schema

Domain profiles are curated calibration presets for specific industries.

```yaml
permit0_profile: v1                # required
id: fintech                        # required — unique profile ID
name: Financial Services           # required
description: >                     # optional
  Conservative defaults for PCI-DSS and SOX regulated environments.
version: "2025.1"                  # required — profile version

# Adjust base flag weights (multiplier applied to compiled defaults)
risk_weight_adjustments:
  FINANCIAL: 1.5                   # range: [0.5, 2.0] (guardrail-enforced)
  EXPOSURE:  1.3
  OUTBOUND:  1.2
  MUTATION:  0.8

# Adjust amplifier dimension weights
amp_weight_adjustments:
  amount:      1.4                 # range: [0.5, 2.0]
  destination: 1.3
  sensitivity: 1.1
  actor:       0.7

# Shift tier thresholds
tier_threshold_shifts:
  MEDIUM: -0.05                    # range: [-0.10, +0.10]
  HIGH:   -0.05                    # negative = stricter (lower threshold)

# Add block rules (can only add, never remove base rules)
additional_block_rules:
  - name: large_external_transfer  # unique within profile
    condition:
      flags: [FINANCIAL, OUTBOUND] # all must be present
      amplifiers:
        amount: ">= 0.70"         # normalized value (0.0–1.0)
        destination: ">= 0.60"
    reason: "Large financial transfer to external destination"

# Set minimum tier floors per action type (can only raise, never lower)
action_type_floors:
  payments.charge:      LOW
  payments.transfer:    MEDIUM
  iam.assign_role:      HIGH
```

### What Profiles Can Do

- Adjust flag weights: multiply by 0.5× to 2.0×
- Adjust amplifier weights: multiply by 0.5× to 2.0×
- Shift tier thresholds: ±0.10
- Add block rules (additive only)
- Set action-type floor tiers (can only raise)

### What Profiles Cannot Do

- Remove or zero a flag
- Disable a base block rule
- Lower a floor below the base
- Change the scoring algorithm
- Modify immutable flags (`DESTRUCTION`, `PHYSICAL`, `EXECUTION`)
- Disable immutable block rules

### Block Rule Condition Schema

```yaml
condition:
  flags: [FLAG1, FLAG2]            # all listed flags must be active
  amplifiers:                      # all listed conditions must hold
    <dim>: ">= <threshold>"       # normalized (0.0–1.0)
  context:                         # optional — time/environment conditions
    day_of_week: [saturday, sunday]
    hour_range: [0, 6]             # UTC hours
    environment: production
```

---

## 7. Org Policy Schema

Org policies are per-customer overrides layered on top of a domain profile.

```yaml
permit0_org_policy: v1             # required
org_id: acme-treasury              # required — unique org identifier
base_profile: fintech              # required — which profile to extend

# Same adjustment fields as profiles (same guardrail bounds)
risk_weight_adjustments:
  FINANCIAL: 1.2

tier_threshold_shifts:
  HIGH: +0.03                      # positive = more lenient (higher threshold)

# Per-action-type amplifier customization
action_type_amplifier_overrides:
  payments.charge:
    amount:
      breakpoints:                 # piecewise linear mapping
        - below: 50000             # amount < $500 (cents)
          value: 5
        - below: 5000000           # amount < $50k
          value: 15
        - below: 50000000          # amount < $500k
          value: 25
        - above: 50000000          # amount >= $500k
          value: 30

  payments.transfer:
    destination:
      known_safe_values:           # org-specific safe list
        - "acct_correspondent_bank_a"
        - "acct_correspondent_bank_b"
      when_safe: 5                 # amplifier value when entity matches safe list
      when_unknown: 35             # amplifier value otherwise

# Pre-approved action patterns
allowlist:
  - norm_hash: "a3f91b2c7d4e8012"
    reason: "Daily reconciliation report to internal finance team"
    approved_by: "jane@acme.com"   # required
    approved_at: "2025-03-15"      # required
    expires: "2025-09-15"          # required — no permanent allowlist entries
    review_ticket: "SEC-1234"      # optional — link to approval ticket

# Additional block rules (additive)
additional_block_rules:
  - name: weekend_large_transfer
    condition:
      flags: [FINANCIAL, OUTBOUND]
      amplifiers:
        amount: ">= 0.50"
      context:
        day_of_week: [saturday, sunday]
    reason: "Large transfers blocked outside business hours"

# Named sets for use in risk rule conditions (not_in_set, in_set)
sets:
  approved_payees:
    - "acct_correspondent_bank_a"
    - "acct_correspondent_bank_b"
    - "acct_clearing_house"
  internal_domains:
    - "acme.com"
    - "acme-treasury.com"
```

### Amplifier Override Types

#### Breakpoints

Piecewise linear mapping from an entity value (typically `amount`) to an amplifier score:

```yaml
breakpoints:
  - below: 50000        # if entity.amount < 50000 → value 5
    value: 5
  - below: 5000000      # if entity.amount < 5000000 → value 15
    value: 15
  - above: 5000000      # if entity.amount >= 5000000 → value 25
    value: 25
```

Breakpoints are evaluated top-to-bottom. The first matching range wins. The last entry must use `above:` to catch all remaining values.

#### Known Safe Values

```yaml
known_safe_values:
  - "acct_bank_a"
  - "acct_bank_b"
when_safe: 5             # amplifier value when entity matches
when_unknown: 35         # amplifier value otherwise
```

The entity field is determined by the amplifier dimension name and action type context.

### Allowlist Requirements

Every allowlist entry **must** have:
- `norm_hash` — the hash of the normalized action pattern
- `reason` — why this is pre-approved
- `approved_by` — who approved it
- `approved_at` — when it was approved
- `expires` — expiry date (no permanent entries)

---

## 8. Fixture Format

Every pack must ship fixtures. CI runs `permit0 pack test packs/**` on every PR.

### Normalizer Fixtures

Test that a raw tool call produces the expected `NormAction`:

```yaml
# packs/stripe/fixtures/charges.create.fixtures.yaml
- name: basic usd charge           # required — descriptive test name
  input:
    tool: http                     # raw_tool_call.tool
    arguments:                     # raw_tool_call.arguments
      method: POST
      url: https://api.stripe.com/v1/charges
      body:
        amount: 5000
        currency: usd
        customer: cus_123
  ctx:                             # NormalizeCtx values
    org_stripe_account_id: acct_123
    org_domain: myorg.com
  expect:
    action_type: payments.charge   # expected NormAction fields
    entities:
      amount: 5000
      currency: usd
      destination_scope: internal

- name: wrong host does not match
  input:
    tool: http
    arguments:
      method: POST
      url: https://api.evil.com/v1/charges
      body: { amount: 100 }
  expect:
    matched: false                 # normalizer should NOT match this input
```

### Risk Rule Fixtures

Test that a `NormAction` produces the expected risk score:

```yaml
# packs/stripe/fixtures/payments.charge.risk-fixtures.yaml
- name: small internal charge
  input:
    action_type: payments.charge
    entities:
      amount: 500
      currency: usd
      recipient: acct_internal
      destination_is_external: false
      environment: production
  expect:
    tier: LOW                      # expected tier
    flags_include: [FINANCIAL, MUTATION]
    flags_exclude: [DESTRUCTION, PRIVILEGE]

- name: large charge triggers gate
  input:
    action_type: payments.charge
    entities:
      amount: 150000
      environment: production
  expect:
    tier: CRITICAL                 # gate fired
    blocked: true
    block_reason_contains: "Large financial transaction"

- name: external transfer high risk
  input:
    action_type: payments.charge
    entities:
      amount: 50000
      verb: transfer
      destination_is_external: true
      environment: production
  expect:
    tier_gte: MEDIUM               # at least MEDIUM
    flags_include: [FINANCIAL, GOVERNANCE]
```

### Session-Aware Fixtures

```yaml
- name: read then exfiltrate escalation
  input:
    action_type: email.send
    entities:
      recipient_scope: external
      body: "Hello"
  session:                         # prior session history
    - action_type: files.read
      tier: LOW
      flags: [EXPOSURE, MUTATION]
      entities:
        path: /etc/credentials.json
    - action_type: db.select
      tier: LOW
      flags: [EXPOSURE]
      entities: {}
  expect:
    tier_gte: MEDIUM
    # session rule: preceded_by [files.read, db.select] should fire
```

### Fixture Assertion Fields

| Field | Type | Description |
|---|---|---|
| `matched` | bool | Whether the normalizer should match (normalizer fixtures only) |
| `action_type` | string | Expected action type |
| `entities` | map | Expected entity values (subset match — extra entities OK) |
| `tier` | string | Exact tier: `MINIMAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `tier_gte` | string | Tier is at least this value |
| `tier_lte` | string | Tier is at most this value |
| `score_gte` | int | Score (0–100) is at least this |
| `score_lte` | int | Score (0–100) is at most this |
| `flags_include` | list | These flags must be active |
| `flags_exclude` | list | These flags must NOT be active |
| `blocked` | bool | Whether a gate/block rule fired |
| `block_reason_contains` | string | Substring of the block reason |

---

## 9. Closed Helper Registry

Helpers are Rust functions callable from YAML `compute` fields. The set is **fixed at compile time** — YAML cannot define new helpers.

### Available Helpers

| Helper | Arguments | Returns | Description |
|---|---|---|---|
| `classify_destination` | `(account_id, org_account_id)` | `"internal"` \| `"external"` \| `"unknown"` | Compares an account ID to the org's own account |
| `recipient_scope` | `(email_or_list, org_domain)` | `"self"` \| `"internal"` \| `"external"` \| `"mixed"` | Classifies email recipients by domain |
| `count_pipes` | `(command)` | int | Counts `\|` in a shell command string |
| `extract_domain` | `(email)` | string | Returns the domain part of an email address |
| `is_private_ip` | `(ip_or_url)` | bool | Checks if an IP/URL targets private network ranges |
| `parse_path_depth` | `(path)` | int | Counts path segments |
| `classify_file_type` | `(filename)` | `"code"` \| `"data"` \| `"config"` \| `"binary"` \| `"unknown"` | Classifies file by extension |
| `extract_amount_cents` | `(amount, currency)` | int | Normalizes amount to cents (handles string/float/int) |
| `detect_pii_patterns` | `(text)` | bool | Checks for common PII patterns (SSN, email, phone) |
| `url_host` | `(url)` | string | Extracts the host from a URL |
| `url_path` | `(url)` | string | Extracts the path from a URL |
| `string_length` | `(value)` | int | Returns the length of a string |
| `list_length` | `(value)` | int | Returns the length of a list |

### Adding New Helpers

New helpers are added only via Rust code in the `permit0-dsl` crate. The process:

1. Implement the function in `permit0-dsl/src/helpers/`.
2. Register it in the helper registry.
3. Add it to this table.
4. Release a new engine version.

Contributors who need a helper that doesn't exist should open an issue. The bar for adding helpers is low — they must be pure functions (no I/O, no state) and deterministic.

---

## 10. Static Validation

The engine validates all YAML at load time (not at evaluation time). Invalid packs are rejected before the engine starts.

### Normalizer Validation

| Check | Error |
|---|---|
| `permit0_pack` is `v1` | `unsupported DSL version` |
| `id` is unique across all loaded packs | `duplicate normalizer ID` |
| `priority` is an integer | `invalid priority` |
| Two normalizers with the same priority both match a fixture input | `priority conflict` |
| `match` uses only known condition primitives | `unknown match primitive` |
| `normalize.action_type` follows `domain.verb` format | `invalid action_type format` |
| `compute` references a known helper | `unknown helper` |
| `compute` argument count matches helper signature | `wrong argument count` |
| `extends` points to an existing file | `missing base normalizer` |
| `api_version.range` is parseable | `invalid version range` |
| Entity `type` is one of: `string`, `int`, `bool`, `float`, `list` | `unknown entity type` |
| `required` and `optional` are not both true | `conflicting field requirements` |
| `required` and `default` are not both set | `required field cannot have default` |

### Risk Rule Validation

| Check | Error |
|---|---|
| `action_type` follows `domain.verb` format | `invalid action_type format` |
| All 10 amplifier dimensions are present in `base` | `missing amplifier dimension` |
| Amplifier values are 0–30 | `amplifier out of range` |
| Flag names are from the fixed set | `unknown flag` |
| Flag roles are `primary` or `secondary` | `invalid flag role` |
| `when` conditions use known primitives | `unknown condition primitive` |
| `then` mutations use known actions | `unknown mutation action` |
| `upgrade`/`downgrade`/`override` reference known dimensions | `unknown amplifier dimension` |
| `split` amplifiers are non-negative | `negative split amplifier` |
| Session conditions use known session primitives | `unknown session primitive` |
| `gate` reason is a non-empty string | `empty gate reason` |

### Profile / Org Policy Validation

| Check | Error |
|---|---|
| Weight adjustments are within [0.5, 2.0] | `weight adjustment out of guardrail bounds` |
| Threshold shifts are within [-0.10, +0.10] | `threshold shift out of guardrail bounds` |
| Immutable flags are not zeroed or removed | `cannot modify immutable flag` |
| Block rules only add, never remove | `cannot remove base block rule` |
| Floor tiers only raise, never lower | `cannot lower tier floor` |
| Allowlist entries have `expires` field | `allowlist entry missing expiry` |
| `base_profile` (org policy) references a known profile | `unknown base profile` |
| Breakpoint lists are ordered and cover the full range | `incomplete breakpoint range` |
| Cumulative effects of profile + org policy pass guardrail check | `guardrail violation after composition` |

---

## 11. Versioning & Compatibility

### DSL Version (`permit0_pack`)

The `permit0_pack: v1` field in every YAML file declares the DSL version.

- **v1** is the current and only version.
- Future versions (v2, v3) will be introduced for breaking changes to the DSL grammar.
- The engine supports loading multiple DSL versions simultaneously — a v1 pack and a v2 pack can coexist.
- When a new version is introduced, v1 remains supported for at least 2 major engine releases.

### `norm_hash` Stability

The `norm_hash` is a SHA-256 of the canonical JSON representation of a `NormAction`. It is the key for caching, allowlists, and denylists.

**Stability contract:** Given the same `NormAction` struct, `norm_hash` is byte-identical across:
- Engine versions
- Operating systems
- Serialization libraries

This is enforced by:
1. Canonical JSON: keys sorted alphabetically, no whitespace, null fields omitted.
2. Golden test: a corpus of `(NormAction, expected_hash)` pairs checked in CI.
3. Any change to `NormAction` serialization is a breaking change requiring a major version bump.

### Pack Versioning

Packs follow semver. A pack version bump is required when:

| Change | Version bump |
|---|---|
| New normalizer added | Minor |
| New risk rule added | Minor |
| Entity field renamed | Major |
| `action_type` renamed | Major |
| Amplifier base values changed | Patch |
| New rule added to existing risk rule | Patch |
| Gate threshold changed | Patch |
| `norm_hash` output changes for existing fixtures | Major |
