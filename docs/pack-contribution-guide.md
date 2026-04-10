# Pack Contribution Guide

This guide walks you through contributing a new pack to permit0.

## What is a Pack?

A pack teaches permit0 how to normalize and score tool calls for a
specific service (e.g. Stripe, Gmail, Slack). Each pack contains:

- **Normalizers** — YAML rules that map raw tool calls to canonical
  `NormAction` structures with typed entities.
- **Risk rules** — YAML rules that assign risk flags and amplifiers
  based on entity values and patterns.
- **Fixtures** — Test cases that verify the pack behaves correctly.

## Quick Start

```sh
# 1. Scaffold a new pack
permit0 pack new my_service

# 2. Edit the generated files
cd packs/my_service
$EDITOR normalizers/my_service.normalizer.yaml
$EDITOR risk_rules/my_service.risk_rule.yaml

# 3. Validate your pack
permit0 pack validate packs/my_service

# 4. Run fixture tests
permit0 pack test packs/my_service

# 5. Submit a PR
git checkout -b pack/my_service
git add packs/my_service
git commit -m "feat: add my_service pack"
```

## Pack Directory Structure

```
packs/my_service/
├── README.md                          # Description, examples, known limitations
├── normalizers/
│   └── my_service.normalizer.yaml     # Normalizer definition
├── risk_rules/
│   └── my_service.risk_rule.yaml      # Risk rule definition
└── fixtures/
    ├── basic.fixture.yaml             # Basic test case
    └── high_risk.fixture.yaml         # Edge case test
```

## Writing a Normalizer

A normalizer tells permit0 how to recognize and decompose a tool call:

```yaml
id: stripe_charge
description: "Normalize Stripe charge creation"
priority: 100

match:
  tool: "http"
  url: { contains: "api.stripe.com/v1/charges" }

action_type: "payment.charge"
channel: "stripe"

entities:
  - name: amount
    path: "$.parameters.body.amount"
    required: true
    type: number

  - name: currency
    path: "$.parameters.body.currency"
    required: true
    default: "usd"

  - name: recipient
    path: "$.parameters.body.destination"
    required: false
```

### Key Fields

| Field | Description |
|-------|-------------|
| `id` | Unique identifier (must be unique across all packs) |
| `priority` | Higher = checked first (100 is default) |
| `match` | Conditions to match raw tool calls |
| `action_type` | Canonical `domain.verb` (see action type catalog) |
| `channel` | Service name (e.g. "stripe", "gmail") |
| `entities` | Extracted parameters with paths and types |

## Writing a Risk Rule

A risk rule assigns risk signals based on entity values:

```yaml
id: stripe_high_value
description: "Flag high-value Stripe charges"
action_type: "payment.charge"

match:
  tool: "http"
  url: { contains: "api.stripe.com" }

flags:
  - name: FINANCIAL
    role: primary

amplifiers:
  amount:
    source: "entity.amount"
    scale: linear
  destination:
    source: "entity.recipient"
```

### Available Flags

`FINANCIAL`, `EXECUTION`, `DESTRUCTION`, `PHYSICAL`, `PRIVILEGE`,
`EXPOSURE`, `GOVERNANCE`, `OUTBOUND`, `MUTATION`

### Flag Roles

- `primary` — contributes more weight to the score
- `secondary` — contributes less weight

## Writing Fixtures

Fixtures are test cases that verify your normalizer and risk rules:

```yaml
tool_name: "http"
parameters:
  method: "POST"
  url: "https://api.stripe.com/v1/charges"
  body:
    amount: 100
    currency: "usd"
expected_permission: "allow"
```

## Validation Checklist

Before submitting:

- [ ] `permit0 pack validate packs/my_service` passes
- [ ] `permit0 pack test packs/my_service` passes
- [ ] At least 3 fixture test cases (happy path, edge case, deny case)
- [ ] Normalizer IDs are unique and descriptive
- [ ] Risk flags are appropriate for the service domain
- [ ] README.md documents the pack's purpose and known limitations

## Pack Staging Pipeline

1. Submit PR to `packs/community/` directory
2. Automated CI runs `permit0 pack validate` and `permit0 pack test`
3. Maintainer review
4. Once approved, pack moves to `packs/verified/` in a follow-up PR
