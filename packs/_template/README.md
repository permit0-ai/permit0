# TODO_NAME pack

> Replace every TODO in this template before submitting.

## Scope

Brief, specific description of what this pack governs. State what's IN
scope (which tools, which action types) and what's NOT.

## Action types covered

| action_type | Tools mapped | Risk rule |
|---|---|---|
| TODO_DOMAIN.TODO_VERB | TODO_TOOL_NAMES | risk_rules/TODO_VERB.yaml |

## Threat model

- **Catches:** what attacker behavior or operator mistake this pack
  prevents — be specific. "Catches send-to-external-without-policy" is
  better than "catches misuse".
- **Does NOT catch:** known limitations. Not catching things is fine;
  silently not catching them is not.
- **Known caveats:** edge cases, parameter remapping gaps, conditional
  alias overrides, etc.

## Calibration data

This pack was tested against TODO_N golden fixtures from
`tests/shared/`. Last calibrated TODO_DATE.

## Channels

| Channel | MCP server | Auth | Notes |
|---|---|---|---|
| TODO | TODO | TODO | TODO |

## Layout

```
packs/<owner>/<name>/
├── pack.yaml
├── README.md (this file)
├── CHANGELOG.md
├── normalizers/
│   └── <channel>/
│       ├── _channel.yaml      ← channel metadata + tool_pattern
│       ├── aliases.yaml       ← foreign-MCP name remapping
│       └── <verb>.yaml × N    ← one normalizer per verb
├── risk_rules/
│   └── <verb>.yaml × N        ← one rule per action_type, channel-agnostic
└── tests/
    ├── <channel>/             ← per-channel fixtures
    ├── shared/                ← cross-channel goldens
    └── security/              ← known-attack fixtures (verified+ tier)
```

## Compatibility

- **permit0 engine:** `>=0.1.0,<0.2`
- **taxonomy:** `1.x`
- **MCP servers:** TODO

## Contributing

See [`docs/pack-contribution-guide.md`](../../docs/pack-contribution-guide.md)
for the contribution workflow.
