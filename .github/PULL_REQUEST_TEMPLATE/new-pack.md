## Pack identity

- **Pack:** `<owner>/<name>` (e.g. `permit0/slack`)
- **Tier targeted:** built-in / community / verified
- **Issue:** #<n> — link to the approved pack proposal

## Scope

<!-- One-paragraph description of what this pack governs. -->

### Action types covered

| `action_type` | Tools mapped | Risk rule |
|---|---|---|
| | | |

### Channels

| Channel | MCP server | Tool pattern |
|---|---|---|
| | | |

## Threat model

- **Catches:** <!-- specific attacker behaviors / operator mistakes this pack prevents -->
- **Does NOT catch:** <!-- known limitations -->
- **Known caveats:** <!-- edge cases, conditional alias overrides, parameter remapping gaps -->

## Calibration

- Tested against `<N>` golden fixtures under `tests/`.
- Last calibrated: `<YYYY-MM-DD>`.
- Cross-channel goldens? Yes / No
- Security fixtures? Yes / No (required for `verified` tier)

## Validation evidence

```text
$ permit0 pack validate packs/<owner>/<name>
<paste the output — should report "All N files valid" with zero hard errors>
```

```text
$ permit0 pack test packs/<owner>/<name>
<paste fixture-pass output>
```

## Pre-merge checklist

### Required for all tiers

- [ ] `pack.yaml` declares `pack_format: 2`
- [ ] `permit0_pack: "<owner>/<name>"` matches the directory path
- [ ] `permit0 pack validate` reports zero hard errors
- [ ] Every action type in `action_types:` has at least one normalizer + one risk rule
- [ ] Every normalizer has a unique `priority:` (no collisions with other packs in the workspace)
- [ ] `_channel.yaml` declares a `tool_pattern:` and every YAML in the channel directory's `match.tool` matches it
- [ ] No legacy `vendor:` field in `pack.yaml`
- [ ] At least 3 fixtures per action type (allow / deny / edge case)
- [ ] README.md filled in (scope, threat model, channels, calibration date)
- [ ] CHANGELOG.md entry for this version

### Required for `built-in` and `verified` tiers

- [ ] Every action type on the always-human list (`email.set_forwarding`, `email.add_delegate`, `iam.*`, `secret.*`, `payment.*`) that this pack covers has at least one `gate:` mutation in `rules:` or `session_rules:`
- [ ] `tests/security/` includes fixtures for every known attack pattern in this domain
- [ ] No regex with catastrophic backtracking in any rule
- [ ] No `Downgrade` or `Override` mutation that could lower a critical action's risk to allow tier
- [ ] Channel detection cannot be spoofed (entity values that drive routing come from the call payload, not from the model's free text)
- [ ] Calibration corpus includes red-team-style cases

### Maintenance commitment

- [ ] At least one maintainer listed in `pack.yaml` `maintainers:`
- [ ] Maintainer agrees to triage issues opened against this pack
- [ ] License is Apache-2.0, MIT, or BSD-2/3 (copyleft licenses are flagged)

## Related docs

- [Layout reference](../../packs/README.md)
- [Action taxonomy](../../docs/taxonomy.md)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
