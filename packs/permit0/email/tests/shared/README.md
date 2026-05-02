# Shared calibration fixtures for the email pack

Cross-channel goldens for the email pack — scenarios where the same
canonical action (`email.send`, `email.archive`, etc.) should produce
the same decision regardless of whether the agent called the Gmail
or Outlook surface.

## Format

Each YAML is one calibration case:

```yaml
name: <unique_case_id>
tool_name: <raw_tool_name>     # e.g. gmail_send, outlook_send
parameters:                     # passed verbatim to the engine
  to: "..."
  subject: "..."
  body: "..."
expected_tier: "Minimal"        # optional — Minimal/Low/Medium/High/Critical
expected_permission: "Allow"    # optional — Allow/Human/Deny
```

## Scope

- **shared/** — channel-agnostic scenarios. The same case should fire
  for both `tool_name: gmail_send` and `tool_name: outlook_send` and
  produce the same decision. Use this for testing canonical behavior.
- **../gmail/**, **../outlook/** — per-channel fixtures (vendor-
  specific entity extraction, alias resolution, etc.). Land alongside
  the channel directories.
- **../security/** — known-attack patterns. Required for verified+
  tier; optional for community.

## Running

```sh
# Discovery happens automatically — `permit0 calibrate test` walks
# both corpora/calibration/ (cross-pack integration corpus) and
# every pack's tests/shared/ (this directory).
permit0 calibrate test
```

## Migration note

PR 5 of the pack taxonomy refactor split calibration corpora into
two homes:

- **Cross-pack** (multi-domain integration scenarios) stay at the
  workspace-level `corpora/calibration/`.
- **Per-pack** (this directory) lets a community pack ship its own
  goldens alongside the rest of the pack.

Both run by default. Decision rationale: keeping cross-pack
calibration top-level avoids coupling integration tests to one pack's
release cadence; keeping per-pack goldens with the pack means a
community PR can ship calibration in the same commit as the
implementation.
