# Slack pack

Message-domain governance for Slack workspaces. Covers the verbs an
LLM agent reaches for most often when wired to a Slack MCP server.

## Scope

**In scope.** Five message-domain verbs covering the bulk of
Slack-MCP traffic: posting to public/private channels, DMing
individuals, searching message history, reacting to messages, and
editing messages the bot previously authored.

**Out of scope (deferred to a follow-up).** `message.get` (reading
single messages), `message.delete` (removing messages), and
`message.send_sms` (Slack does not natively send SMS). Adding these
later is one normalizer + one risk rule + an `action_types:` bump.

**Out of scope (won't fix in this pack).** Slack Workflows, Slack
Connect (cross-org channels), file uploads, channel admin
(`channels.create`, `channels.archive`). Those belong in separate
domain packs (`workflow`, `infra`, `file`) once the taxonomy fleshes
them out.

## Action types covered

| action_type | Tools mapped | Risk rule |
|---|---|---|
| `message.post_channel` | `slack_post_channel`, `chat_post_message` (channel ID), `post_message` (channel ID) | [`risk_rules/post_channel.yaml`](risk_rules/post_channel.yaml) |
| `message.send_dm` | `slack_send_dm`, `chat_post_message` (D/U-prefixed), `post_message` (D/U-prefixed), `send_dm` | [`risk_rules/send_dm.yaml`](risk_rules/send_dm.yaml) |
| `message.search` | `slack_search`, `search_messages`, `search` | [`risk_rules/search.yaml`](risk_rules/search.yaml) |
| `message.react` | `slack_react`, `reactions_add`, `react` | [`risk_rules/react.yaml`](risk_rules/react.yaml) |
| `message.update` | `slack_update`, `chat_update` | [`risk_rules/update.yaml`](risk_rules/update.yaml) |

## Threat model

**Catches:**
- Bulk DM social-engineering (>5 DMs in one session escalates `scope`).
- Channel/DM disambiguation confusion — `chat.postMessage` to a U-prefixed channel is a DM, not a public post; the alias resolver routes them to different action types so policies that allow public posts can't accidentally allow DMs.
- Block Kit posts with interactive UI elements (action-bearing buttons get a higher `scope` amplifier than plain text).
- Bulk channel posting that looks like spam or stuffing (>10 posts/session escalates).
- Bulk message editing that shapes like coverup behavior (>5 edits/session escalates `irreversibility`).
- Reconnaissance via aggressive search (>50 search calls/session escalates).

**Does NOT catch:**
- Slack Workflows triggered by Block Kit actions — the agent's post is governed, but downstream workflow execution is a separate concern.
- Cross-workspace Slack Connect leakage — the workspace-level audit trail covers this; the pack treats all channels uniformly.
- File uploads attached to messages (`files.upload`) — out of scope; needs a `file.upload` action type when added.

**Known caveats:**
- The DM-vs-channel disambiguation is parameter-based: an MCP that surfaces channel IDs as opaque IDs without the C/D/U prefix will route incorrectly. Most Slack SDKs preserve the prefix; if yours doesn't, use a conditional alias on a different param.
- Reactions don't carry parameter context worth scoring beyond presence. Workspace-level workflows that load-bear on specific reactions (e.g. `:white_check_mark:` triggering deploys) need a per-workspace risk-rule overlay rather than a base-pack policy.

## Calibration data

This pack ships with one golden fixture under `tests/shared/`. Add more before promoting beyond the initial 0.1.0 release. Last calibrated 2026-05-01.

## Channels

| Channel | MCP server | Auth | Notes |
|---|---|---|---|
| `slack` | [`clients/slack-mcp`](../../../clients/slack-mcp) (planned) | `oauth_user` | Slack Web API methods, snake_case after prefix strip |

## Layout

```
packs/permit0/slack/
├── pack.yaml
├── pack.lock.yaml
├── README.md (this file)
├── CHANGELOG.md
├── normalizers/
│   └── slack/
│       ├── _channel.yaml         ← channel metadata + tool_pattern: slack_*
│       ├── aliases.yaml          ← Slack Web API + community-MCP names
│       ├── post_channel.yaml
│       ├── send_dm.yaml
│       ├── search.yaml
│       ├── react.yaml
│       └── update.yaml
├── risk_rules/
│   ├── post_channel.yaml
│   ├── send_dm.yaml
│   ├── search.yaml
│   ├── react.yaml
│   └── update.yaml
└── tests/
    └── shared/
        └── post-to-public-channel.yaml
```

## Compatibility

- **permit0 engine:** `>=0.1.0,<0.2`
- **taxonomy:** `1.x`
- **MCP servers:** Slack Web API (any MCP wrapping it; `clients/slack-mcp/` planned in-tree)

## Contributing

See [`docs/pack-contribution-guide.md`](../../../docs/pack-contribution-guide.md)
for the contribution workflow. The Slack pack is intentionally minimal
right now — adding `get`, `delete`, and richer reaction policy is the
natural next contribution.
