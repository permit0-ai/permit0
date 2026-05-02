# Changelog

All notable changes to this pack are documented in this file. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-05-01

### Added

- Initial Slack pack covering five message-domain verbs:
  `message.post_channel`, `message.send_dm`, `message.search`,
  `message.react`, and `message.update`.
- Foreign-tool aliases for Slack Web API method names
  (`chat.postMessage`, `chat.update`, `search.messages`,
  `reactions.add` after prefix strip) plus common community-MCP
  shortenings (`post_message`, `send_dm`, `search`, `react`).
- DM-vs-channel disambiguation via conditional alias on the
  `channel` parameter: D/U-prefixed channel IDs route to
  `slack_send_dm`, everything else to `slack_post_channel`.
- Risk rules with always-human gate on DMs and session-rule
  escalation for bulk posting / DM / search / update patterns.
- One shared calibration fixture for the public-channel post
  happy path.
