# Action Type Taxonomy

> **Source of truth.** The canonical list lives in
> [`crates/permit0-types/src/taxonomy.rs`](../crates/permit0-types/src/taxonomy.rs).
> If you find a discrepancy between this document and the code, **the
> code wins**. A CI test (`taxonomy_doc_in_sync`) keeps this file
> aligned with the enum — drift fails the build.

permit0 normalizes every tool call into a **NormAction** — a vendor-agnostic, policy-addressable representation of intent. Risk rules score, deny, allow, allowlist, or deny-list by NormAction, not by raw tool name — so `gmail_send`, `outlook_send`, and a future `slack_send_dm` all flow through the same set of policies once they share an action type.

The taxonomy is an **append-only enum** in `permit0-types`. New verbs land via PR; the enum's closed nature is what makes risk rules predictable across vendors. As of writing, it defines 22 domains.

## Anatomy of a NormAction

```
NormAction {
    action_type: "<domain>.<verb>"   // e.g. "email.send"
    channel:     "<vendor/surface>"  // e.g. "gmail", "outlook"
    entities:    { ... }             // semantically extracted fields
    execution:   {
        surface_tool:    "<raw tool name>"
        surface_command: "<human-readable summary>"
    }
}
```

- **`action_type`** is what **risk rules** match on — `packs/<owner>/<pack>/risk_rules/<verb>.yaml` has a top-level `action_type:` field.
- **`channel`** is what **per-vendor overrides** can branch on (e.g. "Gmail sends from the org primary domain go to Allow, Outlook from a personal account goes to HumanInTheLoop").
- **`entities`** are what **rule `when` clauses** look at. They are normalized across tool surfaces — every email-domain normalizer extracts `to`/`subject`/`body`/`recipient_scope`/`domain`, regardless of whether the underlying tool was Gmail or Outlook.
- Rules can reference entities directly (`subject: { contains: "password" }`) or under the `entity.*` namespace (`entity.recipient_scope: { equals: "external" }`). The `entity.*` form is preferred for normalizer-computed values.

## Taxonomy

Legend: ✅ = at least one in-tree pack ships a normalizer + risk rule for this action_type. 🟡 = taxonomy-declared, no pack yet (the engine returns `HumanInTheLoop` for any tool call that doesn't normalize to a covered action type).

Phase 1 ships exactly one pack: [`packs/permit0/email`](../packs/permit0/email/). Every other domain is declared and ready for a pack contribution.

### `email` — 16 verbs

Pack: [`packs/permit0/email`](../packs/permit0/email/) (Gmail + Outlook channels).

| action_type | Status | Notes |
|---|:---:|---|
| `email.search` | ✅ | |
| `email.read` | ✅ | |
| `email.read_thread` | ✅ | |
| `email.list_mailboxes` | ✅ | |
| `email.draft` | ✅ | |
| `email.list_drafts` | ✅ | |
| `email.send` | ✅ | Outbound — recipient_scope drives external-domain escalation |
| `email.mark_read` | ✅ | |
| `email.flag` | ✅ | |
| `email.move` | ✅ | |
| `email.archive` | ✅ | |
| `email.mark_spam` | ✅ | |
| `email.delete` | ✅ | |
| `email.create_mailbox` | ✅ | |
| `email.set_forwarding` | ✅ | Always-human gate — auto-forwarding is a textbook account-takeover tactic |
| `email.add_delegate` | ✅ | Always-human gate — granting another user mailbox access |

### `message` — 8 verbs

Slack, Discord, Teams, MS Teams, Mattermost, etc.

| action_type | Status | Notes |
|---|:---:|---|
| `message.post_channel` | 🟡 | Public/private channel posts |
| `message.send_dm` | 🟡 | 1:1 DMs — bypass channel-level moderation |
| `message.send_sms` | 🟡 | SMS-style messaging |
| `message.search` | 🟡 | Workspace history search |
| `message.get` | 🟡 | Single-message fetch |
| `message.react` | 🟡 | Emoji reactions |
| `message.update` | 🟡 | Message edits — bulk edits look like coverup behavior |
| `message.delete` | 🟡 | |

### `social` — 6 verbs

Twitter/X, LinkedIn, Mastodon, Bluesky.

| action_type | Status | Notes |
|---|:---:|---|
| `social.post` | 🟡 | Public broadcast — large blast radius |
| `social.reply` | 🟡 | |
| `social.delete` | 🟡 | |
| `social.like` | 🟡 | |
| `social.send_dm` | 🟡 | |
| `social.search` | 🟡 | |

### `cms` — 6 verbs

WordPress, Contentful, Sanity, Webflow.

| action_type | Status | Notes |
|---|:---:|---|
| `cms.publish` | 🟡 | Content goes live |
| `cms.update` | 🟡 | |
| `cms.unpublish` | 🟡 | |
| `cms.schedule` | 🟡 | Future-dated publish — review window matters |
| `cms.delete` | 🟡 | |
| `cms.list` | 🟡 | |

### `newsletter` — 5 verbs

Mailchimp, Substack, Beehiiv, Customer.io.

| action_type | Status | Notes |
|---|:---:|---|
| `newsletter.send` | 🟡 | Mass send — large blast radius, irreversible once sent |
| `newsletter.schedule` | 🟡 | |
| `newsletter.draft` | 🟡 | |
| `newsletter.update` | 🟡 | |
| `newsletter.unsubscribe` | 🟡 | |

### `calendar` — 6 verbs

Google Calendar, Outlook Calendar, Cal.com.

| action_type | Status | Notes |
|---|:---:|---|
| `calendar.list` | 🟡 | |
| `calendar.get` | 🟡 | |
| `calendar.create` | 🟡 | |
| `calendar.update` | 🟡 | |
| `calendar.delete` | 🟡 | |
| `calendar.rsvp` | 🟡 | |

### `task` — 8 verbs

Jira, Linear, Asana, Trello, Monday.

| action_type | Status | Notes |
|---|:---:|---|
| `task.create` | 🟡 | |
| `task.get` | 🟡 | |
| `task.list` | 🟡 | |
| `task.update` | 🟡 | |
| `task.complete` | 🟡 | |
| `task.assign` | 🟡 | |
| `task.delete` | 🟡 | |
| `task.comment` | 🟡 | |

### `file` — 14 verbs

Google Drive, OneDrive, Dropbox, S3, local filesystem.

| action_type | Status | Notes |
|---|:---:|---|
| `file.list` | 🟡 | |
| `file.get` | 🟡 | |
| `file.read` | 🟡 | |
| `file.create` | 🟡 | |
| `file.update` | 🟡 | |
| `file.delete` | 🟡 | |
| `file.delete_recursive` | 🟡 | Distinct from `delete` because the blast radius is qualitatively different |
| `file.move` | 🟡 | |
| `file.copy` | 🟡 | |
| `file.share` | 🟡 | Share links / presigned URLs are exfil vectors |
| `file.upload` | 🟡 | |
| `file.download` | 🟡 | |
| `file.export` | 🟡 | Bulk export is high sensitivity |
| `file.search` | 🟡 | |

### `db` — 13 verbs

Postgres, MySQL, MongoDB, BigQuery, Snowflake.

| action_type | Status | Notes |
|---|:---:|---|
| `db.select` | 🟡 | |
| `db.insert` | 🟡 | |
| `db.update` | 🟡 | |
| `db.delete` | 🟡 | |
| `db.create` | 🟡 | DDL — schema mutation |
| `db.alter` | 🟡 | DDL |
| `db.drop` | 🟡 | DDL — destructive |
| `db.truncate` | 🟡 | Destructive but reversible from backup |
| `db.grant_access` | 🟡 | Privilege escalation vector |
| `db.revoke_access` | 🟡 | |
| `db.export` | 🟡 | Bulk-export distinct from select — different sensitivity |
| `db.backup` | 🟡 | |
| `db.restore` | 🟡 | |

### `crm` — 8 verbs

Salesforce, HubSpot, Pipedrive, Attio.

| action_type | Status | Notes |
|---|:---:|---|
| `crm.list` | 🟡 | |
| `crm.get` | 🟡 | |
| `crm.search` | 🟡 | |
| `crm.create` | 🟡 | |
| `crm.update` | 🟡 | |
| `crm.delete` | 🟡 | |
| `crm.log_activity` | 🟡 | |
| `crm.export` | 🟡 | Customer-list exfil vector |

### `payment` — 9 verbs

Stripe, Square, PayPal, ACH/wire systems.

| action_type | Status | Notes |
|---|:---:|---|
| `payment.charge` | 🟡 | Always-human gate when shipped |
| `payment.refund` | 🟡 | Always-human gate when shipped |
| `payment.transfer` | 🟡 | Always-human gate when shipped |
| `payment.get_balance` | 🟡 | |
| `payment.list` | 🟡 | |
| `payment.get` | 🟡 | |
| `payment.create` | 🟡 | |
| `payment.update` | 🟡 | |
| `payment.cancel_subscription` | 🟡 | |

### `legal` — 3 verbs

DocuSign, HelloSign, government filings.

| action_type | Status | Notes |
|---|:---:|---|
| `legal.sign_document` | 🟡 | Agent signing on behalf of a user — high stakes |
| `legal.submit_filing` | 🟡 | |
| `legal.accept_terms` | 🟡 | |

### `iam` — 10 verbs

Okta, Auth0, AWS IAM, Google Workspace admin.

| action_type | Status | Notes |
|---|:---:|---|
| `iam.list` | 🟡 | |
| `iam.get` | 🟡 | |
| `iam.create` | 🟡 | Always-human gate when shipped |
| `iam.update` | 🟡 | |
| `iam.delete` | 🟡 | Always-human gate when shipped |
| `iam.assign_role` | 🟡 | Always-human gate — privilege escalation vector |
| `iam.revoke_role` | 🟡 | Always-human gate when shipped |
| `iam.reset_password` | 🟡 | Always-human gate when shipped |
| `iam.generate_api_key` | 🟡 | Always-human gate when shipped |
| `iam.revoke_api_key` | 🟡 | |

### `secret` — 6 verbs

Vault, AWS Secrets Manager, 1Password, Doppler.

| action_type | Status | Notes |
|---|:---:|---|
| `secret.get` | 🟡 | Always-human gate when shipped |
| `secret.list` | 🟡 | |
| `secret.create` | 🟡 | Always-human gate when shipped |
| `secret.update` | 🟡 | Always-human gate when shipped |
| `secret.rotate` | 🟡 | Always-human gate when shipped |
| `secret.delete` | 🟡 | |

### `infra` — 6 verbs

AWS, GCP, Azure, Terraform, Pulumi.

| action_type | Status | Notes |
|---|:---:|---|
| `infra.list` | 🟡 | |
| `infra.get` | 🟡 | |
| `infra.create` | 🟡 | |
| `infra.update` | 🟡 | |
| `infra.terminate` | 🟡 | Destructive |
| `infra.scale` | 🟡 | Cost blast-radius |

### `process` — 2 verbs

Shell, subprocess, Lambda, Cloud Functions.

| action_type | Status | Notes |
|---|:---:|---|
| `process.run` | 🟡 | Shell / subprocess — single highest blast-radius action type |
| `process.invoke` | 🟡 | Function/lambda invoke |

### `network` — 5 verbs

HTTP clients, webhooks.

| action_type | Status | Notes |
|---|:---:|---|
| `network.get` | 🟡 | |
| `network.post` | 🟡 | |
| `network.put` | 🟡 | |
| `network.delete` | 🟡 | |
| `network.send_webhook` | 🟡 | |

### `dev` — 9 verbs

GitHub, GitLab, CI/CD platforms.

| action_type | Status | Notes |
|---|:---:|---|
| `dev.list` | 🟡 | |
| `dev.get` | 🟡 | |
| `dev.create` | 🟡 | |
| `dev.update` | 🟡 | |
| `dev.close_issue` | 🟡 | |
| `dev.merge_pr` | 🟡 | Code lands on main |
| `dev.push_code` | 🟡 | |
| `dev.deploy` | 🟡 | Production blast-radius |
| `dev.run_pipeline` | 🟡 | |

### `browser` — 8 verbs

Headless and headful browser automation.

| action_type | Status | Notes |
|---|:---:|---|
| `browser.navigate` | 🟡 | |
| `browser.click` | 🟡 | |
| `browser.fill_form` | 🟡 | |
| `browser.submit_form` | 🟡 | Action — often irreversible |
| `browser.take_screenshot` | 🟡 | |
| `browser.download_file` | 🟡 | |
| `browser.execute_js` | 🟡 | Arbitrary code in page context |
| `browser.scrape` | 🟡 | |

### `device` — 5 verbs

Robotics, IoT, smart home.

| action_type | Status | Notes |
|---|:---:|---|
| `device.lock` | 🟡 | |
| `device.unlock` | 🟡 | |
| `device.enable` | 🟡 | |
| `device.disable` | 🟡 | |
| `device.move` | 🟡 | Robot/drone actuation |

### `ai` — 5 verbs

LLM APIs, agent invocations, embedding services, fine-tuning.

| action_type | Status | Notes |
|---|:---:|---|
| `ai.prompt` | 🟡 | LLM call |
| `ai.embed` | 🟡 | |
| `ai.fine_tune` | 🟡 | |
| `ai.invoke_agent` | 🟡 | Subagent invocation — recursive trust boundary |
| `ai.generate_image` | 🟡 | |

### `unknown` — 1 verb

| action_type | Status | Notes |
|---|:---:|---|
| `unknown.unclassified` | — | Fallback for tool calls no normalizer matches. Engine returns `HumanInTheLoop`. |

## What happens for declared-but-unpacked action_types?

If you add a YAML rule referencing, say, `dev.deploy`, it parses — the taxonomy accepts it. But until someone ships a normalizer that produces `dev.deploy` and a risk rule scoring it, the engine path is:

1. Raw tool call arrives.
2. No normalizer matches → falls through to `ActionType::UNKNOWN` (= `unknown.unclassified`).
3. No risk rule for `unknown.unclassified` → engine returns `HumanInTheLoop`.

Declared-only action_types don't crash; they bypass per-call scoring and always ask a human. The path from 🟡 to ✅ is: write the normalizer, write a risk rule, register both in `pack.yaml`. See [`pack-contribution-guide.md`](./pack-contribution-guide.md).

## Adding a new NormAction

1. Pick a `domain.verb` pair from `permit0_types::taxonomy`. If nothing fits, add a new `Verb` variant to the enum (it's append-only and versioned).
2. Add a normalizer YAML under `packs/<owner>/<pack>/normalizers/<channel>/<verb>.yaml` with `match:` on the raw tool name + `normalize:` producing the action.
3. Add a risk rule YAML under `packs/<owner>/<pack>/risk_rules/<verb>.yaml` with the same `action_type:`.
4. List the action_type in `packs/<owner>/<pack>/pack.yaml` under `action_types:`.
5. Update this document — both the per-domain table and the `taxonomy_doc_in_sync` test will catch you if you forget.
6. Golden-test the end-to-end decision — see [`pack-contribution-guide.md`](./pack-contribution-guide.md) and `corpora/calibration/` for examples.

## Related docs

- [`dsl.md`](./dsl.md) — full DSL reference: `when`/`then`, predicate operators including `in_set`, helper registry
- [`permit.md`](./permit.md) — how Allow/Human/Deny is derived from a NormAction + RiskScore
- [`pack-contribution-guide.md`](./pack-contribution-guide.md) — step-by-step for shipping a new pack
- [`../packs/README.md`](../packs/README.md) — pack layout and trust tier semantics
