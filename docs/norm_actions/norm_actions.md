# NormAction Catalog

permit0 normalizes every tool call into a **NormAction** — a vendor-agnostic, policy-addressable representation of intent. Rules score, deny, allow, allowlist, or deny-list by NormAction, not by raw tool name — so a `Bash` call, an `http` call to Stripe, and a bank-pack `wire_transfer` all flow through the same set of policies.

The canonical source of truth is `permit0_types::catalog` (see `crates/permit0-types/src/catalog.rs`). It defines **20 domains** × **~116 action_types**. Of those, this repo ships **10 with full packs** (normalizer + risk rule). The rest are declared — you can reference them in YAML and they'll parse fine — but they currently fall through to `HumanInTheLoop` because no risk rule exists yet.

## Anatomy of a NormAction

```
NormAction {
    action_type: "<domain>.<verb>"   // e.g. "payments.charge"
    channel:     "<vendor/surface>"  // e.g. "stripe", "bash", "claude_code"
    entities:    { ... }             // semantically extracted fields
    execution:   {
        surface_tool:    "<raw tool name>"
        surface_command: "<human-readable summary>"
    }
}
```

- **`action_type`** is what **risk rules** match on — `packs/<pack>/risk_rules/<file>.yaml` has a top-level `action_type:` field.
- **`channel`** is what **per-vendor overrides** can branch on (e.g. "Stripe charges go to Finance review, Adyen goes to Ops").
- **`entities`** are what **rule `when` clauses** look at. They are normalized across tool surfaces — every shell tool extracts `command`, every write tool extracts `path` + `file_type`.
- Rules can reference entities either directly (`command: { contains: "rm -rf" }`) or under the `entity.*` namespace (`entity.host: { not_in_set: "org.trusted_domains" }`). The `entity.*` form is preferred for normalizer-computed values.

## Catalog Overview

Legend: ✅ = pack shipped, 🟡 = catalog-declared, no pack yet (falls through to `HumanInTheLoop`).

### email — 9 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `email.search` | 🟡 | |
| `email.get_thread` | 🟡 | |
| `email.send` | ✅ | gmail pack |
| `email.reply` | 🟡 | |
| `email.forward` | 🟡 | Forward-to-external is a common exfil vector |
| `email.draft` | 🟡 | |
| `email.label` | 🟡 | |
| `email.archive` | 🟡 | |
| `email.delete` | 🟡 | |

### messages — 6 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `messages.send` | 🟡 | Slack/Discord/Teams DMs |
| `messages.post_channel` | 🟡 | |
| `messages.send_dm` | 🟡 | |
| `messages.search` | 🟡 | |
| `messages.react` | 🟡 | |
| `messages.delete` | 🟡 | |

### content — 3 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `content.post_social` | 🟡 | Twitter/LinkedIn/etc. |
| `content.update_cms` | 🟡 | |
| `content.send_newsletter` | 🟡 | Large-blast-radius — worth prioritizing |

### calendar — 6 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `calendar.list_events` | 🟡 | |
| `calendar.get_event` | 🟡 | |
| `calendar.create_event` | 🟡 | |
| `calendar.update_event` | 🟡 | |
| `calendar.delete_event` | 🟡 | |
| `calendar.rsvp` | 🟡 | |

### tasks — 6 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `tasks.create` | 🟡 | Jira/Linear/Asana |
| `tasks.assign` | 🟡 | |
| `tasks.complete` | 🟡 | |
| `tasks.update` | 🟡 | |
| `tasks.delete` | 🟡 | |
| `tasks.comment` | 🟡 | |

### files — 10 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `files.list` | ✅ | claude_code pack (`Glob`) |
| `files.read` | ✅ | claude_code + filesystem packs |
| `files.write` | ✅ | claude_code pack (`Write`, `Edit`) |
| `files.delete` | 🟡 | |
| `files.move` | 🟡 | |
| `files.copy` | 🟡 | |
| `files.share` | 🟡 | Google Drive / SharePoint / S3 presigned |
| `files.upload` | 🟡 | |
| `files.download` | 🟡 | |
| `files.export` | 🟡 | Bulk-export risk is distinct from read |

### db — 7 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `db.select` | 🟡 | |
| `db.insert` | 🟡 | |
| `db.update` | 🟡 | |
| `db.delete` | 🟡 | |
| `db.admin` | 🟡 | DDL / role management |
| `db.export` | 🟡 | Bulk export — high sensitivity |
| `db.backup` | 🟡 | |

### crm — 9 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `crm.search_contacts` | 🟡 | |
| `crm.get_contact` | 🟡 | |
| `crm.create_contact` | 🟡 | |
| `crm.update_contact` | 🟡 | |
| `crm.delete_contact` | 🟡 | |
| `crm.create_deal` | 🟡 | |
| `crm.update_deal` | 🟡 | |
| `crm.log_activity` | 🟡 | |
| `crm.export` | 🟡 | Customer-list exfil |

### payments — 8 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `payments.charge` | ✅ | stripe pack |
| `payments.refund` | 🟡 | stripe normalizer exists but **no risk rule** — falls through |
| `payments.transfer` | ✅ | bank_transfer pack |
| `payments.get_balance` | 🟡 | |
| `payments.list_transactions` | 🟡 | |
| `payments.create_invoice` | 🟡 | |
| `payments.update_payment_method` | 🟡 | Card-on-file changes are high-risk |
| `payments.create_subscription` | 🟡 | |

### legal — 3 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `legal.sign_document` | 🟡 | DocuSign / agents signing contracts |
| `legal.submit_filing` | 🟡 | |
| `legal.accept_terms` | 🟡 | |

### iam — 8 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `iam.list_users` | 🟡 | |
| `iam.create_user` | 🟡 | |
| `iam.update_user` | 🟡 | |
| `iam.delete_user` | 🟡 | |
| `iam.assign_role` | 🟡 | Privilege-escalation vector |
| `iam.revoke_role` | 🟡 | |
| `iam.reset_password` | 🟡 | |
| `iam.generate_api_key` | 🟡 | |

### secrets — 3 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `secrets.read` | 🟡 | Vault / AWS Secrets Manager / 1Password |
| `secrets.create` | 🟡 | |
| `secrets.rotate` | 🟡 | |

### infra — 6 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `infra.list_resources` | 🟡 | |
| `infra.create_resource` | 🟡 | Spawn instances / buckets |
| `infra.modify_resource` | 🟡 | |
| `infra.terminate_resource` | 🟡 | Destructive |
| `infra.scale` | 🟡 | Cost-blast-radius |
| `infra.modify_network` | 🟡 | Security-group / firewall changes |

### process — 4 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `process.shell` | ✅ | bash + claude_code packs |
| `process.run_script` | 🟡 | |
| `process.docker_run` | 🟡 | |
| `process.lambda_invoke` | 🟡 | |

### network — 3 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `network.http_get` | ✅ | claude_code pack (`WebFetch`, `WebSearch`) |
| `network.http_post` | 🟡 | |
| `network.webhook_send` | 🟡 | |

### dev — 9 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `dev.get_repo` | 🟡 | |
| `dev.list_issues` | 🟡 | |
| `dev.create_issue` | 🟡 | |
| `dev.create_pr` | 🟡 | |
| `dev.merge_pr` | 🟡 | High-risk — code lands on main |
| `dev.push_code` | 🟡 | |
| `dev.deploy` | 🟡 | Prod blast-radius |
| `dev.run_pipeline` | 🟡 | |
| `dev.create_release` | 🟡 | |

### browser — 7 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `browser.navigate` | 🟡 | |
| `browser.click` | 🟡 | |
| `browser.fill_form` | 🟡 | |
| `browser.submit_form` | 🟡 | Actual action — often irreversible |
| `browser.screenshot` | 🟡 | |
| `browser.download` | 🟡 | |
| `browser.execute_js` | 🟡 | Arbitrary code in page context |

### device — 5 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `device.unlock` | 🟡 | Physical/robotic surfaces |
| `device.lock` | 🟡 | |
| `device.camera_enable` | 🟡 | |
| `device.camera_disable` | 🟡 | |
| `device.move` | 🟡 | Robot/drone actuation |

### ai — 3 verbs

| action_type | Status | Notes |
|---|:---:|---|
| `ai.prompt` | ✅ | claude_code pack (`Agent` — subagent invocation) |
| `ai.embed` | 🟡 | |
| `ai.fine_tune` | 🟡 | |

### unknown — 1 verb

| action_type | Status | Notes |
|---|:---:|---|
| `unknown.unclassified` | — | Fallback for tool calls no normalizer matches. Engine returns `HumanInTheLoop`. |

## Shipped NormActions (detailed)

These are the 10 action_types with both a normalizer and a risk rule currently in the repo.

| action_type | Normalizers (tool → channel) | Risk rule |
|---|---|---|
| `process.shell` | `Bash` → claude_code, `bash` → bash | `bash/risk_rules/shell.yaml` |
| `files.write` | `Write` / `Edit` → claude_code | `claude_code/risk_rules/file_write.yaml` |
| `files.read` | `Read` / `Grep` → claude_code, `file_read` → local | `filesystem/risk_rules/read.yaml` |
| `files.list` | `Glob` → claude_code | `claude_code/risk_rules/file_list.yaml` |
| `network.http_get` | `WebFetch` / `WebSearch` → claude_code | `claude_code/risk_rules/network.yaml` |
| `ai.prompt` | `Agent` → claude_code | `claude_code/risk_rules/ai_prompt.yaml` |
| `email.send` | `gmail_send` → gmail | `gmail/risk_rules/send.yaml` |
| `payments.charge` | `http POST api.stripe.com/v1/charges` → stripe | `stripe/risk_rules/charge.yaml` |
| `payments.refund` | `http POST api.stripe.com/v1/refunds` → stripe | — (falls through to HumanInTheLoop) |
| `payments.transfer` | `bank_transfer` → bank | `bank_transfer/risk_rules/transfer.yaml` |

---

### `process.shell`

Shell / subprocess execution. The single highest-blast-radius action type in permit0 — hosts all the catastrophic-delete, privilege-escalation, and remote-code-execution gates.

- **Normalizers**: `claude_code:bash` (`Bash`, priority 200), `permit0-pack-bash:shell` (`bash`, priority 90)
- **Entities**: `command` (required), `pipe_count` (heuristic for chained command risk)
- **Risk rule**: `packs/bash/risk_rules/shell.yaml`
- **Built-in gates**: `catastrophic_recursive_delete`, `remote_code_execution`, `device_write`, `privilege_escalation`

Example:
```json
{"tool_name": "Bash", "parameters": {"command": "sudo rm -rf /"}}
```
→ `process.shell` → `DENY` (Critical, gate `catastrophic_recursive_delete`).

---

### `files.write`

File creation or modification. Two Claude-Code tools normalize here: `Write` (new file) and `Edit` (in-place modification).

- **Normalizers**: `claude_code:write` (priority 201), `claude_code:edit` (priority 202)
- **Entities**: `path` (required, from `file_path`), `file_type` (code/data/config/binary), `path_depth`, `content_length` (Write) or `old_string_length` + `new_string_length` (Edit)
- **Risk rule**: `packs/claude_code/risk_rules/file_write.yaml`
- **Notable gates**: `ssh_directory_write`, writes under `/etc`, `/var`, `.claude/settings`, any `credentials` / `secret` / `.env` path fragment.

---

### `files.read`

File read or search. Covers direct reads and pattern-search tools.

- **Normalizers**: `claude_code:read` (priority 203), `claude_code:grep` (priority 205), `filesystem:file_read` (priority 85)
- **Entities**: `path` (required), `file_type`, `path_depth`, `pii` (filesystem pack only — via `detect_pii_patterns` over content)
- **Risk rule**: `packs/filesystem/risk_rules/read.yaml`
- **Notable gates**: `system_credential_access` (blocks reads of `/etc/shadow`, `/etc/passwd`, `.ssh/id_*`, known credential files).

---

### `files.list`

Filesystem enumeration / glob patterns. Separate from `files.read` because the blast radius is different — a `/**/*` glob enumerates an entire filesystem without reading any file content.

- **Normalizer**: `claude_code:glob` (`Glob`, priority 204)
- **Entities**: `pattern` (required), `path` (base directory)
- **Risk rule**: `packs/claude_code/risk_rules/file_list.yaml`

---

### `network.http_get`

Outbound HTTP — both `WebFetch` (direct URL) and `WebSearch` (query → search engine).

- **Normalizers**: `claude_code:web_fetch` (priority 207), `claude_code:web_search` (priority 208)
- **Entities**: `url` (WebFetch) / `query` (WebSearch), `host` (via `url_host`), `is_private` (via `is_private_ip`, SSRF guard)
- **Risk rule**: `packs/claude_code/risk_rules/network.yaml`
- **Key rules**:
  - Per-call: private-IP access → PRIVILEGE flag, known-exfil hostnames (`webhook.site`, `requestbin`, `ngrok`, `pipedream`) → EXPOSURE
  - **Named-set-driven allowlist**: `entity.host: { not_in_set: "org.trusted_domains" }` → GOVERNANCE + destination amplifier. Default set defined in `permit0-scoring::default_named_sets`; override in the active profile.
  - **Session attack-chain gates**: if the session has ever produced `HIGH`/`CRITICAL` tier (any action type), any subsequent outbound call is gated via `post_attack_chain_outbound_block`. Cross-action-type scrutiny via `max_tier` + `distinct_flags`.

---

### `ai.prompt`

Subagent invocation or LLM prompt submission.

- **Normalizer**: `claude_code:agent` (`Agent`, priority 206)
- **Entities**: `subagent_type` (default `"general-purpose"`), `prompt_length`
- **Risk rule**: `packs/claude_code/risk_rules/ai_prompt.yaml`

---

### `email.send`

Outbound email.

- **Normalizer**: `gmail:send` (`gmail_send`, priority 95)
- **Entities**: `to` (required), `subject`, `body`, `recipient_scope` (self/internal/external/mixed via `recipient_scope(to, org_domain)`), `domain` (via `extract_domain`)
- **Risk rule**: `packs/gmail/risk_rules/send.yaml`
- **Notable rules**: multiple recipients / BCC-to-external / subject keywords (`password|reset|verify`) escalate sensitivity; session rule catches >50 sends/day.

---

### `payments.charge`

Stripe card charge creation.

- **Normalizer**: `stripe:charges.create` (matches `http POST api.stripe.com/v1/charges`, priority 100)
- **Entities**: `amount` (required), `currency` (default `"usd"`), `customer`, `amount_cents` (via `extract_amount_cents`)
- **Risk rule**: `packs/stripe/risk_rules/charge.yaml`
- **Notable rules**: amount-based amplifier scaling, currency / country risk bumps, session-level card-testing pattern detection.

---

### `payments.refund`

Stripe refund. Normalizer exists but no risk rule — currently falls through to `HumanInTheLoop`. File an issue or add your own rule.

- **Normalizer**: `stripe:refunds.create` (priority 99)
- **Entities**: `amount`, `currency`, `charge`, `reason`

---

### `payments.transfer`

Bank wire / ACH transfer.

- **Normalizer**: `bank:wire_transfer` (`bank_transfer`, priority ~95)
- **Entities**: `amount` (required), `currency` (default `"usd"`, lowercased), `recipient` (required, from `recipient_account`), `recipient_name`, `memo`
- **Risk rule**: `packs/bank_transfer/risk_rules/transfer.yaml`
- **Notable rules**: amount-tiered amplifiers, unknown-recipient gate, session-level APP-fraud / scatter-transfer detection (see `demos/demo1_app_fraud.py`).

## Entities cheat sheet

Cross-pack, these entity keys are consistent, so rules written against one pack often port to another:

| Entity | Meaning | Packs producing it |
|---|---|---|
| `command` | shell command string | bash, claude_code (`Bash`) |
| `path` | filesystem path | claude_code (Write/Edit/Read/Grep), filesystem |
| `file_type` | `code`/`data`/`config`/`binary` | all file tools |
| `path_depth` | integer, `/`-separated segments | all file tools |
| `url` | full URL | claude_code (`WebFetch`) |
| `host` | URL host, lowercased | claude_code (`WebFetch`) |
| `is_private` | private IP / localhost check | claude_code (`WebFetch`) |
| `amount` | monetary amount (raw) | stripe, bank_transfer |
| `amount_cents` | monetary amount in cents | stripe |
| `currency` | ISO currency, lowercased | stripe, bank_transfer |
| `recipient` / `recipient_name` | bank transfer counterparty | bank_transfer |
| `to` | email recipient(s) | gmail |
| `recipient_scope` | `self`/`internal`/`external`/`mixed` | gmail |
| `domain` | email recipient domain | gmail |
| `pii` | bool, PII detected in content | filesystem |

## What happens for declared-but-unpacked action_types?

If you add a YAML rule referencing, say, `dev.deploy`, it parses — the catalog accepts it. But until someone ships a normalizer that produces `dev.deploy` and a risk rule scoring it, the engine path is:

1. Raw tool call arrives.
2. No normalizer matches → falls through to `ActionType::UNKNOWN` (= `unknown.unclassified`).
3. No risk rule for `unknown.unclassified` → engine returns `HumanInTheLoop`.

So declared-only action_types don't crash; they just bypass per-call scoring and always ask a human. The path from 🟡 to ✅ is: write the normalizer, write a risk rule, register both in `pack.yaml`. See [`pack-contribution-guide.md`](./pack-contribution-guide.md).

## Adding a new NormAction

1. Pick a `domain.verb` pair from `permit0_types::catalog`. If nothing fits, add a new `Verb` variant to the enum (it's append-only and versioned).
2. Add a normalizer YAML under `packs/<name>/normalizers/` with `match:` on the raw tool name + `normalize:` producing the action.
3. Add a risk rule YAML under `packs/<name>/risk_rules/` with the same `action_type:`.
4. Register both files in `packs/<name>/pack.yaml`.
5. Golden-test the end-to-end decision — see [`pack-contribution-guide.md`](./pack-contribution-guide.md) and `corpora/calibration/` for examples.

## Related docs

- [`dsl.md`](./dsl.md) — full DSL reference: `when`/`then`, predicate operators including `in_set`, helper registry
- [`permit.md`](./permit.md) — how Allow/Human/Deny is derived from a NormAction + RiskScore
- [`pack-contribution-guide.md`](./pack-contribution-guide.md) — step-by-step for shipping a new pack
