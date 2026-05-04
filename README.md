# Permit0

**The policy engine for AI agent actions. The boundary between what your agent decides and what it's allowed to do.**

*action taxonomy · default risk policies · deterministic · pre-execution · auditable.*

<a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg"></a>
<img alt="Rust 1.85+" src="https://img.shields.io/badge/rust-1.85%2B-orange">

> Permit0 integrates with **Claude Code** and **OpenClaw** — more integrations to come. The pilot `email` taxonomy is ready, with Outlook and Gmail packs. [Open an issue to request the next taxonomy domain or tool pack →](https://github.com/permit0-ai/permit0/issues/new?template=new-pack.md) and ⭐ star the project.

---

## Use this if...

Your AI agent — one you built, or one you use every day — can send email, touch a database, move money, or execute code. You've watched it do something in testing that shouldn't have happened. Or you've held it back from real work because there's no hard permission you set that actually gets enforced.

Permit0 is the boundary between what the LLM *decides* and what actually runs. Every tool call is normalized into a canonical action, scored deterministically against risk dimensions, and decided against a policy in sub-millisecond time — with a signed audit trail an auditor can verify.

The vocabulary is published. The first pack is shipped. The rest is the work.

[▶ Watch the 3-minute demo →](https://www.youtube.com/watch?v=7lzj9cgPxXo) — three real attack patterns: APP fraud, card testing, insider exfiltration.

---

## Try it — Claude Code + Outlook/Gmail in 5 minutes

> **On OpenClaw?** Skip to [`integrations/permit0-openclaw/`](integrations/permit0-openclaw/) — wrap a skill with `permit0Skill(...)` and gate every dispatch through the same daemon. The rest of this section is the Claude Code path.

```bash
# 1. Build
git clone https://github.com/permit0-ai/permit0.git && cd permit0
cargo build --release

# 2. Daemon (calibration mode: every fresh decision blocks on a human)
cargo run -p permit0-cli -- serve --calibrate --port 9090
# Open http://localhost:9090/ui/

# 3. MCP servers (in another terminal)
pip install -e clients/outlook-mcp        # 13 outlook_* tools
pip install -e clients/gmail-mcp          # 13 gmail_*  tools  (skip if unused)

# 4. One-time auth (zero-config for Outlook; Gmail needs a Google OAuth app)
python -c "from permit0_outlook_mcp.auth import get_token; get_token()"
```

Wire into Claude Code with two files (use absolute paths — `~` doesn't expand in JSON):

```jsonc
// ~/.claude/settings.json — gates every tool call before it runs
{
  "hooks": {
    "PreToolUse": [{ "hooks": [{
      "type": "command",
      "command": "/abs/path/to/permit0 hook --db /home/<user>/.permit0/sessions.db"
    }]}]
  }
}
```

```jsonc
// ~/.claude.json — exposes the email tools to Claude
{
  "mcpServers": {
    "permit0-outlook": { "command": "/abs/path/to/permit0-outlook-mcp" },
    "permit0-gmail":   { "command": "/abs/path/to/permit0-gmail-mcp" }
  }
}
```

Restart Claude Code. Ask it: *"list recent emails and archive any newsletters,"* then *"send alice@example.com a draft of my notes."* Every action shows up in the dashboard's **Approvals** tab with Permit0's tier, the risk flags that fired (`OUTBOUND`, `EXPOSURE`, `GOVERNANCE`, …), and the full message body. Approve or deny; verdicts cache in the policy store. Once calibration agrees with you, drop `--calibrate` to enforce.

Shadow mode (`permit0 hook --shadow`) logs decisions without blocking, if you want to observe before enforcing.

---

## What makes it different

|  | **Permit0** | Microsoft AGT | Lakera / Guardrails | Langfuse / Helicone |
| --- | --- | --- | --- | --- |
| Category | Action governance | Action governance | Prompt governance | LLM observability |
| Governs | Agent actions | Agent actions | LLM text | After-the-fact |
| Public action vocabulary | ✅ 22 domains, 159 verbs | ❌ empty | ❌ | ❌ |
| Default risk policies | ✅ shipped per action (calibrated) | ❌ DSL only | ❌ | ❌ |
| Tool normalization | ✅ via YAML packs | ❌ | ❌ | ❌ |
| Session-aware | ✅ cross-call pattern detection | ❌ | ❌ | ⚠️ passive |
| Deterministic | ✅ sub-ms | ✅ | ❌ | n/a |
| Signed audit | ✅ ed25519 hash chain | ⚠️ logs only | ❌ | ⚠️ unsigned |

> Permit0 publishes the canonical action vocabulary first — `gmail.send`, `outlook.send`, and any future SMTP wrapper all resolve to `email.send`, so one risk rule covers every tool that ever does that thing. The vocabulary is the moat. The shipped risk defaults mean you get a working policy on install. The packs are how the community fills in the long tail.

---

## What is the taxonomy?

The taxonomy is the canonical, append-only vocabulary for *what agents do* — `email.send`, `payment.transfer`, `db.delete`, `iam.assign_role`, and so on. Every tool call from every vendor normalizes to one of these verbs. Write one risk rule for `email.send` and it covers Gmail, Outlook, your custom SMTP wrapper, and the SES adapter someone ships next year.

22 domains, 159 verbs are defined today in [`crates/permit0-types/src/taxonomy.rs`](crates/permit0-types/src/taxonomy.rs) and documented at [`docs/taxonomy.md`](docs/taxonomy.md). The engine fails closed on any tool call that doesn't normalize to a covered action — unknown actions queue for human approval, they don't auto-run.

**Today (v0.1):** engine, signed audit, admin UI, CLI, one reference pack (`email`, 16 verbs for Gmail + Outlook), two integrations (Claude Code, OpenClaw).

**Roadmap:** packs for Slack, Notion, Linear, Stripe, Postgres, Bash, GitHub; framework adapters for LangChain, CrewAI, AutoGen, OpenAI Agents; pre-built CLI binaries.

---

## How it works

<details>
<summary><strong>Decision pipeline (click to expand)</strong></summary>

```
Tool call              ┌─────────────────────────────────┐
  (Bash, HTTP,  ────────► │        Permit0 Engine           │
   Stripe, ...)           ├─────────────────────────────────┤
                          │  1. Normalize (YAML pack)       │
                          │  2. Deny / Allow lists          │
                          │  3. Policy cache                │  ──► Allow
                          │  4. Risk scoring (9 × 7)        │  ──► Deny
                          │  5. Session amplification       │  ──► Human
                          │  6. Tier routing                │      review
                          │     Minimal/Low → Allow         │      (allow /
                          │     Medium      → LLM review or │       deny)
                          │                   human review  │
                          │     High        → Human review  │
                          │     Critical    → Deny          │
                          │  7. LLM reviewer (optional)     │
                          │       → Deny, or                │
                          │       → Escalate to human       │
                          │  8. Signed audit (ed25519)      │
                          └─────────────────────────────────┘
```

The deterministic path (steps 1–6, 8) runs in-process, sub-millisecond, no network calls. Two identical inputs always produce identical outputs.

**Risk dimensions:** 9 flags (`DESTRUCTION`, `PRIVILEGE`, `FINANCIAL`, `EXPOSURE`, `EXECUTION`, `MUTATION`, `OUTBOUND`, `GOVERNANCE`, `PHYSICAL`) × 7 amplifiers (`destination`, `sensitivity`, `scope`, `amount`, `session`, `irreversibility`, `boundary`) → 6-step hybrid scorer → `score ∈ [0, 100]` → tier → decision.

</details>

### Trust asymmetry — why the LLM reviewer can deny but not allow

Permit0 treats LLM reviewers as a **filter, not an authority.** The reviewer can narrow the decision space — flagging an ambiguous action as obviously unsafe — but it cannot expand it. Only policy or a human can grant permission for a medium-risk action.

This preserves the determinism guarantee. The LLM is allowed to be fallible in one direction: false negatives still escalate to humans. Never in the other: no false positives that silently approve unsafe actions. For regulated environments, disable the LLM reviewer entirely — every medium-risk action routes straight to human review.

---

## FAQ

**1. Why not OPA or Cedar?** Policy DSLs, not action engines. They don't intercept, normalize, or score — you'd build Permit0 on top of them.

**2. Why not Microsoft AGT?** Right category, ships empty. Permit0 ships the taxonomy, risk defaults, and session scoring on install — and one working reference pack so you can read real YAML when you write your own.

**3. Does this add latency to every agent call?** The deterministic hot path runs in-process, sub-millisecond, no network calls — cached decisions are microseconds. The LLM reviewer is only invoked on genuinely ambiguous medium-risk actions, never on the default path. Your agent's own LLM call is ~1000× slower than Permit0's evaluation.

**4. What happens to a tool or action I haven't registered?** Unknown actions fail closed — they route to human approval rather than auto-allow. You can add a pack in an afternoon of YAML.

**5. Can I run it fully offline / air-gapped?** Yes. Default install uses SQLite and in-memory storage, no external dependencies. The LLM reviewer is optional — disable it in regulated environments where every medium-risk decision must go to a human.

**6. Why is only the email pack shipped?** Phase 1 focus: prove the engine end-to-end on one domain that everyone has (their inbox), with two channels (Outlook + Gmail), through a real agent host (Claude Code). The taxonomy is the moat; the packs are linear work the community can parallelize. Yours next.

---

## Known limitations

- **Text-only attacks — out of scope.** If the attack gets the agent to produce harmful output without calling a tool (bad advice, fabricated instructions, malicious links in rendered text), there's no action to intercept. Different problem, different layer — pair Permit0 with a content filter on the output side.
- **Actions that skip your hook.** Subprocesses that make their own network calls, tools that bypass your agent framework, anything that doesn't flow through `permit0 hook` or the gateway — Permit0 can't see them. Wrap at the outermost boundary.
- **Tools with no pack.** Fail-closed protects you, but actions for unpacked domains pile up in the human review queue until a pack exists. Fine for week one, annoying by week four — write the pack or open a request.
- **No pre-built binaries yet.** Today you build from source (Rust 1.85+). Release CI is on the roadmap.

---

## Write your own pack

A pack is YAML that maps a tool's native calls onto the canonical taxonomy. Risk defaults are inherited from the taxonomy action; override them only if the tool behaves differently in your context.

```yaml
# packs/community/notion/normalizers/archive.yaml
permit0_pack: "community/notion"
id: "notion:pages_archive"
priority: 105

match:
  tool: notion.pages.archive

normalize:
  action_type: "doc.archive"
  domain: "doc"
  verb: "archive"
  channel: "notion"
  entities:
    page_id: { from: "page_id", type: "string" }
```

The full structure (normalizers + risk rules + tests + `pack.yaml`) is in [`packs/_template/`](packs/_template/) — copy it, fill it in, run `permit0 pack validate` and `permit0 pack test`, submit a PR. The email pack at [`packs/permit0/email/`](packs/permit0/email/) is the reference implementation.

---

## Contributing

Good first PRs:

- Write a pack for a tool we don't cover (Slack, Notion, Linear, Stripe, Postgres, Bash, browser)
- Sharpen an existing normalizer's precision (entity extraction, scope detection)
- Open an issue with a tool surface that breaks normalization

Dev setup, branch conventions, and PR review bar live in [`CONTRIBUTING.md`](CONTRIBUTING.md). (Coming with v0.1 — file an issue if you want to start before it lands and I'll walk you through.)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
