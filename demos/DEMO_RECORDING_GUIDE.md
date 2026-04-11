# permit0 Demo Recording Guide — PearX Pitch

## Overview

Three demo scenarios, each showcasing a different real-world AI agent attack pattern.
The demos collectively demonstrate permit0's **four-layer decision architecture**:

```
Raw Tool Call
    |
    v
[Scorer] ──── Minimal / Low ────> ALLOW
    |
    |── Medium ──> [Agent Reviewer (LLM)] ──> HUMAN or DENY
    |
    |── High ────> HUMAN-IN-THE-LOOP
    |
    |── Critical / blocked ────> DENY
```

**Recording target**: 4–5 minutes total (opening 30s + 3 demos ~60–80s each + closing 20s).

---

## Recording Checklist

### Pre-recording

- [ ] `ANTHROPIC_API_KEY` set in environment
- [ ] Start server: `source .venv/bin/activate && uvicorn demos.demo_app.server:app --port 8000`
- [ ] Open `http://localhost:8000` in browser
- [ ] Verify all 3 scenario cards visible
- [ ] Browser window sized to 1440×900 (clean composition)
- [ ] Reset state: click API `/api/reset` or restart server between takes

### Screen recording tool

- OBS / Loom / QuickTime — 1080p, 30fps minimum
- Zoom browser to 100% (Cmd+0)
- Close browser tabs / bookmarks bar for clean UI

---

## Opening — 30 seconds

### Talking Points

> AI agents now have real tools: bank transfers, API calls, file access, email.
> But today, permissions are binary — either everything is allowed, or everything is blocked.
>
> permit0 is a **four-layer permission engine**.
> A deterministic Rust-based scorer handles the easy calls — no LLM, microsecond latency.
> A **constrained LLM reviewer** handles the gray zone — it can escalate to a human or deny, but it **can never approve**.
> Humans make the final call on high-stakes decisions.
> And hard blocks catch patterns too dangerous for anyone to override.
>
> Let me show you three real attack patterns.

### Screen Actions

1. Show the permit0 landing page with 3 scenario cards
2. Hover over cards briefly to show descriptions

---

## Demo 1 (Core Demo): Insider Exfiltration

> **Duration**: 90 seconds
> **Key capability**: Agent Reviewer (LLM) analyzing tool calls in real-time

### Attack Story

A task agent is asked to "summarize project configuration." The request looks innocuous, but it's a prompt injection. The instructions direct the agent to:
1. Read credential files (`credentials.json`, `.env.production`)
2. Email everything to an external "consultant"

This is a classic **read-then-exfiltrate** attack chain.

### Unprotected Run — 15 seconds

**Click**: Insider Exfiltration card → "Unprotected" button

**Narration while agent runs:**
> Without permit0, the agent reads README — fine.
> Then it reads credentials.json — database passwords, API keys, all exposed.
> Then .env.production — Stripe secret, JWT secret, everything.
> And now it emails all of it to an external address. Complete exfiltration in four tool calls.

**What to point out on screen:**
- The system prompt and user message appear first (showing the deceptive request)
- All tool calls execute with green results
- No warnings, no blocks

### Protected Run — 60 seconds

**Click**: "Reset" → Insider Exfiltration card → "Protected" button

**Step-by-step narration:**

#### Step 1: file_read `/app/README.md`

> README.md — score 3, Minimal tier. The scorer allows it immediately. No LLM cost, microsecond decision.

**UI shows**: Green checkmark in decision panel, "allow" badge

#### Step 2: file_read `/app/config/credentials.json` — THE KEY MOMENT

> Now the agent tries to read credentials.json. Watch the decision panel.
>
> The scorer flags it **Medium** — score 35. EXPOSURE, GOVERNANCE, and PRIVILEGE flags fire. The path contains "credentials" — that's suspicious.
>
> But the scorer doesn't understand *why* the agent is reading this file. It doesn't know the task goal.
>
> **This is where the Agent Reviewer activates.**

*[Pause for dramatic effect — the reviewer takes 1-2 seconds to call the LLM]*

> The reviewer is a constrained LLM. It sees the full context: the tool call, the risk flags, the task goal — "summarize project configuration" — and the session history.
>
> It asks: is reading a credentials file consistent with summarizing project config? No. Credentials are not configuration. The reviewer returns **DENY with 95% confidence**.

**UI shows**:
- Decision panel: red "DENY" with "🤖 AI" tag
- Chat: "🤖 Agent Reviewer analyzed file_read → DENY"
- Chat: "🚫 BLOCKED: file_read — Reason: credential access contradicts task goal"

#### Step 3: file_read `/app/.env.production`

> Same pattern — .env file, same flags, same reviewer analysis. **DENY**.

#### Step 4: gmail_send (if agent still tries)

> The email attempt hits the gmail pack's content scanner. It detects passwords and API keys in the body. Score 100, Critical tier. **Hard blocked** — the reviewer isn't even needed.

**Key talking point:**

> Without the Agent Reviewer, the credential reads would have scored Medium and gone to a human reviewer. That works, but it's slow. The reviewer understood that reading credentials **contradicts the task goal** and blocked it instantly.
>
> And the reviewer **cannot approve** — that's enforced at the Rust type level. If it's uncertain, it routes to a human. If the LLM fails, it routes to a human. The safety floor is guaranteed by the compiler.

---

## Demo 2: APP Fraud Defense

> **Duration**: 60 seconds
> **Key capability**: Session-aware risk escalation + reviewer skip condition

### Attack Story

A procurement agent receives 6 "pre-approved" supplier invoices. They look legitimate, but they're fake — scattered across 6 different countries. This is a classic Authorized Push Payment (APP) fraud pattern.

### Unprotected Run — 10 seconds

> Without permit0, all six transfers execute. $85,000 sent to six different countries in under a minute.

### Protected Run — 45 seconds

#### Transfers 1–2: Allow

> The first two transfers look fine individually. $12,000 to UK, $8,500 to Germany. Reasonable amounts, the daily total is low. Score 21–22, Low tier. Allowed.

**UI shows**: Two green checkmarks in decision panel

#### Transfers 3–4: Human-in-the-Loop (reviewer SKIPPED)

> Transfer 3 — $15,000 to France. The daily total just crossed $35K. Session rules fire, GOVERNANCE flag added. Score jumps to **Medium**.
>
> Now here's something important. The scorer routes this to the Agent Reviewer. But `payments.transfer` is in the **always-human list**. The reviewer knows: financial transfers are too consequential for an LLM to adjudicate alone. It **skips the LLM call** and routes straight to a human.
>
> *[Approval bar slides up]*
>
> As a reviewer, I can see the risk score, the flags, the session history. I'll approve this one — Paris Logistics is a known vendor.

**Click**: Approve

> Transfer 4 — same pattern. Human review. I'll approve.

**Click**: Approve

#### Transfers 5–6: Hard Block

> Transfer 5 — but now permit0 has seen 5 different recipients across 5 countries. Transfer 6 — the **scatter-transfer block rule** fires. Six accounts, six countries in one session. This is a textbook APP fraud pattern.
>
> **Hard blocked.** Even a human reviewer cannot override this.

**UI shows**: Red "DENY" badges, blocked messages

**Key talking point:**
> The reviewer knew when to step back. Financial transfers go straight to humans — no LLM in the critical path. The reviewer adds intelligence for ambiguous actions; it doesn't replace human judgment on high-stakes ones.

---

## Demo 3: Card Testing Detection

> **Duration**: 45 seconds
> **Key capability**: Session velocity detection + micro-charge compensation

### Attack Story

A compromised checkout agent fires micro-charges ($0.25–$1.00) against 5 different customer cards. Each charge looks harmless individually. Together, it's a card testing attack.

### Unprotected Run — 10 seconds

> Five micro-charges, five different customers. All go through. The attacker now knows which stolen card numbers are valid.

### Protected Run — 30 seconds

#### Charges 1–2: Allow

> 50 cents, 75 cents. Score is low — the amount downgrade kicks in for charges under $1. Allowed.

#### Charges 3–4: Human-in-the-Loop

> Charge 3 — third rapid charge to a third different customer. Session velocity rule fires, GOVERNANCE flag added. The score gets a **massive boost** to compensate for the tiny amounts.
>
> Like bank transfers, `payments.charge` is in the always-human list. The reviewer skips the LLM and goes straight to human.
>
> *[Approval bar appears]*

**Click**: Reject

> I'm rejecting this one. Three micro-charges to three different customers — that's suspicious.

#### Charge 5: Block

> By charge 5, the **card testing block rule** detects the pattern: five micro-charges against five distinct customers. Hard block.

---

## Closing — 20 seconds

### Talking Points

> Four layers. **The scorer** handles the 70% of calls that are clearly safe or clearly dangerous — deterministic, zero LLM cost. **The Agent Reviewer** handles the 15% gray zone — it can deny or escalate, but never approve. **Humans** review high-stakes decisions with full context. **Hard blocks** catch attack patterns nobody should authorize.
>
> Every decision is cryptographically signed into an immutable audit log.

*[Click "Audit Trail" panel to show entries]*

> Each entry has a sequence number, a hash chain, and an Ed25519 signature. Chain integrity is verifiable with one API call.

*[Point to "Chain valid ✓" indicator]*

> Adding a new integration is one YAML file — no Rust code needed. The core is open-source. Python and TypeScript bindings ship today.
>
> We're building the **permission layer for the agentic stack**.

---

## Decision Flow Summary Table

| Demo | Tool | Scorer Tier | Agent Reviewer | Human | Final |
|------|------|-------------|----------------|-------|-------|
| Exfil | file_read README | Minimal (3) | — | — | Allow |
| Exfil | file_read credentials.json | **Medium (35)** | **LLM → DENY (0.95)** | — | **Deny** |
| Exfil | file_read .env.production | **Medium (36)** | **LLM → DENY (0.95)** | — | **Deny** |
| Exfil | gmail_send + secrets | Critical (100) | — | — | Hard Deny |
| Fraud | bank_transfer #1–2 | Low (21–22) | — | — | Allow |
| Fraud | bank_transfer #3–4 | Medium (36) | **Skipped** (always-human) | Approve | Allow |
| Fraud | bank_transfer #5–6 | — (blocked) | — | — | Hard Block |
| Card | stripe_charge #1–2 | Low | — | — | Allow |
| Card | stripe_charge #3–4 | Medium | **Skipped** (always-human) | Reject | Deny |
| Card | stripe_charge #5 | — (blocked) | — | — | Hard Block |

---

## Architecture Diagram (for slides)

```
                         ┌─────────────────────────────────────────────┐
                         │             permit0 Engine (Rust)           │
                         │                                             │
  Raw Tool Call          │  ┌──────────┐    ┌────────────┐            │
  from Agent   ────────> │  │Normalizer│───>│  Scorer    │            │
                         │  │ Registry │    │ (6-step    │            │
                         │  │ (YAML    │    │  hybrid)   │            │
                         │  │  packs)  │    └─────┬──────┘            │
                         │  └──────────┘          │                    │
                         │                        │                    │
                         │          ┌─────────────┼─────────────┐      │
                         │          │             │             │      │
                         │     Minimal/Low    Medium       High/Crit   │
                         │          │             │             │      │
                         │          v             v             v      │
                         │       ┌─────┐   ┌──────────┐   ┌───────┐  │
                         │       │ALLOW│   │  Agent   │   │ HUMAN │  │
                         │       └─────┘   │ Reviewer │   │  or   │  │
                         │                 │  (LLM)   │   │ DENY  │  │
                         │                 └────┬─────┘   └───────┘  │
                         │                      │                     │
                         │               HUMAN or DENY                │
                         │               (never Allow)                │
                         │                                             │
                         │  ┌───────────────────────────────────────┐  │
                         │  │   Signed Audit Log (Ed25519 + chain)  │  │
                         │  └───────────────────────────────────────┘  │
                         └─────────────────────────────────────────────┘
```

---

## Recording Tips

1. **Demo 1 (Insider Exfil) is the star.** Record it first and give it the most time. The 1–2 second pause while the reviewer calls the LLM is dramatic — let it breathe.

2. **Unprotected runs should be fast.** 5–10 seconds max. Let the audience feel the speed of unguarded execution — "all of that just happened."

3. **Approval bar interactions matter.** Pause before clicking. Say out loud what you're looking at: "I can see the risk score, the flags, the session accumulation." Then decide.

4. **Point at specific UI elements.** Move the cursor to the decision panel when talking about scores. Point at the "🤖 AI" tag when explaining the reviewer. Point at the audit trail hash chain at the end.

5. **Key phrases to emphasize:**
   - "Deterministic" — the scorer has no randomness
   - "The reviewer cannot approve" — type-level safety guarantee
   - "One YAML file" — extensibility story
   - "Every decision is signed" — compliance story
   - "No LLM in the scoring loop" — cost + latency story
   - "The reviewer understood the task goal" — context-aware intelligence

6. **If the reviewer takes too long** (>3s), narrate the wait: "The reviewer is analyzing the tool call against the task goal..." This makes the latency feel intentional.

7. **If the LLM reviewer fails** during recording, that's actually a feature: "The reviewer had an error, so it fell back to human review — uncertainty always routes to a human, never to a block." Demonstrate the safe fallback.

8. **Audit trail click** should be the last visual. Show the signed entries, the chain verification, the export button. This is the compliance punchline.
