# TODOs

## Pack signing infrastructure
**What:** Design pack signing scheme (key issuance, signature format, verify path).
**Why:** Phase 2's `verified` trust tier requires it. Today the `pack.yaml` `signature` field is reserved-but-empty. Without signing, `trust_tier: verified` is self-attestation, which is a footgun.
**Pros:** Enables verified tier; closes the self-attestation gap; aligns with supply-chain best practice.
**Cons:** Cryptographic design takes time; needs an explicit threat model.
**Context:** During the pack-taxonomy refactor (May 2026), the eng review's outside voice flagged tier-as-metadata as a self-attestation footgun. We deferred the `verified` and `experimental` tiers and reserved `signature`, `provenance`, `content_hash` as optional fields in `pack_format: 2`. This TODO is to fill in the spec and implementation when the federated registry conversation starts.
**Depends on:** Federated registry direction (Phase 2 trigger conditions in the discussion doc, section 12).

## Taxonomy version-resolver semantics
**What:** Spec the semantics for `taxonomy: "1.x"` collisions — what happens when two installed packs declare different minor ranges (e.g., one wants `1.5`, another wants `1.7`).
**Why:** `pack_format: 2` introduces the `taxonomy:` compatibility field but the resolver behavior is unspecified.
**Pros:** Avoids a Phase 2 surprise when multiple community packs are installed simultaneously.
**Cons:** Premature with a single pack today.
**Context:** Eng review's outside voice flagged this gap. Today there is exactly one pack (`permit0/email`), so the question is theoretical. Becomes load-bearing when `~/.permit0/packs/` has multiple packs.
**Depends on:** Multiple packs existing concurrently.

## First community pack walkthrough
**What:** Build the first community pack end-to-end (Slack, Stripe, GitHub, or Notion) to validate the contribution flow.
**Why:** The contribution flow (`permit0 pack new <author>/<name>`, scaffolding, validator, calibration, PR template) is an untested hypothesis. Plan open Q5.
**Pros:** Validates the UX; surfaces friction; produces a second pack as ground truth for cross-pack design questions (taxonomy version resolver, calibration discovery, etc.).
**Cons:** Picks a vendor; commits to scope; expands from "refactor" to "new feature."
**Context:** Plan section 15 lists Slack, Stripe, GitHub, Notion as candidates. Slack is probably the lowest-risk choice (read-heavy, well-documented MCP, low blast-radius compared to Stripe).
**Depends on:** Refactor PRs 1–5 landing.
