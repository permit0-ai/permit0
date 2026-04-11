#!/usr/bin/env python3
"""
Demo 2 — Card Testing Detection
================================
Simulates a compromised AI agent rapid-firing micro-charges against
distinct customers to probe for valid card numbers (a "card testing" attack).

permit0 detects the pattern via session-aware scoring and blocks the third
attempt. The full decision trail is exported as a signed JSONL audit bundle
that can be independently verified.

Run:
    cd crates/permit0-py && source .venv/bin/activate
    python ../../demos/demo2_card_testing.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

# Resolve packs path relative to this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
PACKS_DIR = os.path.join(PROJECT_ROOT, "packs")

import permit0  # type: ignore

CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
RESET = "\033[0m"


def banner(text: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 60}{RESET}\n")


def status(label: str, value: str, color: str = GREEN) -> None:
    print(f"  {label:.<36} {color}{value}{RESET}")


def main() -> None:
    banner("Demo 2: Card Testing Detection")

    # ── 1. Build engine with audit ──
    print(f"{BOLD}Step 1:{RESET} Build audited engine from packs/stripe")
    audit = permit0.AuditBundle()
    builder = permit0.EngineBuilder()

    # Load stripe normalizers
    norm_dir = os.path.join(PACKS_DIR, "stripe", "normalizers")
    for fname in sorted(os.listdir(norm_dir)):
        if fname.endswith(".yaml"):
            with open(os.path.join(norm_dir, fname)) as f:
                builder.install_normalizer_yaml(f.read())

    # Load stripe risk rules
    rule_dir = os.path.join(PACKS_DIR, "stripe", "risk_rules")
    for fname in sorted(os.listdir(rule_dir)):
        if fname.endswith(".yaml"):
            with open(os.path.join(rule_dir, fname)) as f:
                builder.install_risk_rule_yaml(f.read())

    builder.with_audit(audit)
    engine = builder.build()
    status("Engine built", "OK")
    status("Audit public key", audit.public_key[:16] + "...")

    # ── 2. Open session ──
    print(f"\n{BOLD}Step 2:{RESET} Open agent session")
    session = permit0.Session("checkout-agent-7f3a")
    status("Session ID", session.session_id)

    # ── 3. Simulate micro-charges ──
    banner("Simulating compromised agent — rapid micro-charges")

    charges = [
        {"amount": 50, "currency": "usd", "customer": "cus_alice_001"},
        {"amount": 75, "currency": "usd", "customer": "cus_bob_002"},
        {"amount": 100, "currency": "usd", "customer": "cus_carol_003"},
        {"amount": 25, "currency": "usd", "customer": "cus_dave_004"},
        {"amount": 50, "currency": "usd", "customer": "cus_eve_005"},
    ]

    for i, charge in enumerate(charges, 1):
        print(f"\n{BOLD}  Charge #{i}:{RESET} ${charge['amount']/100:.2f} → {charge['customer']}")

        result = engine.check_with_session(
            session,
            "http",
            {
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": charge,
            },
        )

        perm = result.permission
        if perm == permit0.Permission.Allow:
            color = GREEN
            icon = "✓"
        elif perm == permit0.Permission.Human:
            color = YELLOW
            icon = "?"
        else:
            color = RED
            icon = "✗"

        status(f"  Permission", f"{icon} {perm}", color)
        status(f"  Source", result.source)
        if result.risk_score:
            status(f"  Risk tier", str(result.risk_score.tier))
            status(f"  Risk score", f"{result.risk_score.score}/100")
            if result.risk_score.blocked:
                status(f"  BLOCKED", result.risk_score.block_reason or "session block rule", RED)

        if perm == permit0.Permission.Deny and result.risk_score and result.risk_score.blocked:
            print(f"\n  {RED}{BOLD}⚠ Agent blocked — card testing pattern detected!{RESET}")
            print(f"  {RED}  {session.len} actions in session, pattern: rapid micro-charges")
            print(f"  {RED}  to {i} distinct customers{RESET}")
            break

    # ── 4. Export signed audit bundle ──
    banner("Exporting signed audit bundle")

    audit_path = os.path.join(tempfile.gettempdir(), "demo2_audit.jsonl")
    audit.export_jsonl(audit_path)
    status("Audit entries", str(audit.entry_count))
    status("Exported to", audit_path)

    # Show a sample entry
    with open(audit_path) as f:
        lines = f.readlines()
    if lines:
        entry = json.loads(lines[0])
        norm = entry.get("norm_action", {})
        at = norm.get("action_type", {})
        action_str = f"{at.get('domain','?')}.{at.get('verb','?')}" if isinstance(at, dict) else str(at)
        print(f"\n  {BOLD}Sample audit entry:{RESET}")
        print(f"    seq:        {entry.get('sequence', '?')}")
        print(f"    action:     {action_str}")
        print(f"    decision:   {entry.get('decision', '?')}")
        print(f"    channel:    {norm.get('channel', '?')}")
        print(f"    hash:       {entry.get('entry_hash', '?')[:32]}...")
        print(f"    signature:  {entry.get('signature', '?')[:32]}...")

    # ── 5. Verify audit chain ──
    banner("Independent audit verification")

    valid, count, reason = permit0.AuditBundle.verify_jsonl(audit_path, audit.public_key)
    if valid:
        status("Chain integrity", f"VALID ({count} entries verified)", GREEN)
        status("Signature check", "ALL SIGNATURES VALID", GREEN)
    else:
        status("Chain integrity", f"FAILED at entry {count}", RED)
        status("Reason", reason or "unknown", RED)

    print(f"\n{BOLD}{GREEN}Demo complete.{RESET} Audit bundle at: {audit_path}")
    print(f"Verify independently: permit0.AuditBundle.verify_jsonl('{audit_path}', '{audit.public_key[:16]}...')\n")


if __name__ == "__main__":
    main()
