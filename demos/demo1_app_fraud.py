#!/usr/bin/env python3
"""
Demo 1 — Authorized Push Payment (APP) Fraud Defense
=====================================================
Simulates a social-engineered AI agent that has been tricked into sending
wire transfers to multiple fraudulent "supplier" accounts. The agent
believes each transfer is a legitimate invoice payment.

permit0 detects the scatter-transfer pattern (5+ distinct recipients
within 60 minutes) and blocks the attack before the 5th payment clears.

Run:
    cd crates/permit0-py && source .venv/bin/activate
    python ../../demos/demo1_app_fraud.py
"""
from __future__ import annotations

import json
import os
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
PACKS_DIR = os.path.join(PROJECT_ROOT, "packs")

import permit0  # type: ignore

CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def banner(text: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 60}{RESET}\n")


def status(label: str, value: str, color: str = GREEN) -> None:
    print(f"  {label:.<40} {color}{value}{RESET}")


def main() -> None:
    banner("Demo 1: APP Fraud Defense (Scatter Transfer)")

    # ── 1. Build engine with bank_transfer pack + audit ──
    print(f"{BOLD}Step 1:{RESET} Build audited engine from packs/")
    audit = permit0.AuditBundle()
    builder = permit0.EngineBuilder()

    # Load all packs (bank_transfer + others)
    for pack_name in sorted(os.listdir(PACKS_DIR)):
        pack_dir = os.path.join(PACKS_DIR, pack_name)
        if not os.path.isdir(pack_dir):
            continue
        norm_dir = os.path.join(pack_dir, "normalizers")
        rule_dir = os.path.join(pack_dir, "risk_rules")
        if os.path.isdir(norm_dir):
            for fname in sorted(os.listdir(norm_dir)):
                if fname.endswith(".yaml"):
                    with open(os.path.join(norm_dir, fname)) as f:
                        builder.install_normalizer_yaml(f.read())
        if os.path.isdir(rule_dir):
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
    session = permit0.Session("procurement-agent-x9k2")
    status("Session ID", session.session_id)

    # ── 3. Simulate the social engineering attack ──
    banner("Simulating social-engineered agent — invoice payments")

    print(f"  {DIM}The agent received fake supplier invoices via email.{RESET}")
    print(f"  {DIM}It believes each is a legitimate payment to a different vendor.{RESET}\n")

    transfers = [
        {
            "recipient_account": "GB82WEST12345698765432",
            "recipient_name": "Acme Supplies Ltd",
            "amount": 12000,
            "currency": "usd",
            "memo": "Invoice #INV-2024-0891",
        },
        {
            "recipient_account": "DE89370400440532013000",
            "recipient_name": "EuroTech GmbH",
            "amount": 8500,
            "currency": "eur",
            "memo": "Invoice #ET-77432",
        },
        {
            "recipient_account": "FR7630006000011234567890189",
            "recipient_name": "Paris Logistics SAS",
            "amount": 15000,
            "currency": "eur",
            "memo": "Invoice #PL-2024-003",
        },
        {
            "recipient_account": "CH9300762011623852957",
            "recipient_name": "Swiss Materials AG",
            "amount": 22000,
            "currency": "chf",
            "memo": "Invoice #SM-8891",
        },
        {
            "recipient_account": "SG6000000000001234567890",
            "recipient_name": "Asia Pacific Trading Pte",
            "amount": 9500,
            "currency": "sgd",
            "memo": "Invoice #APT-2024-112",
        },
        {
            "recipient_account": "AE070331234567890123456",
            "recipient_name": "Gulf Services FZE",
            "amount": 18000,
            "currency": "aed",
            "memo": "Invoice #GS-4401",
        },
    ]

    for i, txn in enumerate(transfers, 1):
        print(
            f"  {BOLD}Transfer #{i}:{RESET} ${txn['amount']:,} {txn['currency'].upper()} "
            f"→ {txn['recipient_name']}"
        )
        print(f"  {DIM}  Account: {txn['recipient_account'][:12]}...  Memo: {txn['memo']}{RESET}")

        result = engine.check_with_session(
            session,
            "bank_transfer",
            txn,
        )

        perm = result.permission
        if perm == permit0.Permission.Allow:
            color, icon = GREEN, "✓"
        elif perm == permit0.Permission.Human:
            color, icon = YELLOW, "?"
        else:
            color, icon = RED, "✗"

        status(f"    Permission", f"{icon} {perm}", color)
        if result.risk_score:
            status(f"    Risk tier", str(result.risk_score.tier))
            status(f"    Risk score", f"{result.risk_score.score}/100")
            if result.risk_score.blocked:
                status(
                    f"    BLOCKED",
                    result.risk_score.block_reason or "session block rule",
                    RED,
                )

        if perm == permit0.Permission.Deny and result.risk_score and result.risk_score.blocked:
            print(
                f"\n  {RED}{BOLD}⚠  Agent blocked — scatter transfer pattern detected!{RESET}"
            )
            print(f"  {RED}  {session.len} actions in session")
            print(f"  {RED}  {i} distinct recipient accounts in under 60 minutes")
            print(f"  {RED}  Total value: ${sum(t['amount'] for t in transfers[:i]):,}{RESET}")
            break
        print()

    # ── 4. Export signed audit bundle ──
    banner("Exporting signed audit bundle")

    audit_path = os.path.join(tempfile.gettempdir(), "demo1_audit.jsonl")
    audit.export_jsonl(audit_path)
    status("Audit entries", str(audit.entry_count))
    status("Exported to", audit_path)

    # Show sample
    with open(audit_path) as f:
        lines = f.readlines()
    if lines:
        last = json.loads(lines[-1])
        norm = last.get("norm_action", {})
        at = norm.get("action_type", {})
        action_str = (
            f"{at.get('domain','?')}.{at.get('verb','?')}"
            if isinstance(at, dict)
            else str(at)
        )
        print(f"\n  {BOLD}Last audit entry (the blocked transfer):{RESET}")
        print(f"    seq:        {last.get('sequence', '?')}")
        print(f"    action:     {action_str}")
        print(f"    decision:   {last.get('decision', '?')}")
        print(f"    hash:       {last.get('entry_hash', '?')[:32]}...")
        print(f"    prev_hash:  {last.get('prev_hash', '?')[:32]}...")
        print(f"    signature:  {last.get('signature', '?')[:32]}...")

    # ── 5. Verify ──
    banner("Independent audit verification")

    valid, count, reason = permit0.AuditBundle.verify_jsonl(audit_path, audit.public_key)
    if valid:
        status("Chain integrity", f"VALID ({count} entries verified)", GREEN)
        status("Signature check", "ALL SIGNATURES VALID", GREEN)
    else:
        status("Chain integrity", f"FAILED at entry {count}", RED)
        status("Reason", reason or "unknown", RED)

    print(f"\n{BOLD}{GREEN}Demo complete.{RESET} Audit bundle at: {audit_path}\n")


if __name__ == "__main__":
    main()
