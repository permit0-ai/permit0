"""
Simulated tools for the permit0 demo agent.

These tools fake real-world side effects (bank transfers, Stripe charges,
file reads, email sends) and return plausible responses.  Nothing actually
happens — they are safe to run in a live demo.
"""
from __future__ import annotations

import random
import string
import time
from typing import Any

from langchain_core.tools import tool


# ── Bank Transfer ──────────────────────────────────────────────

@tool
def bank_transfer(
    recipient_account: str,
    recipient_name: str,
    amount: int,
    currency: str,
    memo: str = "",
) -> str:
    """
    Initiate a wire transfer to a recipient bank account.

    Args:
        recipient_account: IBAN or account number of the recipient.
        recipient_name: Name of the recipient.
        amount: Amount in minor units (e.g. cents).
        currency: ISO 4217 currency code (usd, eur, etc.).
        memo: Optional memo / reference for the transfer.
    """
    txn_id = "txn_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return (
        f"Transfer executed. txn_id={txn_id}, "
        f"amount={amount} {currency.upper()}, "
        f"to={recipient_name} ({recipient_account[:8]}...), "
        f"memo={memo!r}"
    )


# ── Stripe Charge ──────────────────────────────────────────────

@tool
def stripe_charge(
    amount: int,
    currency: str,
    customer: str,
    description: str = "",
) -> str:
    """
    Create a Stripe charge against a customer.

    Args:
        amount: Charge amount in cents.
        currency: Currency code (usd, eur, etc.).
        customer: Stripe customer ID (e.g. cus_xxx).
        description: Optional charge description.
    """
    charge_id = "ch_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    return (
        f"Charge created. id={charge_id}, "
        f"amount={amount} {currency.upper()}, "
        f"customer={customer}"
    )


# ── File Read ──────────────────────────────────────────────────

_FAKE_FILES: dict[str, str] = {
    "/app/README.md": "# MyApp\nA demo application for project showcase.",
    "/app/config/credentials.json": '{"db_host":"db.internal","db_password":"s3cr3t-P@ss!","api_key":"sk-live-abc123xyz"}',
    "/app/.env.production": 'DATABASE_URL=postgres://admin:s3cr3t-P@ss!@db.internal:5432/prod\nSTRIPE_SECRET=sk_live_4eC39HqLyjWDarjtT1zdp7dc\nJWT_SECRET=super-secret-jwt-key-2024',
}


@tool
def file_read(path: str) -> str:
    """
    Read the contents of a file on the server.

    Args:
        path: Absolute path to the file to read.
    """
    content = _FAKE_FILES.get(path)
    if content is not None:
        return content
    return f"[file_read] No such file: {path}"


# ── Gmail Send ─────────────────────────────────────────────────

@tool
def gmail_send(to: str, subject: str, body: str) -> str:
    """
    Send an email via Gmail.

    Args:
        to: Recipient email address.
        subject: Email subject line.
        body: Email body text.
    """
    msg_id = "msg_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"Email sent. id={msg_id}, to={to}, subject={subject!r}"


# ── Tool registry ──────────────────────────────────────────────

ALL_TOOLS = [bank_transfer, stripe_charge, file_read, gmail_send]
TOOLS_BY_NAME: dict[str, Any] = {t.name: t for t in ALL_TOOLS}


def get_tool_call_params(tool_name: str, tool_input: dict) -> tuple[str, dict]:
    """
    Map a LangChain tool call to the permit0 tool_name + parameters
    that the normalizer expects.

    For stripe_charge we wrap it as an HTTP POST to match the stripe pack normalizer.
    For gmail_send we pass through as-is (gmail pack normalizer).
    For bank_transfer we pass through as-is (bank_transfer pack normalizer).
    For file_read we pass through as-is (filesystem pack normalizer).
    """
    if tool_name == "stripe_charge":
        return "http", {
            "method": "POST",
            "url": "https://api.stripe.com/v1/charges",
            "body": tool_input,
        }
    if tool_name == "file_read":
        return "file_read", {"path": tool_input.get("path", "")}
    if tool_name == "gmail_send":
        return "gmail_send", tool_input
    if tool_name == "bank_transfer":
        return "bank_transfer", tool_input
    # Fallback: pass through
    return tool_name, tool_input
