"""Smoke tests for the guard decorator. Requires a running permit0 daemon
on http://localhost:9090 with the email pack loaded.

Skip these tests if the daemon isn't reachable.
"""
import os
import pytest
import httpx

import permit0


def _daemon_up() -> bool:
    url = os.environ.get("PERMIT0_URL", "http://localhost:9090")
    try:
        return httpx.get(f"{url}/api/v1/health", timeout=1).status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _daemon_up(), reason="permit0 daemon not running")


def test_clean_send_is_allowed():
    @permit0.guard("email.send")
    def send(*, to, subject, body):
        return f"sent to {to}"

    result = send(to="bob@example.com", subject="hi", body="ok")
    assert result == "sent to bob@example.com"


def test_credential_in_body_is_denied():
    @permit0.guard("email.send")
    def send(*, to, subject, body):
        pytest.fail("should not be called — permit0 should deny")

    # Use a unique body string to avoid PolicyCache hits from prior runs;
    # otherwise tier/score would be None (cache replays permission only).
    import uuid
    body = f"password is hunter2 {uuid.uuid4().hex}"
    with pytest.raises(permit0.Denied) as exc:
        send(to="bob@external.com", subject="creds", body=body)

    decision = exc.value.decision
    assert decision.permission == "deny"
    assert decision.tier == "CRITICAL"
    assert decision.blocked is True


def test_action_type_derived_from_function_name():
    @permit0.guard()
    def email_send(*, to, subject, body):
        return "sent"

    assert email_send.__permit0_action__ == "email.send"
    assert email_send(to="bob@example.com", subject="hi", body="ok") == "sent"


def test_action_type_derivation_keeps_underscores_in_verb():
    @permit0.guard()
    def email_create_mailbox(*, name):
        return f"created {name}"

    assert email_create_mailbox.__permit0_action__ == "email.create_mailbox"
    assert email_create_mailbox(name="Receipts") == "created Receipts"


def test_undecidable_function_name_raises_at_decoration_time():
    with pytest.raises(ValueError, match="domain.verb"):
        @permit0.guard()
        def sendemail(to, subject, body):
            pass


def test_lower_level_check_action():
    decision = permit0.check_action(
        "email.send",
        {"to": "bob@example.com", "subject": "hi", "body": "ok"},
    )
    assert decision.allowed
    assert decision.action_type == "email.send"
    assert decision.channel == "app"


def test_custom_entities_mapper():
    """If a function's arg names don't match risk rule entity names, override via `entities=`."""
    @permit0.guard(
        "email.send",
        entities=lambda recipient, msg, **_: {"to": recipient, "subject": "X", "body": msg},
    )
    def my_send(recipient, msg):
        return "sent"

    assert my_send("bob@example.com", "hello") == "sent"
