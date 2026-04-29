"""permit0 Python SDK — guard your functions with norm-action-level policies.

Quick start::

    import permit0

    @permit0.guard("email.send")
    def send_via_smtp(to, subject, body):
        smtp.send(...)

    # Or let permit0 derive the action from the function name:
    @permit0.guard()
    def email_send(to, subject, body):  # → action_type "email.send"
        ...

Function arguments are automatically forwarded to permit0 as entities (by name).
On a non-allow decision, ``permit0.Denied`` is raised.

Configuration:

* ``PERMIT0_URL`` — daemon URL (default ``http://localhost:9090``)
"""

from permit0._client import (
    Decision,
    Denied,
    check_action,
    guard,
)

__all__ = ["Decision", "Denied", "check_action", "guard"]
__version__ = "0.1.0"
