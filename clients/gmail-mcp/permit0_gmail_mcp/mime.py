"""Build base64url-encoded RFC 2822 messages for Gmail's send/draft endpoints.

Gmail's ``messages.send`` / ``drafts.create`` take a ``raw`` field which is
the urlsafe-base64-encoded MIME message. Reply/forward semantics are
expressed via ``In-Reply-To`` and ``References`` headers + ``threadId``.
"""
import base64
from email.mime.text import MIMEText


def build_raw(
    *,
    to: str = "",
    subject: str = "",
    body: str = "",
    cc: str = "",
    bcc: str = "",
    in_reply_to: str = "",
    references: str = "",
) -> str:
    """Return urlsafe-base64-encoded RFC 2822 message ready for the
    ``raw`` field of Gmail's messages.send / drafts.create."""
    msg = MIMEText(body, "plain", "utf-8")
    if to:
        msg["To"] = to
    if cc:
        msg["Cc"] = cc
    if bcc:
        msg["Bcc"] = bcc
    if subject:
        msg["Subject"] = subject
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        # Per RFC 5322, References should chain prior message-ids.
        msg["References"] = references or in_reply_to
    return base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
