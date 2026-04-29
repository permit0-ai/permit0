"""MCP server exposing Gmail tools to Claude Code.

Mirrors clients/outlook-mcp/permit0_outlook_mcp/server.py — same 13 tools,
same norm actions, same permit0 gate. Backend differences (Gmail uses
labels + base64url RFC 2822, Outlook uses folders + JSON message objects)
are absorbed here.

Like outlook-mcp, this server does NOT expose set_forwarding or
add_delegate — they are account-takeover vectors and an LLM agent has no
legitimate need for them.

Configuration:
    PERMIT0_URL          — daemon URL (default http://localhost:9090)
    GMAIL_CREDENTIALS    — path to OAuth credentials.json
                           (default ~/.permit0/gmail_credentials.json)
"""
import json

import permit0
from mcp.server.fastmcp import FastMCP

from .gmail import call as gmail
from .mime import build_raw

server = FastMCP("permit0-gmail")

# Channel string sent to permit0 — identifies this backend in audit logs.
# Tagging at the SDK call site (rather than letting it default to "app")
# is what differentiates Gmail from Outlook in the unified email.* IR.
CHANNEL = "gmail"


def guard(action_type: str):
    """Wrapper around permit0.guard that pins channel='gmail' for this server."""
    return permit0.guard(action_type, channel=CHANNEL)


# ── Search / Read ─────────────────────────────────────────────

@server.tool()
@guard("email.search")
def gmail_search(query: str = "", top: int = 10, page_token: str = "") -> str:
    """Search Gmail messages. ``query`` uses Gmail's search syntax
    (e.g. 'from:alice subject:meeting newer_than:7d', see
    https://support.google.com/mail/answer/7190). ``top`` is page size.

    Pagination: response includes ``nextPageToken`` if more results exist;
    pass it as ``page_token`` to fetch the next page."""
    params = {"maxResults": top}
    if query:
        params["q"] = query
    if page_token:
        params["pageToken"] = page_token
    return json.dumps(gmail("GET", "/messages", params=params), indent=2, ensure_ascii=False)


@server.tool()
@guard("email.read")
def gmail_read(message_id: str) -> str:
    """Read full content of one message by id (subject, body, headers, labels)."""
    # format=full returns both headers and the parsed body parts.
    return json.dumps(
        gmail("GET", f"/messages/{message_id}", params={"format": "full"}),
        indent=2,
        ensure_ascii=False,
    )


@server.tool()
@guard("email.read_thread")
def gmail_read_thread(thread_id: str) -> str:
    """Read all messages in a thread (Gmail's native thread concept).
    ``thread_id`` is a Gmail threadId."""
    return json.dumps(
        gmail("GET", f"/threads/{thread_id}", params={"format": "full"}),
        indent=2,
        ensure_ascii=False,
    )


@server.tool()
@guard("email.list_mailboxes")
def gmail_list_mailboxes() -> str:
    """List all Gmail labels (system + user). Labels in Gmail are the
    equivalent of mailboxes / folders in Outlook. Use the returned label
    ids with gmail_move."""
    return json.dumps(gmail("GET", "/labels"), indent=2, ensure_ascii=False)


# ── Draft / Send ──────────────────────────────────────────────

@server.tool()
@guard("email.draft")
def gmail_draft(
    to: str = "",
    subject: str = "",
    body: str = "",
    draft_id: str = "",
    in_reply_to: str = "",
    forward_from: str = "",
    cc: str = "",
    bcc: str = "",
) -> str:
    """Create or modify a draft. Modes (mutually exclusive):
    - default: create a new draft (provide to/subject/body)
    - draft_id: update an existing draft
    - in_reply_to: create as reply (uses original's threadId + headers)
    - forward_from: create as forward (uses original's body as quote)
    """
    thread_id = ""
    references_header = ""

    if in_reply_to:
        # Fetch original to get threadId + Message-ID for proper threading.
        orig = gmail("GET", f"/messages/{in_reply_to}", params={"format": "metadata",
                                                                 "metadataHeaders": "Message-ID,References,Subject"})
        thread_id = orig.get("threadId", "")
        headers = {h["name"].lower(): h["value"]
                   for h in orig.get("payload", {}).get("headers", [])}
        in_reply_to_header = headers.get("message-id", "")
        references_header = headers.get("references", "") or in_reply_to_header
        if not subject:
            orig_subj = headers.get("subject", "")
            subject = orig_subj if orig_subj.lower().startswith("re:") else f"Re: {orig_subj}"
    elif forward_from:
        orig = gmail("GET", f"/messages/{forward_from}", params={"format": "full"})
        thread_id = orig.get("threadId", "")
        # Don't auto-quote the body; that's heavy. Agent can fetch and quote
        # itself if it wants. We just preserve threadId so Gmail groups it.

    raw = build_raw(
        to=to,
        cc=cc,
        bcc=bcc,
        subject=subject,
        body=body,
        in_reply_to=in_reply_to_header if in_reply_to else "",
        references=references_header,
    )
    payload = {"message": {"raw": raw}}
    if thread_id:
        payload["message"]["threadId"] = thread_id

    if draft_id:
        result = gmail("PUT", f"/drafts/{draft_id}", body=payload)
    else:
        result = gmail("POST", "/drafts", body=payload)
    return json.dumps(result, indent=2, ensure_ascii=False)


@server.tool()
def gmail_send(
    to: str = "",
    subject: str = "",
    body: str = "",
    in_reply_to: str = "",
    reply_all: bool = False,
    forward_from: str = "",
    from_draft_id: str = "",
    cc: str = "",
    bcc: str = "",
) -> str:
    """Send email. Modes (mutually exclusive):
    - default: send a new message
    - in_reply_to (+ optional reply_all): reply to a message
    - forward_from (+ to): forward a message
    - from_draft_id: send an existing draft

    Note: when from_draft_id is set, this server fetches the draft's
    to/subject/body BEFORE running the permit0 check, so the policy
    engine sees the actual content (no audit blind spots).
    """
    # Hydrate from draft so permit0 evaluates real content.
    if from_draft_id:
        draft = gmail("GET", f"/drafts/{from_draft_id}", params={"format": "full"})
        msg = draft.get("message", {})
        headers = {h["name"].lower(): h["value"]
                   for h in msg.get("payload", {}).get("headers", [])}
        if not to:
            to = headers.get("to", "")
        if not subject:
            subject = headers.get("subject", "")
        if not body:
            # Body is base64-encoded inside parts; for simplicity grab snippet.
            body = msg.get("snippet", "")

    decision = permit0.check_action(
        "email.send",
        {
            "to": to,
            "subject": subject,
            "body": body,
            "in_reply_to": in_reply_to,
            "reply_all": reply_all,
            "forward_from": forward_from,
            "from_draft_id": from_draft_id,
        },
        channel=CHANNEL,
    )
    if not decision.allowed:
        raise permit0.Denied(decision)

    if from_draft_id:
        result = gmail("POST", f"/drafts/send", body={"id": from_draft_id})
        return json.dumps({"sent": True, "from_draft": from_draft_id}, indent=2, ensure_ascii=False)

    # For reply / forward / new, build a raw RFC 2822 message + send.
    thread_id = ""
    references_header = ""
    in_reply_to_header = ""
    if in_reply_to:
        orig = gmail("GET", f"/messages/{in_reply_to}", params={"format": "metadata",
                                                                 "metadataHeaders": "Message-ID,References,Subject,From,To,Cc"})
        thread_id = orig.get("threadId", "")
        headers = {h["name"].lower(): h["value"]
                   for h in orig.get("payload", {}).get("headers", [])}
        in_reply_to_header = headers.get("message-id", "")
        references_header = headers.get("references", "") or in_reply_to_header
        if not to:
            to = headers.get("from", "")
        if reply_all:
            extra_to = headers.get("to", "")
            if extra_to and extra_to not in to:
                to = f"{to}, {extra_to}"
            if not cc:
                cc = headers.get("cc", "")
        if not subject:
            orig_subj = headers.get("subject", "")
            subject = orig_subj if orig_subj.lower().startswith("re:") else f"Re: {orig_subj}"
    elif forward_from:
        orig = gmail("GET", f"/messages/{forward_from}", params={"format": "metadata",
                                                                  "metadataHeaders": "Subject"})
        thread_id = orig.get("threadId", "")
        headers = {h["name"].lower(): h["value"]
                   for h in orig.get("payload", {}).get("headers", [])}
        if not subject:
            orig_subj = headers.get("subject", "")
            subject = orig_subj if orig_subj.lower().startswith("fwd:") else f"Fwd: {orig_subj}"

    raw = build_raw(
        to=to, cc=cc, bcc=bcc,
        subject=subject, body=body,
        in_reply_to=in_reply_to_header,
        references=references_header,
    )
    send_body = {"raw": raw}
    if thread_id:
        send_body["threadId"] = thread_id
    result = gmail("POST", "/messages/send", body=send_body)
    return json.dumps({"sent": True, "id": result.get("id"), "threadId": result.get("threadId")},
                      indent=2, ensure_ascii=False)


# ── Read state / Flag ─────────────────────────────────────────

@server.tool()
@guard("email.mark_read")
def gmail_mark_read(message_id: str, read: bool = True) -> str:
    """Mark a message as read (read=True) or unread (read=False).
    Implemented in Gmail by removing/adding the UNREAD label."""
    body = {"removeLabelIds": ["UNREAD"]} if read else {"addLabelIds": ["UNREAD"]}
    return json.dumps(
        gmail("POST", f"/messages/{message_id}/modify", body=body),
        indent=2,
        ensure_ascii=False,
    )


@server.tool()
@guard("email.flag")
def gmail_flag(message_id: str, flagged: bool = True) -> str:
    """Star (flagged=True) or unstar (flagged=False) a message.
    Gmail uses the STARRED label for stars."""
    body = {"addLabelIds": ["STARRED"]} if flagged else {"removeLabelIds": ["STARRED"]}
    return json.dumps(
        gmail("POST", f"/messages/{message_id}/modify", body=body),
        indent=2,
        ensure_ascii=False,
    )


# ── Move / Archive / Mark Spam / Delete ───────────────────────

@server.tool()
@guard("email.move")
def gmail_move(message_id: str, destination: str) -> str:
    """Move a message to ``destination`` mailbox (Gmail label).
    ``destination`` can be a label id (use gmail_list_mailboxes to discover)
    or one of Gmail's well-known label ids: 'INBOX', 'STARRED', 'SPAM',
    'TRASH', 'IMPORTANT', 'UNREAD'. Adds the destination label and removes
    the INBOX label (so the message leaves the inbox view)."""
    body = {"addLabelIds": [destination], "removeLabelIds": ["INBOX"]}
    return json.dumps(
        gmail("POST", f"/messages/{message_id}/modify", body=body),
        indent=2,
        ensure_ascii=False,
    )


@server.tool()
@guard("email.archive")
def gmail_archive(message_id: str) -> str:
    """Archive a message. In Gmail, archive = remove the INBOX label
    (the message remains in 'All Mail')."""
    return json.dumps(
        gmail("POST", f"/messages/{message_id}/modify", body={"removeLabelIds": ["INBOX"]}),
        indent=2,
        ensure_ascii=False,
    )


@server.tool()
@guard("email.mark_spam")
def gmail_mark_spam(message_id: str) -> str:
    """Mark a message as spam (adds the SPAM label, removes INBOX)."""
    body = {"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]}
    return json.dumps(
        gmail("POST", f"/messages/{message_id}/modify", body=body),
        indent=2,
        ensure_ascii=False,
    )


@server.tool()
@guard("email.delete")
def gmail_delete(message_id: str) -> str:
    """Delete a message — uses Gmail's trash (recoverable). For permanent
    delete, an admin would call DELETE /messages/{id} but we don't expose
    that here per the spec (would need email.permanent_delete)."""
    gmail("POST", f"/messages/{message_id}/trash")
    return json.dumps({"deleted": True, "message_id": message_id})


# ── Mailbox management ────────────────────────────────────────

@server.tool()
@guard("email.create_mailbox")
def gmail_create_mailbox(name: str) -> str:
    """Create a new Gmail label (mailbox equivalent). Default visibility
    is 'labelShow' / 'show' so it appears in Gmail's left sidebar."""
    body = {"name": name, "labelListVisibility": "labelShow",
            "messageListVisibility": "show"}
    return json.dumps(gmail("POST", "/labels", body=body), indent=2, ensure_ascii=False)


# Note: email.set_forwarding and email.add_delegate are deliberately NOT
# exposed as MCP tools (matches outlook-mcp). They are account-takeover
# vectors and an agent never has a legitimate reason to call them.


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
