"""MCP server exposing Outlook (Microsoft Graph) tools to Claude Code.

Each tool is gated by permit0:

    @server.tool()
    @permit0.guard("email.send")
    def outlook_send(...): ...

When Claude Code invokes a tool, the call goes:
    MCP server  →  permit0.guard  →  /api/v1/check_action (daemon)
                                       ↓
                                   allow / deny / human
                                       ↓
                  Microsoft Graph (only on allow)

This server does NOT expose set_forwarding or add_delegate to the LLM —
those are account-takeover vectors and the agent never needs them.

Configuration:
    PERMIT0_URL          — daemon URL (default http://localhost:9090)
    MSGRAPH_CLIENT_ID    — override the default public client id
"""
import json

import permit0
from mcp.server.fastmcp import FastMCP

from .graph import call as graph

server = FastMCP("permit0-outlook")

# Channel string sent to permit0 — identifies this backend in audit logs.
CHANNEL = "outlook"


def guard(action_type: str):
    """Wrapper around permit0.guard that pins channel='outlook' for this server."""
    return permit0.guard(action_type, channel=CHANNEL)


# ── Search / Read ─────────────────────────────────────────────

@server.tool()
@guard("email.search")
def outlook_search(query: str = "", top: int = 10, skip: int = 0) -> str:
    """Search inbox messages. ``query`` is a Microsoft Graph $search string
    (or empty for "most recent"). ``top`` is the page size (max 1000).
    ``skip`` is the offset for pagination (use top+skip to walk pages).
    Returns id, subject, from, receivedDateTime for each match. Use the
    returned ids with outlook_read / outlook_move / outlook_archive / etc.

    Note: Microsoft Graph does NOT support $skip when $search is used. When
    ``query`` is provided, ``skip`` is ignored and you must page using the
    ``@odata.nextLink`` URL returned in the previous response (not exposed
    by this wrapper — request a follow-up if you need cursor pagination)."""
    select = "$select=id,subject,from,receivedDateTime,isRead,conversationId"
    parts = [f"$top={top}", select]
    if query:
        parts.insert(0, f'$search="{query}"')
    else:
        if skip > 0:
            parts.append(f"$skip={skip}")
        parts.append("$orderby=receivedDateTime desc")
    path = "/me/messages?" + "&".join(parts)
    return json.dumps(graph("GET", path), indent=2, ensure_ascii=False)


@server.tool()
@guard("email.read")
def outlook_read(message_id: str) -> str:
    """Read full content (subject, body, recipients, headers) of one message
    by id."""
    return json.dumps(graph("GET", f"/me/messages/{message_id}"), indent=2, ensure_ascii=False)


@server.tool()
@guard("email.read_thread")
def outlook_read_thread(thread_id: str) -> str:
    """Read all messages in a conversation. ``thread_id`` is a
    conversationId (you can get one via outlook_search → conversationId)."""
    path = (
        f"/me/messages?$filter=conversationId eq '{thread_id}'"
        "&$select=id,subject,from,receivedDateTime,body,isRead"
        "&$orderby=receivedDateTime asc"
    )
    return json.dumps(graph("GET", path), indent=2, ensure_ascii=False)


@server.tool()
@guard("email.list_mailboxes")
def outlook_list_mailboxes() -> str:
    """List all mail folders (inbox, archive, sent, custom folders, …)
    with ids and message counts. Use folder ids with outlook_move."""
    return json.dumps(graph("GET", "/me/mailFolders"), indent=2, ensure_ascii=False)


# ── Draft / Send ──────────────────────────────────────────────

@server.tool()
@guard("email.draft")
def outlook_draft(
    to: str = "",
    subject: str = "",
    body: str = "",
    draft_id: str = "",
    in_reply_to: str = "",
    forward_from: str = "",
) -> str:
    """Create or modify a draft. Modes (mutually exclusive):
    - default: create a new draft (provide to/subject/body)
    - draft_id: modify an existing draft
    - in_reply_to: create a reply draft to the given message id
    - forward_from: create a forward draft from the given message id
    """
    if draft_id:
        # Modify existing draft via PATCH
        body_obj = {}
        if to:
            body_obj["toRecipients"] = [{"emailAddress": {"address": to}}]
        if subject:
            body_obj["subject"] = subject
        if body:
            body_obj["body"] = {"content": body, "contentType": "Text"}
        result = graph("PATCH", f"/me/messages/{draft_id}", body_obj)
    elif in_reply_to:
        result = graph("POST", f"/me/messages/{in_reply_to}/createReply")
        if subject or body:
            update = {}
            if subject:
                update["subject"] = subject
            if body:
                update["body"] = {"content": body, "contentType": "Text"}
            result = graph("PATCH", f"/me/messages/{result['id']}", update)
    elif forward_from:
        result = graph("POST", f"/me/messages/{forward_from}/createForward")
        if to:
            update = {"toRecipients": [{"emailAddress": {"address": to}}]}
            if body:
                update["body"] = {"content": body, "contentType": "Text"}
            result = graph("PATCH", f"/me/messages/{result['id']}", update)
    else:
        msg = {
            "subject": subject,
            "body": {"content": body, "contentType": "Text"},
        }
        if to:
            msg["toRecipients"] = [{"emailAddress": {"address": to}}]
        result = graph("POST", "/me/messages", msg)
    return json.dumps(result, indent=2, ensure_ascii=False)


@server.tool()
def outlook_send(
    to: str = "",
    subject: str = "",
    body: str = "",
    in_reply_to: str = "",
    reply_all: bool = False,
    forward_from: str = "",
    from_draft_id: str = "",
) -> str:
    """Send email. Modes (mutually exclusive):
    - default: send a new message (provide to/subject/body)
    - in_reply_to (+ optional reply_all): reply to a message
    - forward_from (+ to): forward a message to a new recipient
    - from_draft_id: send an existing draft

    Note: when from_draft_id is set, this server fetches the draft's
    to/subject/body BEFORE running the permit0 check, so the policy
    engine sees the actual content (no audit blind spots).
    """
    # If we're sending an existing draft, hydrate to/subject/body from the
    # draft so permit0 can score the actual content. This must happen
    # BEFORE the @permit0.guard decorator runs — so we wrap the policy
    # check manually.
    if from_draft_id:
        draft = graph("GET", f"/me/messages/{from_draft_id}")
        recipients = draft.get("toRecipients") or []
        if recipients and not to:
            to = recipients[0].get("emailAddress", {}).get("address", "")
        if not subject:
            subject = draft.get("subject", "")
        if not body:
            body = draft.get("body", {}).get("content", "")

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
        result = graph("POST", f"/me/messages/{from_draft_id}/send")
        return json.dumps({"sent": True, "from_draft": from_draft_id}, indent=2, ensure_ascii=False)

    if in_reply_to:
        endpoint = "replyAll" if reply_all else "reply"
        payload = {}
        if body:
            payload["comment"] = body
        result = graph("POST", f"/me/messages/{in_reply_to}/{endpoint}", payload)
        return json.dumps({"sent": True, "replied_to": in_reply_to}, indent=2, ensure_ascii=False)

    if forward_from:
        payload = {"toRecipients": [{"emailAddress": {"address": to}}]}
        if body:
            payload["comment"] = body
        result = graph("POST", f"/me/messages/{forward_from}/forward", payload)
        return json.dumps({"sent": True, "forwarded_from": forward_from}, indent=2, ensure_ascii=False)

    # Default: new message
    msg = {
        "message": {
            "toRecipients": [{"emailAddress": {"address": to}}],
            "subject": subject,
            "body": {"content": body, "contentType": "Text"},
        },
        "saveToSentItems": True,
    }
    graph("POST", "/me/sendMail", msg)
    return json.dumps({"sent": True, "to": to}, indent=2, ensure_ascii=False)


# ── Read state / Flag ─────────────────────────────────────────

@server.tool()
@guard("email.mark_read")
def outlook_mark_read(message_id: str, read: bool = True) -> str:
    """Mark a message as read (read=True) or unread (read=False)."""
    return json.dumps(
        graph("PATCH", f"/me/messages/{message_id}", {"isRead": read}),
        indent=2,
        ensure_ascii=False,
    )


@server.tool()
@guard("email.flag")
def outlook_flag(message_id: str, flagged: bool = True) -> str:
    """Flag (star) a message (flagged=True) or clear the flag (flagged=False)."""
    status = "flagged" if flagged else "notFlagged"
    return json.dumps(
        graph("PATCH", f"/me/messages/{message_id}", {"flag": {"flagStatus": status}}),
        indent=2,
        ensure_ascii=False,
    )


# ── Move / Archive / Mark Spam / Delete ───────────────────────

@server.tool()
@guard("email.move")
def outlook_move(message_id: str, destination: str) -> str:
    """Move a message to ``destination`` mailbox. ``destination`` can be a
    Graph folder id, or one of the well-known names: 'inbox', 'archive',
    'junkemail', 'deleteditems', 'drafts', 'sentitems'."""
    return json.dumps(
        graph("POST", f"/me/messages/{message_id}/move", {"destinationId": destination}),
        indent=2,
        ensure_ascii=False,
    )


@server.tool()
@guard("email.archive")
def outlook_archive(message_id: str) -> str:
    """Move a message to the Archive mailbox."""
    return json.dumps(
        graph("POST", f"/me/messages/{message_id}/move", {"destinationId": "archive"}),
        indent=2,
        ensure_ascii=False,
    )


@server.tool()
@guard("email.mark_spam")
def outlook_mark_spam(message_id: str) -> str:
    """Move a message to the Junk Email mailbox (trains the spam classifier)."""
    return json.dumps(
        graph("POST", f"/me/messages/{message_id}/move", {"destinationId": "junkemail"}),
        indent=2,
        ensure_ascii=False,
    )


@server.tool()
@guard("email.delete")
def outlook_delete(message_id: str) -> str:
    """Delete a message. Microsoft Graph moves it to Deleted Items
    (recoverable until the user empties that folder)."""
    graph("DELETE", f"/me/messages/{message_id}")
    return json.dumps({"deleted": True, "message_id": message_id})


# ── Mailbox management ────────────────────────────────────────

@server.tool()
@guard("email.create_mailbox")
def outlook_create_mailbox(name: str, parent_id: str = "") -> str:
    """Create a new mail folder. If ``parent_id`` is given, create as a
    child of that folder; otherwise create at the mailbox root."""
    if parent_id:
        path = f"/me/mailFolders/{parent_id}/childFolders"
    else:
        path = "/me/mailFolders"
    return json.dumps(graph("POST", path, {"displayName": name}), indent=2, ensure_ascii=False)


# Note: email.set_forwarding and email.add_delegate are deliberately NOT
# exposed as MCP tools. They're account-takeover vectors and an agent
# never has a legitimate need to call them. The corresponding norm actions
# and risk rules still exist (CRITICAL gate) so any other code path that
# attempts these operations is caught.


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
