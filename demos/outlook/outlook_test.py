#!/usr/bin/env python3
"""Thin Outlook wrapper that consults permit0 before calling Microsoft Graph.

Usage:
    python outlook_test.py list
    python outlook_test.py read --id <message_id>
    python outlook_test.py send --to bob@example.com --subject "hi" --body "ok"
    python outlook_test.py move --id <id> --folder <folder_id>
    python outlook_test.py archive --id <message_id>
    python outlook_test.py create-folder --name "Receipts"
    python outlook_test.py delete --id <message_id>
    python outlook_test.py mark-spam --id <message_id>
    python outlook_test.py draft --to bob@example.com --subject "hi" --body "ok"
"""
import argparse
import functools
import json
import os
import pathlib
import sys

import httpx
import msal

PERMIT0 = os.environ.get("PERMIT0_URL", "http://localhost:9090")
GRAPH = "https://graph.microsoft.com/v1.0"
DRY_RUN = False
# Microsoft Graph PowerShell public client — works for personal Outlook accounts
# without you having to register your own app. Swap for your own client_id once
# you've registered an app in Azure Portal.
CLIENT_ID = os.environ.get(
    "MSGRAPH_CLIENT_ID", "14d82eec-204b-4c2f-b7e8-296a70dab67e"
)
SCOPES = ["Mail.ReadWrite", "Mail.Send"]
TOKEN_CACHE = pathlib.Path.home() / ".permit0" / "outlook_token.json"


def get_token() -> str:
    cache = msal.SerializableTokenCache()
    if TOKEN_CACHE.exists():
        cache.deserialize(TOKEN_CACHE.read_text())
    app = msal.PublicClientApplication(
        CLIENT_ID,
        authority="https://login.microsoftonline.com/common",
        token_cache=cache,
    )
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
        if result:
            _save_cache(cache)
            return result["access_token"]
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise SystemExit(f"device flow failed: {flow}")
    print(flow["message"], file=sys.stderr)
    result = app.acquire_token_by_device_flow(flow)
    _save_cache(cache)
    if "access_token" not in result:
        raise SystemExit(f"auth failed: {result.get('error_description')}")
    return result["access_token"]


def _save_cache(cache: msal.SerializableTokenCache) -> None:
    TOKEN_CACHE.parent.mkdir(parents=True, exist_ok=True)
    if cache.has_state_changed:
        TOKEN_CACHE.write_text(cache.serialize())


def permit0_check(tool_name: str, parameters: dict) -> dict:
    r = httpx.post(
        f"{PERMIT0}/api/v1/check",
        json={"tool_name": tool_name, "parameters": parameters},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()


def graph(token, method: str, path: str, body=None) -> dict:
    if DRY_RUN:
        print(f"  [dry-run] would call: {method} {path}", file=sys.stderr)
        if body is not None:
            print(f"  [dry-run] body: {json.dumps(body, ensure_ascii=False)}", file=sys.stderr)
        return {"dry_run": True, "method": method, "path": path, "body": body}
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = httpx.request(method, f"{GRAPH}{path}", headers=headers, json=body, timeout=30)
    if r.status_code >= 400:
        raise SystemExit(f"graph error {r.status_code}: {r.text}")
    return r.json() if r.text else {}


def print_decision(d: dict) -> None:
    perm = d.get("permission", "?")
    color = {"allow": "\033[32m", "deny": "\033[31m", "human": "\033[33m"}.get(perm, "\033[0m")
    # tier/score are absent when source != "Scorer" (e.g. PolicyCache, Allowlist) —
    # the cached decision short-circuits before re-scoring.
    tier = d.get("tier") or "—"
    score = d.get("score") if d.get("score") is not None else "—"
    print(
        f"  permit0: {color}{perm.upper()}\033[0m  "
        f"action={d.get('action_type')}  tier={tier}  score={score}  "
        f"source={d.get('source')}",
        file=sys.stderr,
    )
    if d.get("blocked") and d.get("block_reason"):
        print(f"  blocked: {d['block_reason']}", file=sys.stderr)


def permit0_gated(tool_name: str):
    """Decorator: consult permit0 before invoking the wrapped function.

    The wrapped function's keyword arguments (except ``token``) are sent to
    permit0 as the parameters object, so argparse ``dest`` names must match
    the wrapped function's keyword parameter names (and the YAML normalizer's
    expected entity names).
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(**kwargs):
            params = {k: v for k, v in kwargs.items() if k != "token"}
            decision = permit0_check(tool_name, params)
            print_decision(decision)
            if decision["permission"] != "allow":
                print(f"skipped (permit0 said {decision['permission']})", file=sys.stderr)
                return None
            return fn(**kwargs)

        return wrapper

    return decorator


# ── verbs ──

def list_messages(*, token):
    return graph(
        token, "GET",
        "/me/messages?$top=10&$select=id,subject,from,receivedDateTime",
    )


@permit0_gated("outlook_read")
def read(*, message_id, token):
    return graph(token, "GET", f"/me/messages/{message_id}")


@permit0_gated("outlook_send")
def send(*, to, subject, body, token):
    msg = {
        "message": {
            "toRecipients": [{"emailAddress": {"address": to}}],
            "subject": subject,
            "body": {"content": body, "contentType": "Text"},
        },
        "saveToSentItems": True,
    }
    return graph(token, "POST", "/me/sendMail", msg)


@permit0_gated("outlook_move")
def move(*, message_id, folder_id, token):
    return graph(
        token, "POST", f"/me/messages/{message_id}/move",
        {"destinationId": folder_id},
    )


@permit0_gated("outlook_archive")
def archive(*, message_id, token):
    # 'archive' is a well-known folder ID in Microsoft Graph
    return graph(
        token, "POST", f"/me/messages/{message_id}/move",
        {"destinationId": "archive"},
    )


@permit0_gated("outlook_create_mailbox")
def create_folder(*, name, token):
    return graph(token, "POST", "/me/mailFolders", {"displayName": name})


@permit0_gated("outlook_delete")
def delete(*, message_id, token):
    return graph(token, "DELETE", f"/me/messages/{message_id}")


@permit0_gated("outlook_mark_spam")
def mark_spam(*, message_id, token):
    # 'junkemail' is a well-known folder ID in Microsoft Graph
    return graph(
        token, "POST", f"/me/messages/{message_id}/move",
        {"destinationId": "junkemail"},
    )


@permit0_gated("outlook_draft")
def draft(*, to, subject, body, token):
    msg = {
        "toRecipients": [{"emailAddress": {"address": to}}],
        "subject": subject,
        "body": {"content": body, "contentType": "Text"},
    }
    return graph(token, "POST", "/me/messages", msg)


def main():
    global DRY_RUN
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--dry-run", action="store_true",
        help="run permit0 check but skip Microsoft Graph (no real API call, no login)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list").set_defaults(fn=list_messages)

    sp = sub.add_parser("read")
    sp.add_argument("--id", dest="message_id", required=True)
    sp.set_defaults(fn=read)

    sp = sub.add_parser("send")
    sp.add_argument("--to", required=True)
    sp.add_argument("--subject", required=True)
    sp.add_argument("--body", required=True)
    sp.set_defaults(fn=send)

    sp = sub.add_parser("move")
    sp.add_argument("--id", dest="message_id", required=True)
    sp.add_argument("--folder", dest="folder_id", required=True,
                    help="destination folder id (or 'archive', 'junkemail', 'deleteditems')")
    sp.set_defaults(fn=move)

    sp = sub.add_parser("archive")
    sp.add_argument("--id", dest="message_id", required=True)
    sp.set_defaults(fn=archive)

    sp = sub.add_parser("create-folder")
    sp.add_argument("--name", required=True)
    sp.set_defaults(fn=create_folder)

    sp = sub.add_parser("delete")
    sp.add_argument("--id", dest="message_id", required=True)
    sp.set_defaults(fn=delete)

    sp = sub.add_parser("mark-spam")
    sp.add_argument("--id", dest="message_id", required=True)
    sp.set_defaults(fn=mark_spam)

    sp = sub.add_parser("draft")
    sp.add_argument("--to", required=True)
    sp.add_argument("--subject", required=True)
    sp.add_argument("--body", required=True)
    sp.set_defaults(fn=draft)

    args = p.parse_args()
    DRY_RUN = args.dry_run
    token = None if DRY_RUN else get_token()
    fn_args = {k: v for k, v in vars(args).items() if k not in ("cmd", "fn", "dry_run")}
    fn_args["token"] = token
    result = args.fn(**fn_args)
    if result is not None:
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
