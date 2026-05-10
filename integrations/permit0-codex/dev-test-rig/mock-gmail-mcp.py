#!/usr/bin/env python3
"""
Mock Gmail MCP server — exposes a `gmail_send` tool over stdio JSON-RPC.

NEVER actually sends mail. Returns a synthetic success response. Sole
purpose is to give Codex a tool named `gmail_send` so permit0's Gmail
pack normalizer matches and risk rules fire (recipient_scope,
extract_domain, etc.) during the live-codex demo.

Wire spec: MCP 2024-11-05 (close enough — Codex's MCP client is
permissive about minor revs).

Trace state goes under `PERMIT0_TRACE_DIR` (default
`/tmp/permit0-codex-test/`) so nothing lands in the repo.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

TRACE_DIR = Path(os.environ.get("PERMIT0_TRACE_DIR", "/tmp/permit0-codex-test"))
LOG_PATH = TRACE_DIR / "mock-mcp.log"
PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "mock-gmail"
SERVER_VERSION = "0.0.1"

TOOLS: list[dict[str, Any]] = [
    {
        "name": "gmail_send",
        "description": (
            "Send an email through the user's Gmail account. NEVER returns "
            "a real send confirmation — this is a mock for testing the "
            "permit0 hook integration."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Primary recipient email address."},
                "cc": {"type": "string", "description": "Cc recipients (comma-separated)."},
                "bcc": {"type": "string", "description": "Bcc recipients (comma-separated)."},
                "subject": {"type": "string", "description": "Email subject line."},
                "body": {"type": "string", "description": "Email body (plain text)."},
            },
            "required": ["to", "subject", "body"],
        },
    },
]


def log(direction: str, payload: Any) -> None:
    try:
        TRACE_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a") as f:
            f.write(
                json.dumps(
                    {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "dir": direction,
                        "payload": payload,
                    }
                )
                + "\n"
            )
    except Exception:
        pass


def send(payload: dict[str, Any]) -> None:
    line = json.dumps(payload)
    log("send", payload)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def handle_request(req: dict[str, Any]) -> dict[str, Any] | None:
    method = req.get("method")
    req_id = req.get("id")

    # Notifications (no `id` field) get no response.
    if req_id is None:
        log("notification_in", req)
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS},
        }

    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "gmail_send":
            to = args.get("to", "<unknown>")
            subject = args.get("subject", "<no subject>")
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"[mock-gmail] Pretended to send email to {to!r} "
                                f"with subject {subject!r}. No real mail was sent."
                            ),
                        }
                    ]
                },
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"unknown tool: {name!r}"},
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"method not implemented: {method!r}"},
    }


def main() -> int:
    log("startup", {"pid": os.getpid()})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            log("recv_bad_json", {"err": str(e), "raw": line[:200]})
            continue
        log("recv", req)
        resp = handle_request(req)
        if resp is not None:
            send(resp)
    log("shutdown", {})
    return 0


if __name__ == "__main__":
    sys.exit(main())
