"""Gmail API HTTP wrapper. Mirrors clients/outlook-mcp/permit0_outlook_mcp/graph.py."""
import httpx

from .auth import get_token

API = "https://gmail.googleapis.com/gmail/v1/users/me"


def call(method: str, path: str, body=None, params=None) -> dict:
    """Send a request to ``{API}{path}`` with the user's Gmail token.

    ``params`` is for query string (e.g. ``q``, ``maxResults``).
    """
    token = get_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = httpx.request(
        method, f"{API}{path}", headers=headers, json=body, params=params, timeout=30
    )
    if r.status_code >= 400:
        raise RuntimeError(f"gmail error {r.status_code}: {r.text}")
    return r.json() if r.text else {}
