"""Microsoft Graph HTTP wrapper. Acquires a token via auth.get_token()
and forwards method/path/body."""
import httpx

from .auth import get_token

GRAPH = "https://graph.microsoft.com/v1.0"


def call(method: str, path: str, body=None) -> dict:
    token = get_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = httpx.request(method, f"{GRAPH}{path}", headers=headers, json=body, timeout=30)
    if r.status_code >= 400:
        raise RuntimeError(f"graph error {r.status_code}: {r.text}")
    return r.json() if r.text else {}
