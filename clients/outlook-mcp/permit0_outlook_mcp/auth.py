"""MSAL device-code auth + token cache for Microsoft Graph.

The token is cached at ~/.permit0/outlook_token.json and shared with
demos/outlook/outlook_test.py — log in once via either, both use it.
"""
import os
import pathlib
import sys

import msal

# Microsoft Graph PowerShell public client — works for personal Outlook accounts
# without the user having to register their own Azure App.
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
    # No cached token — fall back to device code. Print the prompt to stderr
    # so it shows up even when this is launched as a subprocess (Claude Code).
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise RuntimeError(f"device flow failed: {flow}")
    print(flow["message"], file=sys.stderr, flush=True)
    result = app.acquire_token_by_device_flow(flow)
    _save_cache(cache)
    if "access_token" not in result:
        raise RuntimeError(f"auth failed: {result.get('error_description')}")
    return result["access_token"]


def _save_cache(cache: msal.SerializableTokenCache) -> None:
    TOKEN_CACHE.parent.mkdir(parents=True, exist_ok=True)
    if cache.has_state_changed:
        TOKEN_CACHE.write_text(cache.serialize())
