"""Google OAuth (Installed App flow) + token cache for Gmail API.

Unlike Microsoft Graph (which has a public client_id we can reuse), Google
requires every app to register its own OAuth credentials. The user must:

1. Visit https://console.cloud.google.com/
2. Create / select a project
3. Enable the Gmail API
4. Create an OAuth 2.0 Client ID (type: Desktop app)
5. Download the JSON, save it to ~/.permit0/gmail_credentials.json
   (or set GMAIL_CREDENTIALS env var)

First call to ``get_token()`` runs the InstalledAppFlow which opens a browser
for the user to grant consent. The resulting refresh token is cached at
~/.permit0/gmail_token.json — subsequent calls refresh silently.
"""
import os
import pathlib
import sys

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

# Combined scopes: read + modify (labels, trash) + send.
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]

CREDENTIALS_PATH = pathlib.Path(
    os.environ.get(
        "GMAIL_CREDENTIALS",
        str(pathlib.Path.home() / ".permit0" / "gmail_credentials.json"),
    )
)
TOKEN_PATH = pathlib.Path.home() / ".permit0" / "gmail_token.json"


def get_token() -> str:
    """Return a valid Gmail access token. Refreshes silently when possible;
    runs the interactive consent flow on first use (browser opens)."""
    creds: Credentials | None = None
    if TOKEN_PATH.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)

    if creds and creds.valid:
        return creds.token

    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        _save(creds)
        return creds.token

    # First-time login: needs interactive consent. Inform the user via stderr
    # in case this MCP server is running as a Claude Code subprocess.
    if not CREDENTIALS_PATH.exists():
        raise RuntimeError(
            f"Gmail OAuth credentials not found at {CREDENTIALS_PATH}.\n"
            "Set up: https://console.cloud.google.com/ → enable Gmail API "
            "→ create OAuth Desktop App → download JSON → save as the path above."
        )

    print(
        "[gmail-mcp] First-time login: copy the URL below into your browser, "
        "approve, and the redirect will return here.",
        file=sys.stderr,
        flush=True,
    )
    flow = InstalledAppFlow.from_client_secrets_file(
        str(CREDENTIALS_PATH), SCOPES
    )
    # open_browser=False → just prints the URL instead of trying to launch a
    # browser (avoids "could not locate runnable browser" in headless envs).
    # The local redirect listener still spins up on port=0 (random) and the
    # user pastes the URL into a browser on the same machine.
    creds = flow.run_local_server(port=0, open_browser=False)
    _save(creds)
    return creds.token


def _save(creds: Credentials) -> None:
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_PATH.write_text(creds.to_json())
