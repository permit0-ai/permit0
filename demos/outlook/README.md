# Outlook + permit0 thin wrapper

A ~150-line Python script that demonstrates the production loop:
**raw call → permit0 check → if allowed, call Microsoft Graph**.

## Setup

```bash
# 1. Start permit0 (in another terminal)
cd /home/hy/projs/permit0-core
cargo run -p permit0-cli -- serve --ui --port 9090

# 2. Install Python deps
cd demos/outlook
pip install -r requirements.txt
```

## First run — sign in

```bash
python outlook_test.py list
```

It will print something like:

```
To sign in, use a web browser to open the page https://microsoft.com/devicelogin
and enter the code XYZ123 to authenticate.
```

Open that URL on any device, paste the code, sign in to your **personal Outlook**
account, and approve the `Mail.ReadWrite` + `Mail.Send` permissions.

Token is cached at `~/.permit0/outlook_token.json` so you only do this once.

## Verbs

```bash
# List 10 most recent messages (no permit0 check — read-only metadata)
python outlook_test.py list

# Read a specific message
python outlook_test.py read --id <message_id>

# Send (the interesting one — try sending to your own address)
python outlook_test.py send \
  --to your-other-address@example.com \
  --subject "permit0 test" \
  --body "hello from permit0"

# Save a draft instead of sending
python outlook_test.py draft \
  --to your-other-address@example.com \
  --subject "draft test" \
  --body "this is a draft"

# Move to a folder (use folder id from the API or well-known: 'archive', 'junkemail', 'deleteditems')
python outlook_test.py move --id <message_id> --folder archive

# Convenience helpers
python outlook_test.py archive   --id <message_id>
python outlook_test.py mark-spam --id <message_id>
python outlook_test.py delete    --id <message_id>

# Create a folder
python outlook_test.py create-folder --name "Receipts"
```

## What the output looks like

For each call, you'll see the permit0 decision printed to stderr first:

```
  permit0: ALLOW  action=email.send  tier=MINIMAL  score=11
{
  "id": "AAMkAGI2…",
  ...graph response...
}
```

If permit0 denies or asks for human approval, the Graph call is **skipped**:

```
  permit0: HUMAN  action=email.delete  tier=HIGH  score=58
skipped (permit0 said human)
```

You can then go to the **permit0 dashboard** at http://localhost:9090/ui/
and watch decisions flow in under the **Audit** tab. Approvals can be granted
in the **Approvals** tab.

## Trying interesting risk scenarios

Things that should escalate or block:

```bash
# Email with a credential in the body — should escalate (EXPOSURE flag fires)
python outlook_test.py send \
  --to bob@external.com \
  --subject "creds" \
  --body "your password is hunter2"

# Email with confidential subject — should escalate (sensitivity)
python outlook_test.py send \
  --to bob@external.com \
  --subject "confidential Q4 report" \
  --body "see attached"
```

## Configuration

Environment variables:

| Variable           | Default                                    | Purpose                                  |
|--------------------|--------------------------------------------|------------------------------------------|
| `PERMIT0_URL`      | `http://localhost:9090`                    | permit0 server                           |
| `MSGRAPH_CLIENT_ID`| Microsoft Graph PowerShell public client   | Override with your own Azure App reg id  |

The default `CLIENT_ID` is Microsoft's public Graph PowerShell client. It works
for personal `@outlook.com` accounts without you having to register an app.
For production use, register your own app at
https://entra.microsoft.com → App registrations → New, and set
`MSGRAPH_CLIENT_ID` to your app's id.
