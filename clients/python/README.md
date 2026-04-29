# permit0 Python SDK

Guard your Python functions with **norm-action-level** policies enforced by the permit0 daemon.

## Install

```bash
pip install -e clients/python   # from repo root
# (PyPI release pending)
```

## Quick start

```python
import permit0

@permit0.guard("email.send")
def send_via_smtp(to, subject, body):
    smtp.send_message(to, subject, body)

# Or let permit0 derive the action from the function name
# (split on first underscore: email_send → email.send)
@permit0.guard()
def email_send(to, subject, body):
    smtp.send_message(to, subject, body)
```

Use it normally. permit0 evaluates the call before each invocation:

```python
try:
    email_send(to="bob@example.com", subject="hi", body="ok")
except permit0.Denied as e:
    print(f"blocked by permit0: {e.decision.block_reason}")
```

## How it works

1. The decorator binds your function's arguments and forwards them to permit0
   as **entities** (a dict).
2. It calls `POST /api/v1/check_action` on the daemon with
   `{action_type, channel, entities}`.
3. On `allow`, your function runs.
4. On `deny` or `human`, `permit0.Denied(decision)` is raised.

The daemon **skips its YAML normalizer step** — your declared `action_type` is
authoritative. This is the right model for app code where you already know
what your function does. (External-API integrations like Outlook still go
through the normalizer-based flow via `POST /api/v1/check`.)

## Defaults

| What | Default |
|------|---------|
| Action type | Derived from function name. `email_send` → `email.send`. Override with `@permit0.guard("...")`. |
| Entities | All bound function arguments by name (excluding `self`, `cls`). Override with `entities=lambda *a, **kw: {...}`. |
| Channel | `"app"`. Override with `channel="mybackend"`. |
| Daemon URL | `http://localhost:9090`. Override with `PERMIT0_URL` env var. |

## Lower-level API

If you don't want a decorator (e.g. for middleware-style integration):

```python
decision = permit0.check_action(
    "email.send",
    {"to": "...", "subject": "...", "body": "..."},
    channel="myapp",
)
if decision.allowed:
    smtp.send(...)
else:
    raise permit0.Denied(decision)
```

## Configuration

```bash
export PERMIT0_URL=http://permit0.internal:9090
```

## Development

Run the smoke test (requires a running daemon):

```bash
cargo run -p permit0-cli -- serve --ui --port 9090 &
cd clients/python
pip install -e ".[test]"
pytest
```
