"""
FastAPI + WebSocket server for the permit0 demo.

Endpoints:
  GET  /                    → Demo UI (static HTML)
  GET  /api/scenarios       → List available scenarios
  GET  /api/audit           → Export audit entries
  WS   /ws/{scenario_id}    → Run a scenario with real-time events

WebSocket protocol:
  Client → Server:
    {"action": "start", "protected": true}
    {"action": "approve"}
    {"action": "reject"}

  Server → Client:
    {"kind": "thinking", ...}
    {"kind": "tool_call", "tool_name": ..., "tool_input": ...}
    {"kind": "permit0_decision", "permission": ..., "risk_score": ...}
    {"kind": "approval_required", "tool_name": ..., ...}
    {"kind": "blocked", "tool_name": ..., "reason": ...}
    {"kind": "tool_result", "tool_name": ..., "result": ...}
    {"kind": "done", "decisions": [...]}
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .agent import AgentEvent, DemoAgent, get_audit, get_engine, reset_engine
from .scenarios import ALL_SCENARIOS, SCENARIOS_BY_ID

app = FastAPI(title="permit0 Demo", version="0.1.0")

STATIC_DIR = Path(__file__).parent / "static"


# ── REST endpoints ─────────────────────────────────────────────

@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/scenarios")
async def list_scenarios():
    return [
        {
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "icon": s.icon,
        }
        for s in ALL_SCENARIOS
    ]


@app.get("/api/audit")
async def export_audit():
    audit = get_audit()
    if audit is None or audit.entry_count == 0:
        return JSONResponse({"entries": [], "valid": True, "count": 0})

    # Export to temp file, read back, verify
    path = os.path.join(tempfile.gettempdir(), "demo_audit.jsonl")
    audit.export_jsonl(path)

    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    valid, count, reason = audit.__class__.verify_jsonl(path, audit.public_key)

    return JSONResponse({
        "entries": entries,
        "valid": valid,
        "count": count,
        "reason": reason,
        "public_key": audit.public_key,
    })


@app.post("/api/reset")
async def reset():
    reset_engine()
    return {"ok": True}


# ── WebSocket endpoint ─────────────────────────────────────────

@app.websocket("/ws/{scenario_id}")
async def ws_scenario(websocket: WebSocket, scenario_id: str):
    await websocket.accept()

    scenario = SCENARIOS_BY_ID.get(scenario_id)
    if not scenario:
        await websocket.send_json({"kind": "error", "data": {"message": f"Unknown scenario: {scenario_id}"}})
        await websocket.close()
        return

    # Wait for start command
    try:
        msg = await websocket.receive_json()
    except WebSocketDisconnect:
        return

    if msg.get("action") != "start":
        await websocket.send_json({"kind": "error", "data": {"message": "Expected {action: 'start'}"}})
        await websocket.close()
        return

    protected = msg.get("protected", True)

    # Ensure engine is initialized
    get_engine()

    # Event callback → push to WebSocket
    async def on_event(event: AgentEvent) -> None:
        try:
            await websocket.send_json({"kind": event.kind, "data": event.data})
        except Exception:
            pass  # Client disconnected

    agent = DemoAgent(
        scenario=scenario,
        protected=protected,
        callback=on_event,
    )

    # Run agent in background, listen for approval messages
    agent_task = asyncio.create_task(agent.run())

    try:
        while not agent_task.done():
            # Wait for either: agent finishes or client message
            receive_task = asyncio.create_task(websocket.receive_json())

            done, pending = await asyncio.wait(
                [agent_task, receive_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Only cancel the receive_task if agent finished first.
            # NEVER cancel agent_task — it must keep running across
            # multiple approve/reject cycles.
            if receive_task in pending:
                receive_task.cancel()
                try:
                    await receive_task
                except (asyncio.CancelledError, WebSocketDisconnect):
                    pass

            if receive_task in done:
                try:
                    client_msg = receive_task.result()
                except (WebSocketDisconnect, asyncio.CancelledError):
                    agent_task.cancel()
                    return

                action = client_msg.get("action")
                if action in ("approve", "reject"):
                    agent.resolve_approval(action)

            if agent_task in done:
                break

        # Wait for agent completion
        try:
            await agent_task
        except asyncio.CancelledError:
            pass

    except WebSocketDisconnect:
        agent_task.cancel()
    except Exception as e:
        await websocket.send_json({"kind": "error", "data": {"message": str(e)}})
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# ── Static files (must be last) ────────────────────────────────

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
