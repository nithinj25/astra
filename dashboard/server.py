"""
DroneShield — Dashboard FastAPI Server (standalone mode)
Run this if you want the dashboard without the IDS proxy.
The IDS proxy (ids_proxy.py) embeds this server when run normally.
"""
import asyncio
import json
import time
import math
import struct
import random
from datetime import datetime, timezone
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn

app = FastAPI(title="DroneShield Dashboard Server")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ws_clients: set[WebSocket] = set()

drone_state = {
    "armed": False, "lat": 37.7749, "lon": -122.4194,
    "alt": 0.0, "mode": 0,
}


@app.get("/health")
async def health():
    return {"status": "ok", "drone_state": drone_state}


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    ws_clients.add(websocket)
    try:
        while True:
            await asyncio.sleep(30)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        ws_clients.discard(websocket)


async def _broadcast(event: dict):
    dead = set()
    for ws in list(ws_clients):
        try:
            await ws.send_json(event)
        except Exception:
            dead.add(ws)
    ws_clients -= dead


async def _demo_stream():
    """Generates fake events for standalone dashboard testing."""
    rng = random.Random(42)
    msg_types = ["HEARTBEAT", "GPS_INPUT", "COMMAND_LONG", "SET_MODE"]
    verdicts  = ["ALLOW"] * 8 + ["ALERT"] * 1 + ["BLOCK"] * 1
    lat, lon  = 37.7749, -122.4194
    t = 0

    while True:
        await asyncio.sleep(0.4)
        t += 1
        verdict = rng.choice(verdicts)
        msg_type = rng.choice(msg_types)

        if msg_type == "GPS_INPUT":
            if verdict == "BLOCK":
                lat += rng.uniform(0.003, 0.006)
                lon += rng.uniform(0.003, 0.006)
            else:
                lat += rng.gauss(0, 5e-6)
                lon += rng.gauss(0, 5e-6)
            drone_state["lat"] = lat
            drone_state["lon"] = lon

        score = rng.uniform(0.6, 0.9) if verdict != "ALLOW" else rng.uniform(0.0, 0.12)

        event = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "packet_type": msg_type,
            "source":      f"127.0.0.1:{rng.randint(10000, 65535)}",
            "verdict":     verdict,
            "threat_score": round(score, 4),
            "drone_state": dict(drone_state),
            "attack_type": ("DEMO_ATTACK" if verdict != "ALLOW" else None),
            "rule":        ("DEMO_RULE" if verdict == "BLOCK" else ""),
        }
        await _broadcast(event)


@app.on_event("startup")
async def startup():
    asyncio.create_task(_demo_stream())


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
