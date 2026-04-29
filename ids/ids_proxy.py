"""
DroneShield — Core IDS Proxy
MitM between GCS/attacker (UDP 14551) and drone (UDP 14550).
FastAPI WebSocket on port 8000.

NOTE: Uses thread-based UDP receive to work around Windows ProactorEventLoop
      UDP limitations. All processing still runs on the asyncio event loop via
      run_coroutine_threadsafe.

Simulation API:
    POST /api/simulate  { "action": "normal|arm|gps|mode|all|stop" }
    GET  /api/sim_status
"""
import asyncio
import struct
import threading
import time
import logging
import argparse
import os
import sys
import random
import socket as _socket
from datetime import datetime, timezone
from typing import Optional

# Windows: force SelectorEventLoop for reliable asyncio UDP support
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, os.path.dirname(__file__))
import rule_engine
import anomaly_model

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [IDS] %(message)s")
logger = logging.getLogger("ids")

# ── MAVLink constants ─────────────────────────────────────────────────────────
HEARTBEAT    = 0
SET_MODE     = 11
COMMAND_LONG = 76
GPS_INPUT    = 232

MSG_NAMES = {0: "HEARTBEAT", 11: "SET_MODE", 76: "COMMAND_LONG", 232: "GPS_INPUT"}
CRC_EXTRA = {HEARTBEAT: 50, SET_MODE: 89, COMMAND_LONG: 152, GPS_INPUT: 151}
CMD_ARM_DISARM = 400
_IDS_PORT = 14551

_pkt_seq = 0


def mavlink_crc(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp ^= (tmp << 4) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def _build(msg_id: int, payload: bytes, sys_id: int = 1, comp_id: int = 1) -> bytes:
    global _pkt_seq
    _pkt_seq = (_pkt_seq + 1) & 0xFF
    header = bytes([
        0xFD, len(payload), 0, 0, _pkt_seq,
        sys_id, comp_id,
        msg_id & 0xFF, (msg_id >> 8) & 0xFF, (msg_id >> 16) & 0xFF,
    ])
    crc_data = header[1:] + payload
    if msg_id in CRC_EXTRA:
        crc_data += bytes([CRC_EXTRA[msg_id]])
    return header + payload + struct.pack("<H", mavlink_crc(crc_data))


def _hb(sys_id: int = 1) -> bytes:
    return _build(HEARTBEAT, struct.pack("<IBBBBB", 0, 6, 8, 81, 4, 3), sys_id)


def _gps(lat: float, lon: float, alt: float = 50.0, sys_id: int = 1) -> bytes:
    t = int(time.time() * 1e6)
    payload = struct.pack("<QBHIHBiifffffffff B",
        t, 0, 0, 0, 0, 3,
        int(lat * 1e7), int(lon * 1e7), alt,
        1.5, 2.0, 0.5, 0.0, 0.0, 0.0, 1.2, 1.8, 8,
    )
    return _build(GPS_INPUT, payload, sys_id)


def _arm(arm: bool = True, sys_id: int = 99) -> bytes:
    p1 = 1.0 if arm else 0.0
    payload = struct.pack("<fffffffHBBB", p1, 0, 0, 0, 0, 0, 0, CMD_ARM_DISARM, 1, 1, 0)
    return _build(COMMAND_LONG, payload, sys_id)


def _mode_change(mode: int = 6, sys_id: int = 99) -> bytes:
    return _build(SET_MODE, struct.pack("<IBB", mode, 1, 217), sys_id)


def parse_mavlink(data: bytes) -> Optional[dict]:
    if len(data) < 12 or data[0] != 0xFD:
        return None
    payload_len = data[1]
    if len(data) < 12 + payload_len:
        return None
    seq     = data[4]
    sys_id  = data[5]
    msg_id  = data[7] | (data[8] << 8) | (data[9] << 16)
    payload = data[10:10 + payload_len]
    checksum = struct.unpack_from("<H", data, 10 + payload_len)[0]
    crc_data = data[1:10 + payload_len]
    if msg_id in CRC_EXTRA:
        crc_data += bytes([CRC_EXTRA[msg_id]])
    valid = mavlink_crc(crc_data) == checksum
    lat, lon = 0.0, 0.0
    if msg_id == GPS_INPUT and len(payload) >= 26:
        lat = struct.unpack_from("<i", payload, 18)[0] / 1e7
        lon = struct.unpack_from("<i", payload, 22)[0] / 1e7
    return {"seq": seq, "sys_id": sys_id, "msg_id": msg_id,
            "payload": payload, "checksum_valid": valid, "lat": lat, "lon": lon}


# ── Shared state ──────────────────────────────────────────────────────────────
drone_state = {"armed": False, "lat": 37.7749, "lon": -122.4194, "alt": 50.0, "mode": 0}

# Per-client queues — each WS connection gets its own asyncio.Queue
client_queues: list[asyncio.Queue] = []

# UDP sockets (shared — created in main())
_drone_sock:  Optional[_socket.socket] = None   # forward to drone :14550
_legit_sock:  Optional[_socket.socket] = None   # trusted sender :14552

# Simulation state
_sim_task:   Optional[asyncio.Task]   = None
_sim_mode:   str                      = "stopped"
_sim_lat:    float = 37.7749
_sim_lon:    float = -122.4194

# The running event loop (set in main, used by UDP thread)
_loop: Optional[asyncio.AbstractEventLoop] = None


def _push_event(event: dict) -> None:
    """Put event into every connected client queue. Safe to call from any thread."""
    for q in client_queues:
        try:
            q.put_nowait(event)
        except Exception:
            pass


# ── IDS packet processing (async, always on the event loop) ──────────────────
async def _process_packet(data: bytes, addr: tuple) -> None:
    pkt = parse_mavlink(data)
    if not pkt or not pkt["checksum_valid"]:
        return

    msg_id  = pkt["msg_id"]
    payload = pkt["payload"]
    src     = f"{addr[0]}:{addr[1]}"

    # Layer 1: rule engine
    rule_res  = rule_engine.check(msg_id, payload, addr, drone_state)
    verdict   = rule_res.verdict
    rule_name = rule_res.rule

    # Layer 2: anomaly model
    ml_score = 0.0
    if verdict != "BLOCK":
        ml_score, ml_v = anomaly_model.score_packet(msg_id, addr[1], pkt["lat"], pkt["lon"])
        if ml_v == "ALERT" and verdict == "ALLOW":
            verdict   = "ALERT"
            rule_name = rule_name or "ML_ANOMALY"

    threat_score = max(0.0, min(1.0, (-ml_score + 0.5)))

    # Forward to drone if not blocked
    if verdict != "BLOCK" and _drone_sock:
        try:
            _drone_sock.sendto(data, ("127.0.0.1", 14550))
        except Exception:
            pass
        _apply_state(msg_id, payload)

    attack_type = (rule_name or "UNKNOWN") if verdict != "ALLOW" else None

    event = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "packet_type":  MSG_NAMES.get(msg_id, f"MSG_{msg_id}"),
        "source":       src,
        "verdict":      verdict,
        "threat_score": round(threat_score, 4),
        "drone_state":  dict(drone_state),
        "attack_type":  attack_type,
        "rule":         rule_name,
    }

    lvl = {"ALLOW": logging.DEBUG, "ALERT": logging.WARNING,
           "BLOCK": logging.ERROR}.get(verdict, logging.INFO)
    logger.log(lvl, f"{verdict:5s} | {MSG_NAMES.get(msg_id, msg_id):14s} | "
                    f"src={src} | score={threat_score:.3f} | rule={rule_name}")

    _push_event(event)


def _apply_state(msg_id: int, payload: bytes) -> None:
    if msg_id == COMMAND_LONG and len(payload) >= 31:
        cmd = struct.unpack_from("<H", payload, 28)[0]
        p1  = struct.unpack_from("<f", payload, 0)[0]
        if cmd == CMD_ARM_DISARM:
            drone_state["armed"] = p1 > 0.5
    elif msg_id == SET_MODE and len(payload) >= 6:
        drone_state["mode"] = struct.unpack_from("<H", payload, 4)[0]
    elif msg_id == GPS_INPUT and len(payload) >= 30:
        drone_state["lat"] = struct.unpack_from("<i", payload, 18)[0] / 1e7
        drone_state["lon"] = struct.unpack_from("<i", payload, 22)[0] / 1e7
        drone_state["alt"] = struct.unpack_from("<f", payload, 26)[0]


# ── Thread-based UDP receiver (avoids Windows ProactorEventLoop UDP issues) ──
def _udp_receiver_thread(loop: asyncio.AbstractEventLoop) -> None:
    """Blocking UDP receiver in a daemon thread. Submits each packet to the
    asyncio event loop for processing."""
    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", _IDS_PORT))
    sock.settimeout(1.0)
    logger.info(f"UDP receiver thread listening on 0.0.0.0:{_IDS_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except _socket.timeout:
            continue
        except Exception as e:
            logger.error(f"UDP receive error: {e}")
            break

        # Hand off to the asyncio event loop — thread-safe
        asyncio.run_coroutine_threadsafe(_process_packet(data, addr), loop)


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="DroneShield IDS")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
async def health():
    return {"status": "ok", "drone_state": drone_state, "clients": len(client_queues)}


@app.get("/api/sim_status")
async def sim_status():
    return {"mode": _sim_mode, "clients": len(client_queues)}


class SimRequest(BaseModel):
    action: str = "normal"


@app.post("/api/simulate")
async def simulate(req: SimRequest):
    global _sim_task, _sim_mode

    if _sim_task and not _sim_task.done():
        _sim_task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(_sim_task), timeout=1.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    if req.action == "stop":
        _sim_mode = "stopped"
        logger.info("Simulation stopped.")
        return {"status": "stopped"}

    SIM_FNS = {
        "normal": _sim_normal,
        "arm":    _sim_arm,
        "gps":    _sim_gps,
        "mode":   _sim_mode_chg,
        "all":    _sim_full,
    }
    if req.action not in SIM_FNS:
        raise HTTPException(400, f"Unknown action: {req.action}")

    _sim_mode = req.action
    _sim_task = asyncio.create_task(SIM_FNS[req.action]())
    logger.info(f"Simulation started: {req.action}")
    return {"status": "started", "action": req.action}


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    client_queues.append(q)
    logger.info(f"WS client connected — {len(client_queues)} active")
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=20.0)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "keepalive"})
                continue
            await websocket.send_json(event)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            client_queues.remove(q)
        except ValueError:
            pass
        logger.info(f"WS client gone — {len(client_queues)} remaining")


# ── Simulation helpers ────────────────────────────────────────────────────────
def _send_legit(pkt: bytes) -> None:
    if _legit_sock:
        try:
            _legit_sock.sendto(pkt, ("127.0.0.1", _IDS_PORT))
        except Exception:
            pass


async def _normal_tick(rng: random.Random) -> None:
    global _sim_lat, _sim_lon
    _send_legit(_hb())
    await asyncio.sleep(0.5)
    _sim_lat += rng.gauss(0, 4e-6)
    _sim_lon += rng.gauss(0, 4e-6)
    _send_legit(_gps(_sim_lat, _sim_lon))
    await asyncio.sleep(0.5)


async def _sim_normal() -> None:
    rng = random.Random(int(time.time()))
    try:
        while True:
            await _normal_tick(rng)
    except asyncio.CancelledError:
        pass


async def _sim_arm() -> None:
    rng = random.Random(int(time.time()))
    atk = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        for _ in range(8):
            await _normal_tick(rng)
        for _ in range(6):
            atk.sendto(_arm(True, sys_id=99), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.15)
        while True:
            await _normal_tick(rng)
    except asyncio.CancelledError:
        pass
    finally:
        atk.close()


async def _sim_gps() -> None:
    global _sim_lat, _sim_lon
    rng = random.Random(int(time.time()))
    atk = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        for _ in range(8):
            await _normal_tick(rng)
        base_lat, base_lon = _sim_lat, _sim_lon
        for step in range(20):
            _send_legit(_hb())
            atk.sendto(_gps(
                base_lat + (step + 1) * 0.001,
                base_lon + (step + 1) * 0.0005,
                sys_id=99,
            ), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.6)
        while True:
            await _normal_tick(rng)
    except asyncio.CancelledError:
        pass
    finally:
        atk.close()


async def _sim_mode_chg() -> None:
    rng = random.Random(int(time.time()))
    atk = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        for _ in range(8):
            await _normal_tick(rng)
        for mode in [6, 3, 9, 6]:
            atk.sendto(_mode_change(mode, sys_id=99), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.4)
        while True:
            await _normal_tick(rng)
    except asyncio.CancelledError:
        pass
    finally:
        atk.close()


async def _sim_full() -> None:
    global _sim_mode, _sim_lat, _sim_lon
    rng = random.Random(int(time.time()))
    atk = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        _sim_mode = "normal"
        for _ in range(5):
            await _normal_tick(rng)

        _sim_mode = "arm"
        for _ in range(6):
            atk.sendto(_arm(True, sys_id=99), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.15)
        for _ in range(6):
            await _normal_tick(rng)

        _sim_mode = "gps"
        base_lat, base_lon = _sim_lat, _sim_lon
        for step in range(12):
            _send_legit(_hb())
            atk.sendto(_gps(
                base_lat + (step + 1) * 0.001,
                base_lon + (step + 1) * 0.0005,
                sys_id=99,
            ), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.7)

        _sim_mode = "mode"
        for mode in [6, 3, 9]:
            atk.sendto(_mode_change(mode, sys_id=99), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.5)

        _sim_mode = "normal"
        while True:
            await _normal_tick(rng)
    except asyncio.CancelledError:
        pass
    finally:
        atk.close()


# ── Main ──────────────────────────────────────────────────────────────────────
async def main(demo: bool = False) -> None:
    global _drone_sock, _legit_sock, _sim_mode, _sim_task, _loop

    logger.info("DroneShield IDS starting…")
    _loop = asyncio.get_event_loop()

    # Load ML model
    logger.info("Loading anomaly model…")
    await _loop.run_in_executor(None, anomaly_model.initialize)
    logger.info("Anomaly model ready.")

    # Socket to forward clean packets to drone (14550)
    _drone_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)

    # Trusted sender socket (bound to 14552 — registered as trusted by rule engine)
    _legit_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    _legit_sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    try:
        _legit_sock.bind(("127.0.0.1", 14552))
        logger.info("Legit sender socket bound to 127.0.0.1:14552")
    except OSError as e:
        logger.warning(f"Could not bind 14552 ({e}) — using ephemeral port")

    # Start UDP receiver in a background daemon thread
    t = threading.Thread(
        target=_udp_receiver_thread,
        args=(_loop,),
        daemon=True,
        name="udp-receiver",
    )
    t.start()

    # Auto-start normal flight simulation
    _sim_mode = "normal"
    _sim_task = asyncio.create_task(_sim_normal())
    logger.info("Normal flight simulation auto-started.")

    # Demo: switch to full attack after 5s
    if demo:
        async def _demo():
            await asyncio.sleep(5)
            global _sim_task, _sim_mode
            logger.info("DEMO: launching full attack sequence…")
            if _sim_task:
                _sim_task.cancel()
            _sim_mode = "all"
            _sim_task = asyncio.create_task(_sim_full())
        asyncio.create_task(_demo())

    # Start FastAPI / uvicorn (blocks until shutdown)
    config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="warning", loop="none")
    server = uvicorn.Server(config)
    logger.info("FastAPI WebSocket: ws://0.0.0.0:8000/ws")
    await server.serve()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DroneShield IDS Proxy")
    parser.add_argument("--demo", action="store_true", help="Auto-run full attack after 5s")
    args = parser.parse_args()
    try:
        asyncio.run(main(demo=args.demo))
    except KeyboardInterrupt:
        print("\nIDS stopped.")
