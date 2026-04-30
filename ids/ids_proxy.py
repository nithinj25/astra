"""
DroneShield — Core IDS Proxy
MitM between GCS/attacker (UDP 14551) and drone (UDP 14550).
FastAPI WebSocket on port 8000.

NOTE: Uses thread-based UDP receive to work around Windows ProactorEventLoop
      UDP limitations. All processing still runs on the asyncio event loop via
      run_coroutine_threadsafe.

Simulation API:
    POST /api/simulate  { "action": "normal|arm|gps|mode|param|mission|spoof|all|stop" }
    GET  /api/sim_status
    GET  /api/telemetry
    GET  /api/events/recent?limit=50
"""
import asyncio
import struct
import threading
import time
import math
import logging
import argparse
import os
import sys
import random
import socket as _socket
from collections import deque
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
HEARTBEAT     = 0
SET_MODE      = 11
PARAM_SET     = 23
MISSION_ITEM  = 39
MISSION_COUNT = 44
COMMAND_LONG  = 76
GPS_INPUT     = 232

MSG_NAMES = {
    0:   "HEARTBEAT",
    11:  "SET_MODE",
    23:  "PARAM_SET",
    39:  "MISSION_ITEM",
    44:  "MISSION_COUNT",
    76:  "COMMAND_LONG",
    232: "GPS_INPUT",
}

CRC_EXTRA = {
    HEARTBEAT:     50,
    SET_MODE:      89,
    PARAM_SET:     168,
    MISSION_ITEM:  254,
    MISSION_COUNT: 221,
    COMMAND_LONG:  152,
    GPS_INPUT:     151,
}

CMD_ARM_DISARM = 400
_IDS_PORT = 14551

_pkt_seq = 0

# ── Orbital flight constants ──────────────────────────────────────────────────
HOME_LAT     = 37.7749
HOME_LON     = -122.4194
ORBIT_R_LAT  = 0.0021     # ~233m radius — stays within 300m geofence
ORBIT_R_LON  = 0.0026     # ~228m at this latitude
ORBIT_OMEGA  = 0.021      # rad/s → period ~299s, speed ~5 m/s


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


def _param_set(param_id: str, value: float, sys_id: int = 99) -> bytes:
    payload = struct.pack(
        "<f16sBBB",
        value,
        param_id.encode().ljust(16, b'\x00'),
        1, 1, 9,
    )
    return _build(PARAM_SET, payload, sys_id)


def _mission_count(count: int, sys_id: int = 99) -> bytes:
    payload = struct.pack("<HBBB", count, 1, 0, 0)
    return _build(MISSION_COUNT, payload, sys_id)


def _mission_item(seq: int, lat: float, lon: float, alt: float, sys_id: int = 99) -> bytes:
    payload = struct.pack(
        "<fffffffiiHHBBBBB",
        0, 0, 0, 0,
        int(lat * 1e7), int(lon * 1e7), alt,
        seq, 16, 1, 1, 3, 0, 1,
    )
    return _build(MISSION_ITEM, payload, sys_id)


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
    return {
        "seq": seq, "sys_id": sys_id, "msg_id": msg_id,
        "payload": payload, "checksum_valid": valid, "lat": lat, "lon": lon,
    }


# ── Shared state ──────────────────────────────────────────────────────────────
drone_state = {
    "armed": False,
    "lat":   HOME_LAT,
    "lon":   HOME_LON,
    "alt":   0.0,
    "mode":  0,
}

# Extended telemetry dict
_telem: dict = {
    "battery_pct":    100.0,
    "gps_sats":       12,
    "heading":        0.0,
    "groundspeed":    0.0,
    "flight_phase":   "PREFLIGHT",
    "geofence_breach": False,
    "orbit_angle":    0.0,
    "orbit_start_time": 0.0,
    "armed_time":     0.0,
}

# Per-client queues
client_queues: list[asyncio.Queue] = []

# Event history deque (maxlen=500)
_event_history: deque = deque(maxlen=500)

# UDP sockets
_drone_sock: Optional[_socket.socket] = None
_legit_sock: Optional[_socket.socket] = None

# Simulation state
_sim_task: Optional[asyncio.Task]  = None
_sim_mode: str                     = "stopped"

# The running event loop
_loop: Optional[asyncio.AbstractEventLoop] = None


def _push_event(event: dict) -> None:
    """Put event into every connected client queue and history. Safe from any thread."""
    _event_history.append(event)
    for q in client_queues:
        try:
            q.put_nowait(event)
        except Exception:
            pass


# ── IDS packet processing ─────────────────────────────────────────────────────
async def _process_packet(data: bytes, addr: tuple) -> None:
    pkt = parse_mavlink(data)
    if not pkt or not pkt["checksum_valid"]:
        return

    msg_id  = pkt["msg_id"]
    payload = pkt["payload"]
    src     = f"{addr[0]}:{addr[1]}"

    # Layer 1: rule engine
    rule_res  = rule_engine.check(msg_id, payload, addr, drone_state, sys_id=pkt["sys_id"])
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

    attack_type    = (rule_name or "UNKNOWN") if verdict != "ALLOW" else None
    blocked_impact = rule_engine.BLOCKED_IMPACT.get(rule_name, "") if verdict != "ALLOW" else ""

    # Build current drone_state with telem overlay
    ds_snapshot = dict(drone_state)
    ds_snapshot.update({
        "battery_pct":    _telem["battery_pct"],
        "gps_sats":       _telem["gps_sats"],
        "heading":        round(_telem["heading"], 1),
        "groundspeed":    round(_telem["groundspeed"], 1),
        "flight_phase":   _telem["flight_phase"],
        "geofence_breach": _telem["geofence_breach"],
    })

    event = {
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "packet_type":    MSG_NAMES.get(msg_id, f"MSG_{msg_id}"),
        "source":         src,
        "verdict":        verdict,
        "threat_score":   round(threat_score, 4),
        "drone_state":    ds_snapshot,
        "attack_type":    attack_type,
        "rule":           rule_name,
        "blocked_impact": blocked_impact,
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


# ── Thread-based UDP receiver ─────────────────────────────────────────────────
def _udp_receiver_thread(loop: asyncio.AbstractEventLoop) -> None:
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


@app.get("/api/telemetry")
async def get_telemetry():
    """Return current flight telemetry (excludes internal orbit state fields)."""
    return {
        "battery_pct":    _telem["battery_pct"],
        "gps_sats":       _telem["gps_sats"],
        "heading":        round(_telem["heading"], 1),
        "groundspeed":    round(_telem["groundspeed"], 1),
        "flight_phase":   _telem["flight_phase"],
        "geofence_breach": _telem["geofence_breach"],
    }


@app.get("/api/events/recent")
async def get_recent_events(limit: int = 50):
    """Return last N events from history (newest first)."""
    limit = max(1, min(limit, 500))
    items = list(_event_history)
    return {"events": items[-limit:][::-1], "total": len(items)}


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
        "normal":  _sim_normal,
        "arm":     _sim_arm,
        "gps":     _sim_gps,
        "mode":    _sim_mode_chg,
        "param":   _sim_param,
        "mission": _sim_mission,
        "spoof":   _sim_spoof,
        "demo":    _sim_demo,
        "all":     _sim_full,
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


def _send_attack(sock: _socket.socket, pkt: bytes) -> None:
    try:
        sock.sendto(pkt, ("127.0.0.1", _IDS_PORT))
    except Exception:
        pass


async def _sim_normal() -> None:
    """Realistic phased flight simulation: PREFLIGHT → ARMED → TAKEOFF → CRUISE."""
    global _telem
    rng = random.Random(int(time.time()))
    start = time.time()
    prev_lat = HOME_LAT
    prev_lon = HOME_LON
    prev_ts  = start

    _telem["flight_phase"]   = "PREFLIGHT"
    _telem["orbit_start_time"] = start
    _telem["armed_time"]     = 0.0
    _telem["orbit_angle"]    = 0.0
    _telem["battery_pct"]    = 100.0
    _telem["geofence_breach"] = False

    try:
        while True:
            now = time.time()
            elapsed = now - start
            dt = now - prev_ts
            prev_ts = now

            # ─ PREFLIGHT: T=0–3s ─────────────────────────────────────────────
            if elapsed < 3.0:
                _telem["flight_phase"] = "PREFLIGHT"
                drone_state["armed"] = False
                drone_state["mode"]  = 0
                drone_state["alt"]   = 0.0
                lat, lon = HOME_LAT, HOME_LON
                _telem["groundspeed"] = 0.0
                _telem["heading"]     = 0.0
                _send_legit(_hb(sys_id=1))
                _send_legit(_gps(lat, lon, alt=0.0))
                await asyncio.sleep(0.5)

            # ─ ARMED: T=3–8s ─────────────────────────────────────────────────
            elif elapsed < 8.0:
                if _telem["flight_phase"] != "ARMED":
                    _telem["flight_phase"] = "ARMED"
                    _telem["armed_time"]   = now
                    drone_state["armed"]   = True
                    drone_state["mode"]    = 4  # GUIDED
                    _send_legit(_arm(True, sys_id=1))
                lat, lon = HOME_LAT, HOME_LON
                _telem["groundspeed"] = 0.0
                _send_legit(_hb(sys_id=1))
                _send_legit(_gps(lat, lon, alt=0.0))
                await asyncio.sleep(0.5)

            # ─ TAKEOFF: T=8–18s — glide toward orbit entry (angle=0) ────────
            elif elapsed < 18.0:
                if _telem["flight_phase"] != "TAKEOFF":
                    _telem["flight_phase"] = "TAKEOFF"
                frac = (elapsed - 8.0) / 10.0
                alt  = frac * 40.0
                drone_state["alt"] = alt
                # Interpolate lat/lon toward orbit entry point to avoid GPS_JUMP at CRUISE start
                orbit_entry_lat = HOME_LAT
                orbit_entry_lon = HOME_LON + ORBIT_R_LON
                lat = HOME_LAT + frac * (orbit_entry_lat - HOME_LAT)
                lon = HOME_LON + frac * (orbit_entry_lon - HOME_LON)
                _telem["groundspeed"] = frac * 5.0
                _telem["heading"]     = 90.0  # heading east toward orbit entry
                _send_legit(_hb(sys_id=1))
                _send_legit(_gps(lat, lon, alt=alt))
                await asyncio.sleep(0.5)

            # ─ CRUISE: T=18s+ ────────────────────────────────────────────────
            else:
                if _telem["flight_phase"] != "CRUISE":
                    _telem["flight_phase"] = "CRUISE"

                # Orbit update
                angle = _telem["orbit_angle"]
                angle = (angle + ORBIT_OMEGA * dt) % (2 * math.pi)
                _telem["orbit_angle"] = angle

                lat = HOME_LAT + ORBIT_R_LAT * math.sin(angle)
                lon = HOME_LON + ORBIT_R_LON * math.cos(angle)

                # Heading from consecutive positions
                dlat = lat - prev_lat
                dlon = lon - prev_lon
                if abs(dlat) > 1e-9 or abs(dlon) > 1e-9:
                    heading = math.degrees(math.atan2(dlon, dlat)) % 360
                    _telem["heading"] = heading

                prev_lat = lat
                prev_lon = lon

                # Groundspeed ~5.0 m/s
                _telem["groundspeed"] = 5.0 + rng.gauss(0, 0.1)

                # Battery drain 0.08%/s
                _telem["battery_pct"] = max(0.0, _telem["battery_pct"] - 0.08 * dt)

                # GPS sats
                if rng.random() < 0.03:
                    _telem["gps_sats"] = rng.randint(8, 10)
                else:
                    _telem["gps_sats"] = 12

                # Geofence check (300m)
                from rule_engine import haversine as _hav, GEOFENCE_RADIUS_M
                dist = _hav(lat, lon, HOME_LAT, HOME_LON)
                _telem["geofence_breach"] = dist > GEOFENCE_RADIUS_M

                drone_state["alt"] = 40.0
                _send_legit(_hb(sys_id=1))
                _send_legit(_gps(lat, lon, alt=40.0))
                await asyncio.sleep(0.5)

    except asyncio.CancelledError:
        pass


async def _cancel_task(t: asyncio.Task) -> None:
    """Cancel a task and wait for it to finish cleanly."""
    if t and not t.done():
        t.cancel()
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass


async def _sim_arm() -> None:
    atk         = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    normal_task = asyncio.create_task(_sim_normal())
    try:
        await asyncio.sleep(8)
        await _cancel_task(normal_task)
        normal_task = None
        for _ in range(6):
            atk.sendto(_arm(True, sys_id=99), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.15)
        await _sim_normal()
    except asyncio.CancelledError:
        pass
    finally:
        if normal_task is not None:
            await _cancel_task(normal_task)
        atk.close()


async def _sim_gps() -> None:
    atk         = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    normal_task = asyncio.create_task(_sim_normal())
    try:
        await asyncio.sleep(10)
        await _cancel_task(normal_task)
        normal_task = None
        base_lat, base_lon = drone_state["lat"], drone_state["lon"]
        for step in range(20):
            _send_legit(_hb())
            atk.sendto(_gps(
                base_lat + (step + 1) * 0.001,
                base_lon + (step + 1) * 0.0005,
                sys_id=99,
            ), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.6)
        await _sim_normal()
    except asyncio.CancelledError:
        pass
    finally:
        if normal_task is not None:
            await _cancel_task(normal_task)
        atk.close()


async def _sim_mode_chg() -> None:
    atk         = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    normal_task = asyncio.create_task(_sim_normal())
    try:
        await asyncio.sleep(8)
        await _cancel_task(normal_task)
        normal_task = None
        for mode in [6, 3, 9, 6]:
            atk.sendto(_mode_change(mode, sys_id=99), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.4)
        await _sim_normal()
    except asyncio.CancelledError:
        pass
    finally:
        if normal_task is not None:
            await _cancel_task(normal_task)
        atk.close()


async def _sim_param() -> None:
    """Loop: send PARAM_SET attacks every 2s from attack socket."""
    atk = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        while True:
            _send_attack(atk, _param_set("FENCE_ACTION",  0.0))
            await asyncio.sleep(0.1)
            _send_attack(atk, _param_set("FS_GCS_ENABLE", 0.0))
            await asyncio.sleep(2.0)
    except asyncio.CancelledError:
        pass
    finally:
        atk.close()


async def _sim_mission() -> None:
    """Loop: send MISSION_COUNT then MISSION_ITEM (Washington DC) every 3s."""
    atk = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        while True:
            _send_attack(atk, _mission_count(1))
            await asyncio.sleep(0.05)
            _send_attack(atk, _mission_item(0, 38.897, -77.036, 100.0))
            await asyncio.sleep(3.0)
    except asyncio.CancelledError:
        pass
    finally:
        atk.close()


async def _sim_spoof() -> None:
    """Loop: send heartbeats cycling sys_id through 40-49 every 0.5s."""
    atk = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    idx = 0
    try:
        while True:
            spoof_id = 40 + (idx % 10)
            idx += 1
            _send_attack(atk, _hb(sys_id=spoof_id))
            await asyncio.sleep(0.5)
    except asyncio.CancelledError:
        pass
    finally:
        atk.close()


async def _sim_demo() -> None:
    """
    Judge-friendly auto-demo: runs each attack type once in sequence with clear
    pauses between so the dashboard reacts visibly. Loops indefinitely.
    """
    global _sim_mode
    atk    = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    normal: asyncio.Task | None = None
    try:
        while True:
            # ── warm-up: normal flight ────────────────────────────────────────
            _sim_mode = "normal"
            normal = asyncio.create_task(_sim_normal())
            await asyncio.sleep(14)       # let CRUISE establish
            await _cancel_task(normal)
            normal = None

            # ── 1: ARM injection ─────────────────────────────────────────────
            _sim_mode = "arm"
            for _ in range(5):
                atk.sendto(_arm(True, sys_id=99), ("127.0.0.1", _IDS_PORT))
                await asyncio.sleep(0.18)
            await asyncio.sleep(9)        # pause so toast is readable

            # ── 2: GPS spoofing ──────────────────────────────────────────────
            _sim_mode = "gps"
            base_lat = drone_state.get("lat", HOME_LAT)
            base_lon = drone_state.get("lon", HOME_LON)
            for step in range(8):
                _send_legit(_hb())
                atk.sendto(_gps(
                    base_lat + (step + 1) * 0.001,
                    base_lon + (step + 1) * 0.0005,
                    sys_id=99,
                ), ("127.0.0.1", _IDS_PORT))
                await asyncio.sleep(0.5)
            await asyncio.sleep(9)

            # ── 3: mode hijacking ────────────────────────────────────────────
            _sim_mode = "mode"
            for mode in [6, 3, 9, 6]:
                atk.sendto(_mode_change(mode, sys_id=99), ("127.0.0.1", _IDS_PORT))
                await asyncio.sleep(0.35)
            await asyncio.sleep(9)

            # ── 4: parameter tampering ───────────────────────────────────────
            _sim_mode = "param"
            for _ in range(2):
                atk.sendto(_param_set("FENCE_ACTION",  0.0), ("127.0.0.1", _IDS_PORT))
                await asyncio.sleep(0.08)
                atk.sendto(_param_set("FS_GCS_ENABLE", 0.0), ("127.0.0.1", _IDS_PORT))
                await asyncio.sleep(0.08)
                atk.sendto(_param_set("ARMING_CHECK",  0.0), ("127.0.0.1", _IDS_PORT))
                await asyncio.sleep(1.2)
            await asyncio.sleep(9)

            # ── 5: mission injection ─────────────────────────────────────────
            _sim_mode = "mission"
            for _ in range(2):
                atk.sendto(_mission_count(1), ("127.0.0.1", _IDS_PORT))
                await asyncio.sleep(0.06)
                atk.sendto(_mission_item(0, 38.897, -77.036, 100.0), ("127.0.0.1", _IDS_PORT))
                await asyncio.sleep(1.5)
            await asyncio.sleep(9)

            # ── 6: heartbeat spoofing ────────────────────────────────────────
            _sim_mode = "spoof"
            for i in range(18):
                atk.sendto(_hb(sys_id=40 + (i % 10)), ("127.0.0.1", _IDS_PORT))
                await asyncio.sleep(0.28)
            await asyncio.sleep(9)

    except asyncio.CancelledError:
        pass
    finally:
        if normal is not None:
            await _cancel_task(normal)
        atk.close()


async def _sim_full() -> None:
    """Full attack sequence: arm → gps → mode → param → mission → spoof, then loop normal."""
    global _sim_mode
    atk         = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    normal_task: asyncio.Task | None = None
    try:
        # Phase: normal flight warm-up
        _sim_mode   = "normal"
        normal_task = asyncio.create_task(_sim_normal())
        await asyncio.sleep(10)
        await _cancel_task(normal_task)
        normal_task = None

        # Phase: arm injection
        _sim_mode = "arm"
        for _ in range(6):
            atk.sendto(_arm(True, sys_id=99), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.15)
        await asyncio.sleep(2)

        # Phase: GPS spoof
        _sim_mode = "gps"
        base_lat, base_lon = drone_state["lat"], drone_state["lon"]
        for step in range(12):
            _send_legit(_hb())
            atk.sendto(_gps(
                base_lat + (step + 1) * 0.001,
                base_lon + (step + 1) * 0.0005,
                sys_id=99,
            ), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.7)

        # Phase: mode change
        _sim_mode = "mode"
        for mode in [6, 3, 9]:
            atk.sendto(_mode_change(mode, sys_id=99), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.5)
        await asyncio.sleep(1)

        # Phase: param tamper
        _sim_mode = "param"
        for _ in range(4):
            atk.sendto(_param_set("FENCE_ACTION",  0.0), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.1)
            atk.sendto(_param_set("FS_GCS_ENABLE", 0.0), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.1)
            atk.sendto(_param_set("ARMING_CHECK",  0.0), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.3)
        await asyncio.sleep(1)

        # Phase: mission inject
        _sim_mode = "mission"
        for _ in range(3):
            atk.sendto(_mission_count(1), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.05)
            atk.sendto(_mission_item(0, 38.897, -77.036, 100.0), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(1.0)

        # Phase: heartbeat spoof
        _sim_mode = "spoof"
        for i in range(20):
            atk.sendto(_hb(sys_id=40 + (i % 10)), ("127.0.0.1", _IDS_PORT))
            await asyncio.sleep(0.2)
        await asyncio.sleep(1)

        # Return to normal
        _sim_mode = "normal"
        await _sim_normal()

    except asyncio.CancelledError:
        pass
    finally:
        if normal_task is not None:
            await _cancel_task(normal_task)
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

    # Trusted sender socket (bound to 14552)
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

    # Start FastAPI / uvicorn
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
