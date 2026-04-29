"""
DroneShield — Rule-Based Detection Engine
Stateful rule checks on individual MAVLink packets.
"""
import time
import math
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("ids.rules")

# Trusted GCS source ports (populated on first heartbeat from 'legitimate' GCS)
TRUSTED_SOURCES: set[tuple] = set()

# Per-source packet timestamps (for rate limiting)
_source_times: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=100))

# Last known GPS position and timestamp
_last_gps: Optional[dict] = None

# Last mode before change
_last_mode: Optional[int] = None

# MAVLink message IDs
HEARTBEAT    = 0
SET_MODE     = 11
COMMAND_LONG = 76
GPS_INPUT    = 232

CMD_ARM_DISARM = 400

GUIDED_MODE = 4
RATE_LIMIT_PPS = 20        # packets per second
GPS_JUMP_THRESHOLD_M = 50  # metres
GPS_JUMP_MAX_SECS = 1.0


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


@dataclass
class RuleResult:
    verdict: str = "ALLOW"          # ALLOW | ALERT | BLOCK
    rule:    str = ""
    detail:  str = ""


def check(msg_id: int, payload: bytes, source: tuple, drone_state: dict) -> RuleResult:
    global _last_gps, _last_mode

    now = time.time()
    q = _source_times[source]
    q.append(now)

    # ── Rule 1: Packet rate > 20/s from a single source ─────────────────────
    recent = sum(1 for t in q if now - t <= 1.0)
    if recent > RATE_LIMIT_PPS:
        return RuleResult(
            verdict="BLOCK",
            rule="RATE_LIMIT",
            detail=f"{recent} pkt/s from {source}",
        )

    # ── Rule 2: ARM from unknown/untrusted source ────────────────────────────
    if msg_id == COMMAND_LONG and len(payload) >= 31:
        import struct
        cmd = struct.unpack_from("<H", payload, 28)[0]
        if cmd == CMD_ARM_DISARM:
            if TRUSTED_SOURCES and source not in TRUSTED_SOURCES:
                return RuleResult(
                    verdict="BLOCK",
                    rule="UNTRUSTED_ARM",
                    detail=f"ARM from unknown source {source}",
                )

    # ── Rule 3: GPS jump > 50 m in < 1 s ────────────────────────────────────
    if msg_id == GPS_INPUT and len(payload) >= 26:
        import struct
        # GPS_INPUT wire layout: Q(8) B(1) H(2) I(4) H(2) B(1) → lat at byte 18
        lat = struct.unpack_from("<i", payload, 18)[0] / 1e7
        lon = struct.unpack_from("<i", payload, 22)[0] / 1e7
        if _last_gps is not None:
            dt = now - _last_gps["ts"]
            if dt < GPS_JUMP_MAX_SECS:
                dist = haversine(lat, lon, _last_gps["lat"], _last_gps["lon"])
                if dist > GPS_JUMP_THRESHOLD_M:
                    _last_gps = {"lat": lat, "lon": lon, "ts": now}
                    return RuleResult(
                        verdict="BLOCK",
                        rule="GPS_JUMP",
                        detail=f"{dist:.1f}m jump in {dt:.3f}s",
                    )
        _last_gps = {"lat": lat, "lon": lon, "ts": now}

    # ── Rule 4: Mode change without prior GUIDED mode ────────────────────────
    if msg_id == SET_MODE and len(payload) >= 6:
        import struct
        new_mode = struct.unpack_from("<H", payload, 4)[0]
        current  = drone_state.get("mode", 0)
        if new_mode != current and current != GUIDED_MODE:
            return RuleResult(
                verdict="ALERT",
                rule="UNEXPECTED_MODE_CHANGE",
                detail=f"mode {current} → {new_mode} (not preceded by GUIDED)",
            )
        _last_mode = new_mode

    # ── Register heartbeat sources as trusted ───────────────────────────────
    if msg_id == HEARTBEAT:
        TRUSTED_SOURCES.add(source)

    return RuleResult(verdict="ALLOW")
