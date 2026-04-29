"""
DroneShield — Rule-Based Detection Engine
Stateful rule checks on individual MAVLink packets.
"""
import time
import math
import struct
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

# Heartbeat spoof tracking: source_ip -> {sys_id: last_seen_ts}
_hb_sys_ids: dict[str, dict[int, float]] = defaultdict(dict)
HEARTBEAT_SPOOF_WINDOW = 30.0  # seconds

# Track whether GPS_JUMP fired on the current packet (to avoid duplicate alerts)
_last_gps_jump_blocked = False

# MAVLink message IDs
HEARTBEAT    = 0
SET_MODE     = 11
COMMAND_LONG = 76
GPS_INPUT    = 232
PARAM_SET    = 23
MISSION_ITEM = 39
MISSION_COUNT = 44

CMD_ARM_DISARM = 400

GUIDED_MODE = 4
RATE_LIMIT_PPS = 20        # packets per second
GPS_JUMP_THRESHOLD_M = 50  # metres
GPS_JUMP_MAX_SECS = 1.0
GEOFENCE_RADIUS_M = 300.0
HOME_LAT = 37.7749
HOME_LON = -122.4194

MSG_NAMES = {
    0:   "HEARTBEAT",
    11:  "SET_MODE",
    23:  "PARAM_SET",
    39:  "MISSION_ITEM",
    44:  "MISSION_COUNT",
    76:  "COMMAND_LONG",
    232: "GPS_INPUT",
}

# Human-readable descriptions of what was PREVENTED when each rule BLOCKS
BLOCKED_IMPACT: dict[str, str] = {
    "RATE_LIMIT":            "MAVLink channel saturation and GCS communication blackout prevented",
    "UNTRUSTED_ARM":         "Unauthorized motor arming and uncontrolled propulsion prevented",
    "GPS_JUMP":              "GPS coordinate injection and adversary-directed flight path hijack prevented",
    "UNEXPECTED_MODE_CHANGE":"Unauthorized flight-mode override and operator control loss prevented",
    "PARAM_TAMPER":          "Critical safety parameter modification — geofence/failsafe disable — prevented",
    "MISSION_INJECT":        "Hostile waypoint upload and covert flight plan replacement prevented",
    "HEARTBEAT_SPOOF":       "Fake GCS identity registration and trust escalation attack prevented",
    "GEOFENCE_BREACH":       "Drone egress beyond 300 m safe zone flagged for RTL intervention",
}


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


def check(
    msg_id: int,
    payload: bytes,
    source: tuple,
    drone_state: dict,
    sys_id: int = 1,
) -> RuleResult:
    global _last_gps, _last_mode, _last_gps_jump_blocked

    now = time.time()
    q = _source_times[source]
    q.append(now)

    # Reset GPS jump flag for this invocation
    _last_gps_jump_blocked = False

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
        lat = struct.unpack_from("<i", payload, 18)[0] / 1e7
        lon = struct.unpack_from("<i", payload, 22)[0] / 1e7
        if _last_gps is not None:
            dt = now - _last_gps["ts"]
            if dt < GPS_JUMP_MAX_SECS:
                dist = haversine(lat, lon, _last_gps["lat"], _last_gps["lon"])
                if dist > GPS_JUMP_THRESHOLD_M:
                    _last_gps = {"lat": lat, "lon": lon, "ts": now}
                    _last_gps_jump_blocked = True
                    return RuleResult(
                        verdict="BLOCK",
                        rule="GPS_JUMP",
                        detail=f"{dist:.1f}m jump in {dt:.3f}s",
                    )
        _last_gps = {"lat": lat, "lon": lon, "ts": now}

    # ── Rule 4: Mode change without prior GUIDED mode ────────────────────────
    if msg_id == SET_MODE:
        if TRUSTED_SOURCES and source not in TRUSTED_SOURCES:
            new_mode = 0
            if len(payload) >= 6:
                new_mode = struct.unpack_from("<H", payload, 4)[0]
            current = drone_state.get("mode", 0)
            return RuleResult(
                verdict="ALERT",
                rule="UNEXPECTED_MODE_CHANGE",
                detail=f"SET_MODE mode={new_mode} from untrusted source {source}",
            )
        elif len(payload) >= 6:
            _last_mode = struct.unpack_from("<H", payload, 4)[0]

    # ── Rule 5: PARAM_SET from untrusted source ──────────────────────────────
    if msg_id == PARAM_SET:
        if TRUSTED_SOURCES and source not in TRUSTED_SOURCES:
            param_name = ""
            if len(payload) >= 20:
                raw = payload[4:20]
                param_name = raw.rstrip(b'\x00').decode(errors="replace")
            detail = f"PARAM_SET"
            if param_name:
                detail += f" param={param_name}"
            detail += f" from untrusted {source}"
            return RuleResult(
                verdict="BLOCK",
                rule="PARAM_TAMPER",
                detail=detail,
            )

    # ── Rule 6: MISSION_ITEM or MISSION_COUNT from untrusted source ──────────
    if msg_id in (MISSION_ITEM, MISSION_COUNT):
        if TRUSTED_SOURCES and source not in TRUSTED_SOURCES:
            msg_name = "MISSION_ITEM" if msg_id == MISSION_ITEM else "MISSION_COUNT"
            return RuleResult(
                verdict="BLOCK",
                rule="MISSION_INJECT",
                detail=f"{msg_name} (id={msg_id}) from untrusted {source}",
            )

    # ── Rule 7: HEARTBEAT_SPOOF — multiple sys_ids from same IP ─────────────
    if msg_id == HEARTBEAT:
        src_ip = source[0] if isinstance(source, tuple) else str(source)
        ip_sysids = _hb_sys_ids[src_ip]
        ip_sysids[sys_id] = now
        # Purge stale entries
        stale = [sid for sid, ts in ip_sysids.items() if now - ts > HEARTBEAT_SPOOF_WINDOW]
        for sid in stale:
            del ip_sysids[sid]
        # Register trusted sources on heartbeat receipt
        TRUSTED_SOURCES.add(source)
        # Check for spoofed identity (>1 unique sys_id from same IP in window)
        if len(ip_sysids) > 1:
            ids_seen = sorted(ip_sysids.keys())
            return RuleResult(
                verdict="ALERT",
                rule="HEARTBEAT_SPOOF",
                detail=f"IP {src_ip} sent HB with sys_ids {ids_seen} in last {HEARTBEAT_SPOOF_WINDOW:.0f}s",
            )

    # ── Rule 8: GEOFENCE_BREACH — GPS outside 300m from HOME ────────────────
    # Only fires if GPS_JUMP didn't already block this packet
    if msg_id == GPS_INPUT and len(payload) >= 26 and not _last_gps_jump_blocked:
        lat = struct.unpack_from("<i", payload, 18)[0] / 1e7
        lon = struct.unpack_from("<i", payload, 22)[0] / 1e7
        dist_home = haversine(lat, lon, HOME_LAT, HOME_LON)
        if dist_home > GEOFENCE_RADIUS_M:
            return RuleResult(
                verdict="ALERT",
                rule="GEOFENCE_BREACH",
                detail=f"{dist_home:.1f}m from home ({HOME_LAT}, {HOME_LON}) — exceeds {GEOFENCE_RADIUS_M:.0f}m geofence",
            )

    return RuleResult(verdict="ALLOW")
