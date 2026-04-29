"""
DroneShield — Traffic Replay Simulator
Records 60s of legitimate GCS traffic then replays with 20% attack injection.
Sends all packets to IDS proxy on port 14551.
"""
import socket
import struct
import time
import json
import random
import math
import logging
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s [REPLAY] %(message)s")

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 14551

REPLAY_FILE = os.path.join(os.path.dirname(__file__), "recorded_traffic.json")

# MAVLink constants
HEARTBEAT    = 0
SET_MODE     = 11
COMMAND_LONG = 76
GPS_INPUT    = 232

CMD_ARM_DISARM = 400

CRC_EXTRA = {
    HEARTBEAT: 50, SET_MODE: 89,
    COMMAND_LONG: 152, GPS_INPUT: 151,
}

_seq = 0


def mavlink_crc(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp ^= (tmp << 4) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def build_mavlink(msg_id: int, payload: bytes,
                  sys_id: int = 1, comp_id: int = 1) -> bytes:
    global _seq
    _seq = (_seq + 1) & 0xFF
    header = bytes([
        0xFD, len(payload), 0, 0, _seq,
        sys_id, comp_id,
        msg_id & 0xFF, (msg_id >> 8) & 0xFF, (msg_id >> 16) & 0xFF,
    ])
    crc_data = header[1:] + payload
    if msg_id in CRC_EXTRA:
        crc_data += bytes([CRC_EXTRA[msg_id]])
    crc = mavlink_crc(crc_data)
    return header + payload + struct.pack("<H", crc)


def _heartbeat() -> bytes:
    return build_mavlink(HEARTBEAT, struct.pack("<IBBBBB", 0, 6, 8, 81, 4, 3))


def _gps(lat: float, lon: float, alt: float = 50.0) -> bytes:
    t = int(time.time() * 1e6)
    payload = struct.pack("<QBHIHBiifffffffff B",
        t, 0, 0, 0, 0, 3,
        int(lat * 1e7), int(lon * 1e7), alt,
        1.5, 2.0, 0.5, 0.0, 0.0, 0.0, 1.2, 1.8, 8,
    )
    return build_mavlink(GPS_INPUT, payload)


def _arm(arm: bool = True, sys_id: int = 1) -> bytes:
    param1 = 1.0 if arm else 0.0
    payload = struct.pack("<fffffffHBBB",
        param1, 0, 0, 0, 0, 0, 0, CMD_ARM_DISARM, 1, 1, 0)
    return build_mavlink(COMMAND_LONG, payload, sys_id=sys_id)


def _mode(mode: int) -> bytes:
    payload = struct.pack("<IBB", mode, 1, 217)
    return build_mavlink(SET_MODE, payload, sys_id=99)


def _gps_spoof_burst(base_lat: float, base_lon: float,
                      jump_lat: float, jump_lon: float, steps: int = 5) -> list[bytes]:
    pkts = []
    for i in range(steps):
        frac = (i + 1) / steps
        lat = base_lat + frac * jump_lat
        lon = base_lon + frac * jump_lon
        pkts.append(_gps(lat, lon))
    return pkts


def generate_legitimate_traffic(duration: float = 60.0) -> list[dict]:
    """Simulate 60s of normal GCS↔drone traffic."""
    records = []
    rng = random.Random(42)
    lat, lon = 37.7749, -122.4194
    alt = 50.0
    t = 0.0

    next_hb  = 0.0
    next_gps = 0.25

    while t < duration:
        if t >= next_hb:
            records.append({"delay": max(0, t - (records[-1]["delay"] if records else 0)),
                            "ts": t, "type": "heartbeat",
                            "raw": list(_heartbeat())})
            next_hb = t + 1.0 + rng.gauss(0, 0.05)

        if t >= next_gps:
            lat += rng.gauss(0, 5e-6)
            lon += rng.gauss(0, 5e-6)
            records.append({"delay": 0.1, "ts": t, "type": "gps",
                            "raw": list(_gps(lat, lon, alt)),
                            "lat": lat, "lon": lon})
            next_gps = t + 0.5 + rng.gauss(0, 0.02)

        t += 0.1

    logging.info(f"Recorded {len(records)} legitimate packets")
    return records


def inject_attacks(records: list[dict]) -> list[dict]:
    """Replace ~20% of packets with attack packets."""
    rng = random.Random(77)
    result = list(records)
    n_inject = max(1, len(result) // 5)
    attack_types = ["arm_inject", "gps_spoof", "mode_change"]

    indices = sorted(rng.sample(range(len(result)), min(n_inject, len(result))))
    lat_base, lon_base = 37.7749, -122.4194

    for idx in indices:
        attack = rng.choice(attack_types)
        if attack == "arm_inject":
            result[idx] = {**result[idx], "type": "ATTACK_ARM",
                           "raw": list(_arm(arm=True, sys_id=99))}
        elif attack == "gps_spoof":
            result[idx] = {**result[idx], "type": "ATTACK_GPS",
                           "raw": list(_gps(
                               lat_base + rng.uniform(0.005, 0.015),
                               lon_base + rng.uniform(0.005, 0.015),
                           ))}
        elif attack == "mode_change":
            result[idx] = {**result[idx], "type": "ATTACK_MODE",
                           "raw": list(_mode(rng.choice([6, 3, 9])))}

    n_attacks = sum(1 for r in result if r["type"].startswith("ATTACK"))
    logging.info(f"Injected {n_attacks} attack packets ({n_attacks/len(result)*100:.1f}%)")
    return result


def replay(records: list[dict], sock: socket.socket) -> None:
    logging.info("Starting replay…")
    for i, record in enumerate(records):
        raw = bytes(record["raw"])
        sock.sendto(raw, (TARGET_HOST, TARGET_PORT))
        kind = record["type"]
        if kind.startswith("ATTACK"):
            logging.warning(f"[{i:4d}] INJECTED {kind}")
        else:
            logging.debug(f"[{i:4d}] {kind}")
        time.sleep(0.08)   # ~12 pkt/s replay speed
    logging.info("Replay complete.")


if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Use cached recording if available, else generate
    if os.path.exists(REPLAY_FILE):
        logging.info(f"Loading recorded traffic from {REPLAY_FILE}")
        with open(REPLAY_FILE) as f:
            records = json.load(f)
    else:
        logging.info("Generating legitimate traffic (60s simulation)…")
        records = generate_legitimate_traffic(60.0)
        with open(REPLAY_FILE, "w") as f:
            json.dump(records, f)

    records = inject_attacks(records)
    replay(records, sock)
    sock.close()
