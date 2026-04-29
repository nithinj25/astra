"""
DroneShield — Simulated Flight Controller
Listens on UDP 14550, maintains drone state, logs everything received.
"""
import socket
import struct
import time
import logging
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DRONE-SIM] %(message)s")

# MAVLink message IDs
HEARTBEAT    = 0
SET_MODE     = 11
COMMAND_LONG = 76
GPS_INPUT    = 232

# MAVLink commands
CMD_ARM_DISARM = 400
CMD_TAKEOFF    = 21
CMD_LAND       = 20

# CRC extra bytes per message type (standard MAVLink values)
CRC_EXTRA = {
    HEARTBEAT:    50,
    SET_MODE:     89,
    COMMAND_LONG: 152,
    GPS_INPUT:    151,
}

MODE_NAMES = {0: "STABILIZE", 3: "AUTO", 4: "GUIDED", 6: "RTL", 9: "LAND"}


@dataclass
class DroneState:
    armed:   bool  = False
    lat:     float = 37.7749    # San Francisco
    lon:     float = -122.4194
    alt:     float = 0.0
    mode:    int   = 0          # 0=STABILIZE
    heading: float = 0.0
    speed:   float = 0.0


def mavlink_crc(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp ^= (tmp << 4) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def parse_mavlink(data: bytes) -> dict | None:
    if len(data) < 12 or data[0] != 0xFD:
        return None
    payload_len = data[1]
    if len(data) < 12 + payload_len:
        return None

    seq    = data[4]
    sys_id = data[5]
    comp_id = data[6]
    msg_id = data[7] | (data[8] << 8) | (data[9] << 16)
    payload = data[10:10 + payload_len]
    checksum = struct.unpack_from("<H", data, 10 + payload_len)[0]

    crc_data = data[1:10 + payload_len]
    if msg_id in CRC_EXTRA:
        crc_data += bytes([CRC_EXTRA[msg_id]])
    valid = mavlink_crc(crc_data) == checksum

    return {
        "seq": seq, "sys_id": sys_id, "comp_id": comp_id,
        "msg_id": msg_id, "payload": payload, "checksum_valid": valid,
    }


class DroneSimulator:
    def __init__(self, port: int = 14550):
        self.state = DroneState()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", port))
        self.sock.settimeout(1.0)
        self.running = False

    def _handle(self, pkt: dict, addr: tuple) -> None:
        mid = pkt["msg_id"]
        pay = pkt["payload"]

        if mid == HEARTBEAT:
            logging.debug(f"HEARTBEAT from {addr}")

        elif mid == COMMAND_LONG:
            if len(pay) < 31:
                return
            cmd    = struct.unpack_from("<H", pay, 28)[0]
            param1 = struct.unpack_from("<f", pay, 0)[0]
            param7 = struct.unpack_from("<f", pay, 24)[0]
            if cmd == CMD_ARM_DISARM:
                self.state.armed = param1 > 0.5
                logging.info(f"{'ARMED' if self.state.armed else 'DISARMED'} — from {addr}")
            elif cmd == CMD_TAKEOFF:
                self.state.alt = param7 if param7 > 0 else 10.0
                logging.info(f"TAKEOFF to {self.state.alt:.1f}m — from {addr}")
            elif cmd == CMD_LAND:
                self.state.alt = 0.0
                self.state.armed = False
                logging.info(f"LAND — from {addr}")

        elif mid == SET_MODE:
            if len(pay) < 6:
                return
            mode = struct.unpack_from("<H", pay, 4)[0]
            self.state.mode = mode
            logging.info(f"MODE → {MODE_NAMES.get(mode, mode)} — from {addr}")

        elif mid == GPS_INPUT:
            if len(pay) < 30:
                return
            # GPS_INPUT wire layout: Q(8) B(1) H(2) I(4) H(2) B(1) → lat at byte 18
            lat = struct.unpack_from("<i", pay, 18)[0] / 1e7
            lon = struct.unpack_from("<i", pay, 22)[0] / 1e7
            alt = struct.unpack_from("<f", pay, 26)[0]
            self.state.lat = lat
            self.state.lon = lon
            self.state.alt = alt
            logging.info(f"GPS ({lat:.6f}, {lon:.6f}, {alt:.1f}m) — from {addr}")

    def run(self) -> None:
        self.running = True
        logging.info("DroneSimulator listening on UDP 14550")
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                pkt = parse_mavlink(data)
                if not pkt:
                    continue
                if not pkt["checksum_valid"]:
                    logging.warning(f"Bad checksum from {addr}")
                    continue
                self._handle(pkt, addr)
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
            except Exception as e:
                logging.error(f"Error: {e}")
        self.sock.close()


if __name__ == "__main__":
    DroneSimulator().run()
