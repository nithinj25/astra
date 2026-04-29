"""
DroneShield — Synthetic MAVLink Training Data Generator
Produces feature vectors for Isolation Forest training.
"""
import numpy as np
import math
import random
from typing import List

# Feature order: mean_interval, std_interval, cmd_rate, gps_delta,
#                unique_msg_types, source_port_entropy

HEARTBEAT    = 0
SET_MODE     = 11
COMMAND_LONG = 76
GPS_INPUT    = 232


def _entropy(counts: List[int]) -> float:
    total = sum(counts)
    if total == 0:
        return 0.0
    probs = [c / total for c in counts if c > 0]
    return -sum(p * math.log2(p) for p in probs)


def _window_features(events: List[dict]) -> np.ndarray:
    """Convert a list of packet-event dicts into a feature vector."""
    if len(events) < 2:
        return np.zeros(6)

    timestamps    = [e["ts"] for e in events]
    intervals     = np.diff(timestamps)
    mean_interval = float(np.mean(intervals))
    std_interval  = float(np.std(intervals))

    cmd_count    = sum(1 for e in events if e["msg_id"] == COMMAND_LONG)
    window_secs  = timestamps[-1] - timestamps[0] + 1e-9
    cmd_rate     = cmd_count / window_secs

    gps_events = [e for e in events if e["msg_id"] == GPS_INPUT]
    if len(gps_events) >= 2:
        dlat = gps_events[-1]["lat"] - gps_events[0]["lat"]
        dlon = gps_events[-1]["lon"] - gps_events[0]["lon"]
        gps_delta = math.sqrt(dlat**2 + dlon**2) * 111_139  # rough metres
    else:
        gps_delta = 0.0

    unique_msg_types = len({e["msg_id"] for e in events})

    port_counts: dict[int, int] = {}
    for e in events:
        port_counts[e["src_port"]] = port_counts.get(e["src_port"], 0) + 1
    source_port_entropy = _entropy(list(port_counts.values()))

    return np.array([
        mean_interval, std_interval, cmd_rate, gps_delta,
        unique_msg_types, source_port_entropy,
    ], dtype=np.float32)


def generate_legitimate_windows(n: int = 10_000) -> np.ndarray:
    """Simulate normal GCS traffic and return feature windows."""
    features = []
    rng = random.Random(42)

    for _ in range(n):
        events: List[dict] = []
        lat, lon = 37.7749, -122.4194
        ts = 0.0
        # 5-second window of normal traffic
        while ts < 5.0:
            # Heartbeat every ~1s (±0.05s jitter)
            hb_interval = 1.0 + rng.gauss(0, 0.05)
            ts += max(0.01, hb_interval)
            events.append({"ts": ts, "msg_id": HEARTBEAT,
                           "lat": lat, "lon": lon, "src_port": 14550})

            # Position update every ~0.5s
            gps_interval = 0.5 + rng.gauss(0, 0.02)
            ts += max(0.01, gps_interval)
            lat += rng.gauss(0, 1e-6)   # tiny drift < 0.1 m/s
            lon += rng.gauss(0, 1e-6)
            events.append({"ts": ts, "msg_id": GPS_INPUT,
                           "lat": lat, "lon": lon, "src_port": 14550})

        # Occasional mode change (10% chance)
        if rng.random() < 0.1:
            events.append({"ts": rng.uniform(0.5, 4.5), "msg_id": SET_MODE,
                           "lat": lat, "lon": lon, "src_port": 14550})
        events.sort(key=lambda e: e["ts"])
        features.append(_window_features(events))

    return np.array(features, dtype=np.float32)


def generate_attack_windows(n: int = 2_000) -> np.ndarray:
    """Simulate attack traffic (ARM injection, GPS spoof, mode change)."""
    features = []
    rng = random.Random(99)
    attacks = ["arm", "gps", "mode"]

    for i in range(n):
        attack = attacks[i % len(attacks)]
        events: List[dict] = []
        lat, lon = 37.7749, -122.4194
        ts = 0.0

        if attack == "arm":
            # Burst of ARM commands from unknown port
            for _ in range(rng.randint(5, 15)):
                ts += rng.uniform(0.01, 0.1)
                events.append({"ts": ts, "msg_id": COMMAND_LONG,
                               "lat": lat, "lon": lon,
                               "src_port": rng.randint(50000, 60000)})

        elif attack == "gps":
            # GPS jumps — large coordinate shifts in < 1s
            for step in range(12):
                ts += 0.4
                lat += rng.uniform(0.001, 0.005)  # ~100–500 m per step
                lon += rng.uniform(0.001, 0.005)
                events.append({"ts": ts, "msg_id": GPS_INPUT,
                               "lat": lat, "lon": lon, "src_port": 14550})

        elif attack == "mode":
            # Rapid mode changes from unknown sources
            for _ in range(rng.randint(3, 8)):
                ts += rng.uniform(0.05, 0.3)
                events.append({"ts": ts, "msg_id": SET_MODE,
                               "lat": lat, "lon": lon,
                               "src_port": rng.randint(40000, 50000)})

        # Sprinkle some noise packets
        for _ in range(rng.randint(1, 5)):
            ts += rng.uniform(0.1, 0.5)
            events.append({"ts": ts, "msg_id": HEARTBEAT,
                           "lat": lat, "lon": lon,
                           "src_port": rng.randint(20000, 65535)})

        events.sort(key=lambda e: e["ts"])
        if len(events) >= 2:
            features.append(_window_features(events))

    return np.array(features, dtype=np.float32)


if __name__ == "__main__":
    print("Generating legitimate windows…")
    legit = generate_legitimate_windows(10_000)
    print(f"  shape: {legit.shape}")

    print("Generating attack windows…")
    attacks = generate_attack_windows(2_000)
    print(f"  shape: {attacks.shape}")

    np.save("legitimate_features.npy", legit)
    np.save("attack_features.npy", attacks)
    print("Saved to legitimate_features.npy / attack_features.npy")
