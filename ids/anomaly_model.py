"""
DroneShield — ML Anomaly Detection Layer
Isolation Forest trained on synthetic MAVLink traffic.
Persists trained model to model.pkl.
"""
import os
import sys
import math
import time
import logging
import numpy as np
from collections import deque
from typing import Optional

logger = logging.getLogger("ids.anomaly")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
ALERT_THRESHOLD = -0.15   # decision_function score below this → ALERT
WINDOW_SECONDS  = 5.0

_model = None
_window: deque = deque()   # recent packet events


def _load_or_train() -> None:
    global _model
    import joblib

    if os.path.exists(MODEL_PATH):
        logger.info(f"Loading model from {MODEL_PATH}")
        _model = joblib.load(MODEL_PATH)
        return

    logger.info("model.pkl not found — training Isolation Forest…")
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "data"))
    from generate_training_data import generate_legitimate_windows, generate_attack_windows
    from sklearn.ensemble import IsolationForest

    legit   = generate_legitimate_windows(10_000)
    attacks = generate_attack_windows(2_000)
    X_train = np.vstack([legit, attacks])

    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)
    joblib.dump(model, MODEL_PATH)
    logger.info(f"Model trained and saved to {MODEL_PATH}")
    _model = model


def _compute_features(events: list) -> np.ndarray:
    if len(events) < 2:
        return np.zeros(6, dtype=np.float32)

    timestamps    = [e["ts"] for e in events]
    intervals     = np.diff(timestamps)
    mean_interval = float(np.mean(intervals))
    std_interval  = float(np.std(intervals))

    window_secs = timestamps[-1] - timestamps[0] + 1e-9
    cmd_count   = sum(1 for e in events if e["msg_id"] == 76)  # COMMAND_LONG
    cmd_rate    = cmd_count / window_secs

    gps_evts = [e for e in events if e["msg_id"] == 232 and e["lat"] != 0.0]
    if len(gps_evts) >= 2:
        dlat = gps_evts[-1]["lat"] - gps_evts[0]["lat"]
        dlon = gps_evts[-1]["lon"] - gps_evts[0]["lon"]
        gps_delta = math.sqrt(dlat**2 + dlon**2) * 111_139
    else:
        gps_delta = 0.0

    unique_msg_types = len({e["msg_id"] for e in events})

    port_counts: dict = {}
    for e in events:
        port_counts[e["src_port"]] = port_counts.get(e["src_port"], 0) + 1
    total = sum(port_counts.values())
    entropy = -sum((c / total) * math.log2(c / total) for c in port_counts.values() if c > 0)

    return np.array([
        mean_interval, std_interval, cmd_rate, gps_delta,
        unique_msg_types, entropy,
    ], dtype=np.float32)


def initialize() -> None:
    _load_or_train()


def score_packet(msg_id: int, src_port: int,
                 lat: float = 0.0, lon: float = 0.0) -> tuple[float, str]:
    """
    Add packet to sliding window and return (score, verdict).
    score is the raw decision_function value (more negative = more anomalous).
    verdict is "ALLOW" or "ALERT".
    """
    global _window

    if _model is None:
        _load_or_train()

    now = time.time()
    _window.append({"ts": now, "msg_id": msg_id, "src_port": src_port,
                    "lat": lat, "lon": lon})

    # Prune events outside the 5-second window
    cutoff = now - WINDOW_SECONDS
    while _window and _window[0]["ts"] < cutoff:
        _window.popleft()

    if len(_window) < 2:
        return 0.0, "ALLOW"

    features = _compute_features(list(_window))
    score    = float(_model.decision_function([features])[0])
    verdict  = "ALERT" if score < ALERT_THRESHOLD else "ALLOW"
    return score, verdict
