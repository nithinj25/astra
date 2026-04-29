#!/usr/bin/env bash
# DroneShield — One-command launcher
# Usage: ./start.sh [--demo]

set -e

DEMO_FLAG=""
[[ "$1" == "--demo" ]] && DEMO_FLAG="--demo"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "  ██████╗ ██████╗  ██████╗ ███╗   ██╗███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ "
echo "  ██╔══██╗██╔══██╗██╔═══██╗████╗  ██║██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗"
echo "  ██║  ██║██████╔╝██║   ██║██╔██╗ ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║"
echo "  ██║  ██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║"
echo "  ██████╔╝██║  ██║╚██████╔╝██║ ╚████║███████╗███████║██║  ██║██║███████╗███████╗██████╔╝"
echo "  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ "
echo ""
echo "  MAVLink Protocol Intrusion Detection System"
echo "  ─────────────────────────────────────────────────────────────"
echo ""

# ── Check Python ──────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
  echo "ERROR: Python 3 not found. Install Python 3.11+."
  exit 1
fi

PYTHON=$(command -v python3 || command -v python)
echo "[*] Python: $($PYTHON --version)"

# ── Install Python deps ───────────────────────────────────────────────────────
echo "[*] Installing Python dependencies…"
$PYTHON -m pip install -q -r "$ROOT/requirements.txt"

# ── Pre-train ML model if needed ──────────────────────────────────────────────
if [ ! -f "$ROOT/ids/model.pkl" ]; then
  echo "[*] Pre-training anomaly model (first run, ~30s)…"
  $PYTHON -c "
import sys; sys.path.insert(0, '$ROOT/ids')
import anomaly_model; anomaly_model.initialize()
print('[*] Model saved to ids/model.pkl')
"
fi

# ── Check Node / npm ──────────────────────────────────────────────────────────
FRONTEND="$ROOT/dashboard/frontend"
if command -v npm &>/dev/null; then
  echo "[*] npm: $(npm --version)"
  if [ ! -d "$FRONTEND/node_modules" ]; then
    echo "[*] Installing frontend dependencies…"
    (cd "$FRONTEND" && npm install --silent)
  fi
  HAVE_NODE=1
else
  echo "[!] npm not found — dashboard frontend will not start."
  HAVE_NODE=0
fi

echo ""
echo "[*] Starting services…"

# ── Drone simulator ───────────────────────────────────────────────────────────
echo "[+] drone_sim        → UDP 14550"
$PYTHON "$ROOT/sim/drone_sim.py" &
SIM_PID=$!

sleep 0.5

# ── IDS proxy + FastAPI WebSocket ─────────────────────────────────────────────
echo "[+] ids_proxy        → UDP 14551 (IDS) | HTTP 8000 (WebSocket)"
$PYTHON "$ROOT/ids/ids_proxy.py" $DEMO_FLAG &
IDS_PID=$!

sleep 1.5

# ── React dashboard ───────────────────────────────────────────────────────────
if [ "$HAVE_NODE" = "1" ]; then
  echo "[+] vite dev server  → http://localhost:5173"
  (cd "$FRONTEND" && npm run dev -- --open) &
  VITE_PID=$!
fi

echo ""
echo "  ┌─────────────────────────────────────────────────────────┐"
echo "  │  DroneShield running!                                   │"
echo "  │  Dashboard:    http://localhost:5173                    │"
echo "  │  WebSocket:    ws://localhost:8000/ws                   │"
echo "  │  Drone sim:    UDP 14550                                │"
echo "  │  IDS proxy:    UDP 14551                                │"
if [[ -n "$DEMO_FLAG" ]]; then
echo "  │  DEMO MODE:    Attack starts in ~5 seconds…             │"
fi
echo "  │                                                         │"
echo "  │  Run attacker manually:                                 │"
echo "  │    python attacker/attacker.py --attack all             │"
echo "  │                                                         │"
echo "  │  Press Ctrl+C to stop all services.                     │"
echo "  └─────────────────────────────────────────────────────────┘"
echo ""

cleanup() {
  echo ""
  echo "[*] Shutting down DroneShield…"
  kill $SIM_PID  2>/dev/null || true
  kill $IDS_PID  2>/dev/null || true
  kill $VITE_PID 2>/dev/null || true
  wait
  echo "[*] Done."
}
trap cleanup INT TERM

wait
