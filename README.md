# DroneShield — MAVLink Intrusion Detection System

> A real-time network security system that monitors, analyzes, and blocks attacks on consumer drone communication protocols — built from scratch without any MAVLink library.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat&logo=python&logoColor=white)
![Node](https://img.shields.io/badge/Node.js-18%2B-339933?style=flat&logo=node.js&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109%2B-009688?style=flat&logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat)

---

## What is DroneShield?

DroneShield is a **man-in-the-middle intrusion detection system** for the MAVLink protocol — the standard communication language used by drones running ArduPilot and PX4 firmware.

It sits between a ground control station (GCS) and the drone's flight controller, inspecting every packet in real time using:

- **Rule-based detection** — catches unauthorized arming, GPS spoofing, and mode hijacking
- **Isolation Forest ML model** — detects behavioral anomalies that rules alone miss
- **FastAPI WebSocket server** — streams live events to the browser dashboard
- **React dashboard** — Palantir-style SOC interface with threat intelligence, attack timelines, source tracking, and event export

The entire MAVLink v2 parser is implemented by hand — no `pymavlink`, no external protocol libraries.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DroneShield                                    │
│                                                                             │
│  ┌──────────────┐    UDP      ┌─────────────────────────┐    UDP           │
│  │  Ground      │  :14551     │   IDS Proxy             │  :14550          │
│  │  Control     │ ──────────► │   (ids_proxy.py)        │ ──────────►  ✈  │
│  │  Station /   │             │                         │           Drone  │
│  │  Attacker    │             │  ┌─────────────────┐    │                  │
│  └──────────────┘             │  │  Rule Engine    │    │                  │
│                               │  │  - ARM inject   │    │                  │
│  ┌──────────────┐    UDP      │  │  - GPS spoof    │    │                  │
│  │  Drone Sim   │  :14550     │  │  - Mode change  │    │                  │
│  │  (Python)    │ ◄────────── │  │  - Rate limit   │    │                  │
│  └──────────────┘             │  └────────┬────────┘    │                  │
│                               │           │             │                  │
│                               │  ┌────────▼────────┐    │                  │
│                               │  │  Isolation      │    │                  │
│                               │  │  Forest ML      │    │                  │
│                               │  └────────┬────────┘    │                  │
│                               └───────────┼─────────────┘                  │
│                                           │ WebSocket :8000/ws              │
│                               ┌───────────▼─────────────┐                  │
│                               │   React Dashboard        │                  │
│                               │   localhost:5173         │                  │
│                               │   - Event stream         │                  │
│                               │   - Threat intelligence  │                  │
│                               │   - Protocol charts      │                  │
│                               │   - Source tracker       │                  │
│                               └──────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.11 or newer | [python.org](https://python.org/downloads) |
| Node.js | 18 or newer | [nodejs.org](https://nodejs.org) |
| npm | comes with Node | — |
| Git | any | [git-scm.com](https://git-scm.com) |

> **Windows users:** tick "Add Python to PATH" during the Python installer.

---

## Quick Start

```bash
# 1 — Clone
git clone https://github.com/nithinj25/astra.git
cd astra
```

**macOS / Linux**
```bash
chmod +x start.sh
./start.sh
```

**Windows** — double-click `start.bat`, or run in terminal:
```bat
start.bat
```

Open **http://localhost:5173** — the dashboard loads automatically.

The launcher handles venv creation, dependency installation, and starts all three services.

---

## Manual Setup

If the one-command launcher doesn't work, use these steps.

### Python environment

```bash
python -m venv venv

# Activate — macOS/Linux:
source venv/bin/activate
# Activate — Windows:
venv\Scripts\activate

pip install -r requirements.txt
```

### Frontend

```bash
cd dashboard/frontend
npm install
cd ../..
```

### Run (3 separate terminals)

**Terminal 1 — Drone Simulator**
```bash
source venv/bin/activate   # Windows: venv\Scripts\activate
python sim/drone_sim.py
```

**Terminal 2 — IDS Proxy + WebSocket**
```bash
source venv/bin/activate
python ids/ids_proxy.py
```

**Terminal 3 — React Dashboard**
```bash
cd dashboard/frontend
npm run dev
```

Open **http://localhost:5173**

---

## Ports

| Service | Protocol | Port |
|---------|----------|------|
| Drone Simulator | UDP | 14550 |
| IDS Proxy (listener) | UDP | 14551 |
| IDS WebSocket + REST | HTTP/WS | 8000 |
| React Dashboard | HTTP | 5173 |

**Kill stale processes if ports are in use:**

```bash
# macOS/Linux
lsof -ti:14550,14551,8000,5173 | xargs kill -9
```
```powershell
# Windows PowerShell
@(14550,14551,8000,5173) | ForEach-Object {
  (Get-NetTCPConnection -LocalPort $_ -EA 0).OwningProcess |
  ForEach-Object { Stop-Process -Id $_ -Force -EA 0 }
}
```

---

## Dashboard Features

### Event Stream (left panel)
Real-time table of every intercepted MAVLink packet.

- **Filter bar** — toggle by verdict: All / Block / Alert / Pass
- **Text search** — filter by rule name, source IP, or protocol type
- **Click any row** — opens full event detail modal (`Esc` to close)

### Event Detail Modal
Clicking a row shows:
- Decoded MAVLink fields for the triggered rule (command ID, parameters, source)
- Drone state snapshot at the exact moment of the event (armed/safe, mode, GPS position)
- Operational impact — what the attack was trying to achieve if it succeeded
- MITRE ATT&CK for ICS technique reference
- IDS action — blocked vs forwarded, with reason

### Threat Score Timeline
Rolling 60-second Recharts plot of the Isolation Forest anomaly score. A threshold line separates nominal from anomalous behavior.

### Flight Instruments Strip
Horizontal HUD bar below the header showing live flight telemetry:
- **Flight phase** — color-coded pill: PREFLIGHT / ARMED / TAKEOFF / CRUISE
- **Battery** — 8-segment bar with percentage
- **GPS** — satellite count + fix quality (LOCK / WEAK / NO FIX)
- **Groundspeed** — m/s
- **Heading** — degrees + cardinal direction (N/NE/E/…)
- **Geofence** — NOMINAL (green) or BREACH (red) relative to 300m home perimeter

### Drone Position Map
Live SVG plot of GPS position history within a 300m geofence circle.
- Green line — legitimate flight path
- Red dots — GPS spoof injection points
- Cyan arrow — drone heading indicator
- Pulsing red ring — active geofence breach animation
- Battery/speed overlay in the corner

### Tab Panel (bottom right)

| Tab | Content |
|-----|---------|
| **Threat Intel** | Active attack classification with CVSS score, impact description, MITRE ATT&CK for ICS reference, and IDS response |
| **Protocol Stats** | Stacked bar chart of MAVLink message types broken down by Pass / Alert / Block |
| **Source Tracker** | Per-IP table: total packets, blocked, alerted, risk %, last seen |
| **Timeline** | Forensic SVG attack timeline — 120s window, attack clusters highlighted, click to inspect |
| **Alert Queue** | SOC acknowledge workflow — Pending / Investigated split with one-click acknowledgment |

### Stat Cards

| Card | Metric |
|------|--------|
| Intercepted | Total packets seen this session |
| Blocked | Count + percentage blocked |
| Alerts | Count + percentage flagged |
| Threat Score | Current Isolation Forest output |
| Pkt/s | 5-second rolling packet rate |
| Prevented | Total attacks blocked this session |

### Export
- **Export JSON** — full event log with all fields as a timestamped `.json` file
- **Export CSV** — spreadsheet-friendly format with one row per event

---

## Simulation Controls

Use the command bar at the bottom of the dashboard:

| Button | What it simulates | Rule triggered |
|--------|-------------------|----------------|
| **Normal Flight** | Orbital cruise: PREFLIGHT → ARMED → TAKEOFF → CRUISE | — |
| **ARM Inject** | Unauthorized motor arm from rogue GCS port | `UNTRUSTED_ARM` |
| **GPS Spoof** | Forged position with >50 m jump | `GPS_JUMP` |
| **Mode Change** | SET_MODE from untrusted source | `UNEXPECTED_MODE_CHANGE` |
| **Param Tamper** | PARAM_SET disabling FENCE_ACTION and FS_GCS_ENABLE | `PARAM_TAMPER` |
| **Mission Inject** | Hostile waypoint upload (Washington DC target) | `MISSION_INJECT` |
| **HB Spoof** | Heartbeats cycling 10 fake sys_ids from same IP | `HEARTBEAT_SPOOF` |
| **Full Attack** | Full sequence: all 6 attack types in succession | all rules |
| **Stop** | Stops all attacks |

Or run the attacker directly from a terminal:

```bash
python attacker/attacker.py --attack arm      # ARM injection
python attacker/attacker.py --attack gps      # GPS spoofing
python attacker/attacker.py --attack mode     # Mode hijacking
python attacker/attacker.py --attack param    # Parameter tampering
python attacker/attacker.py --attack mission  # Mission injection
python attacker/attacker.py --attack spoof    # Heartbeat spoofing
python attacker/attacker.py --attack all      # All attacks
```

---

## Attack Types & Detection

### UNTRUSTED_ARM — CRITICAL (CVSSv3 9.1)
**MITRE ICS T0883 — Unauthorized Command Message**

`COMMAND_LONG(MAV_CMD_COMPONENT_ARM_DISARM=400)` from an unregistered GCS port. If accepted, motors activate without operator knowledge — physical hazard to anyone near the drone.

**Detection:** Trusted sources are registered via heartbeat on port 14552. Any ARM from an unknown source is dropped.

---

### GPS_JUMP — HIGH (CVSSv3 8.5)
**MITRE ICS T0856 — Spoof Reporting Message**

`GPS_INPUT` packet with position delta > 50 m in under one second — physically impossible for the flight envelope. Accepting forged coordinates hands navigation to the attacker.

**Detection:** Haversine distance between consecutive GPS fixes; jumps over threshold are blocked.

---

### UNEXPECTED_MODE_CHANGE — HIGH (CVSSv3 7.8)
**MITRE ICS T0855 — Unauthorized Mode Change**

`SET_MODE` from a source not in the trusted registry. Attacker can force `RTL`, `LAND`, or `GUIDED` — redirecting the flight path or injecting waypoints covertly.

**Detection:** Mode changes only accepted from registered trusted sources.

---

### PARAM_TAMPER — CRITICAL (CVSSv3 9.3)
**MITRE ICS T0836 — Modify Parameter**

`PARAM_SET` from an unregistered source targeting flight-critical parameters: `FENCE_ACTION=0` (disables geofencing), `FS_GCS_ENABLE=0` (disables GCS failsafe), `ARMING_CHECK=0` (disables arming checks). Successful modification removes safety constraints silently.

**Detection:** Any PARAM_SET from a source not in the trusted registry is blocked.

---

### MISSION_INJECT — CRITICAL (CVSSv3 9.0)
**MITRE ICS T0840 — Network Connection Enumeration**

`MISSION_COUNT` + `MISSION_ITEM` from an unregistered source. Attacker uploads a replacement flight plan directing the drone to hostile coordinates (demonstrated: Washington DC) without operator knowledge.

**Detection:** Mission uploads only accepted from trusted GCS. Current mission plan preserved on block.

---

### HEARTBEAT_SPOOF — HIGH (CVSSv3 7.5)
**MITRE ICS T0886 — Remote System Discovery**

A single source IP sends `HEARTBEAT` packets cycling through multiple system IDs within a 30-second window. The goal is to register multiple fake GCS identities in the IDS trust registry, enabling subsequent unauthorized commands.

**Detection:** More than one unique sys_id from the same IP within 30 seconds → ALERT.

---

### GEOFENCE_BREACH — HIGH (CVSSv3 8.0)
**MITRE ICS T0856 — Spoof Reporting Message**

GPS position update places the drone beyond the 300m operational geofence. This is the signature of slow-drift GPS spoofing — incrementally shifting position by <50m per tick to evade GPS_JUMP detection, gradually relocating the drone outside safe airspace.

**Detection:** Haversine distance from home position (37.7749°N, 122.4194°W) exceeds 300m. ALERT raised; RTL recommended.

---

### RATE_LIMIT — MEDIUM (CVSSv3 6.5)
**MITRE ICS T0814 — Denial of Service**

Packet rate > 20 pkt/s from a single source. Saturates the MAVLink serial budget, delays legitimate GCS telemetry, and can trigger the flight-controller watchdog failsafe.

**Detection:** Per-source sliding-window rate counter; excess packets dropped.

---

## How the ML Works

The Isolation Forest model was trained on 12,000 synthetic MAVLink sequences. Each 5-second window is featurized into 6 dimensions:

| Feature | What it captures |
|---------|-----------------|
| `mean_interval` | Average inter-packet gap |
| `std_interval` | Timing variance — floods have very low variance |
| `cmd_rate` | COMMAND_LONG frequency |
| `gps_delta` | Average position change per packet |
| `unique_msg_types` | Diversity of message types |
| `source_port_entropy` | Source port randomness |

Score > 0.15 → `ALERT` · Score > 0.45 → `CRITICAL`

The pre-trained `ids/model.pkl` is included — no retraining needed on first run.

---

## Project Structure

```
droneshield/
├── ids/
│   ├── ids_proxy.py              # Core IDS — MitM proxy, FastAPI, WebSocket
│   ├── rule_engine.py            # Signature-based detection rules
│   ├── anomaly_model.py          # Isolation Forest wrapper
│   └── model.pkl                 # Pre-trained model (~1 MB)
├── sim/
│   └── drone_sim.py              # Simulated ArduPilot flight controller
├── attacker/
│   └── attacker.py               # Attack packet injector
├── replay/
│   └── replay_sim.py             # Replay saved attack sequences
├── data/
│   └── generate_training_data.py # ML training data generator
├── dashboard/
│   └── frontend/
│       └── src/
│           ├── App.tsx                    # Root — layout, WebSocket, state
│           ├── components/
│           │   ├── PacketFeed.tsx         # Filterable event stream
│           │   ├── ThreatGraph.tsx        # 60s threat score chart
│           │   ├── AttackMap.tsx          # Live GPS map
│           │   ├── ThreatIntel.tsx        # CVSS/MITRE threat cards
│           │   ├── ProtocolChart.tsx      # Protocol distribution chart
│           │   ├── SourceTracker.tsx      # Per-IP statistics
│           │   └── EventDrawer.tsx        # Event detail modal
│           └── data/
│               └── ruleIntel.ts           # MITRE ATT&CK / CVSS database
├── requirements.txt
├── start.sh                      # One-command launcher (macOS/Linux)
├── start.bat                     # One-command launcher (Windows)
└── README.md
```

---

## Troubleshooting

**Dashboard shows "RECONNECTING"**
1. Confirm `ids_proxy.py` is running: `curl http://localhost:8000/health`
2. Start the IDS before opening the browser

**Port already in use** — see the port cleanup commands in the [Ports](#ports) section above.

**Model not found**
```bash
python -c "import sys; sys.path.insert(0,'ids'); import anomaly_model; anomaly_model.initialize()"
```

**Windows: UDP packets not received**
The IDS proxy forces `WindowsSelectorEventLoopPolicy` at startup to work around a bug in Python's `ProactorEventLoop` where UDP receive silently fails. Ensure you're using the included `ids_proxy.py` and Python 3.11+.

**Frontend build errors**
```bash
cd dashboard/frontend
rm -rf node_modules package-lock.json   # macOS/Linux
# Windows: rmdir /s /q node_modules && del package-lock.json
npm install
npm run dev
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| IDS Core | Python 3.11, asyncio, raw sockets |
| API / WebSocket | FastAPI, Uvicorn |
| ML | scikit-learn Isolation Forest, NumPy |
| Protocol | MAVLink v2 — hand-written parser |
| Frontend | React 18, TypeScript, Vite |
| Styling | Tailwind CSS |
| Charts | Recharts |

---

## License

MIT — do whatever you want with it.

---

*Built by [@nithinj25](https://github.com/nithinj25)*
