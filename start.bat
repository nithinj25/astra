@echo off
:: DroneShield — Windows one-command launcher
:: Usage: start.bat

setlocal EnableDelayedExpansion
set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"

echo.
echo   ██████╗ ██████╗  ██████╗ ███╗   ██╗███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗
echo   ██╔══██╗██╔══██╗██╔═══██╗████╗  ██║██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
echo   ██║  ██║██████╔╝██║   ██║██╔██╗ ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║
echo   ██║  ██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
echo   ██████╔╝██║  ██║╚██████╔╝██║ ╚████║███████╗███████║██║  ██║██║███████╗███████╗██████╔╝
echo   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
echo.
echo   MAVLink Protocol Intrusion Detection System
echo   ─────────────────────────────────────────────────────────────────────
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.11+ from https://python.org
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version') do echo [*] %%v

:: Create venv if needed
if not exist "%ROOT%\venv\" (
    echo [*] Creating virtual environment...
    python -m venv "%ROOT%\venv"
)

:: Install Python deps
echo [*] Installing Python dependencies...
"%ROOT%\venv\Scripts\pip.exe" install -q -r "%ROOT%\requirements.txt"

:: Pre-train model if missing
if not exist "%ROOT%\ids\model.pkl" (
    echo [*] Training anomaly model (first run, ~30s)...
    "%ROOT%\venv\Scripts\python.exe" -c "import sys; sys.path.insert(0,'%ROOT%\ids'); import anomaly_model; anomaly_model.initialize()"
)

:: Check Node
npm --version >nul 2>&1
if errorlevel 1 (
    echo [!] npm not found — frontend will not start. Install Node.js from https://nodejs.org
    set HAVE_NODE=0
) else (
    for /f "tokens=*" %%v in ('npm --version') do echo [*] npm %%v
    set HAVE_NODE=1
)

:: Install frontend deps
if "!HAVE_NODE!"=="1" (
    if not exist "%ROOT%\dashboard\frontend\node_modules\" (
        echo [*] Installing frontend dependencies...
        pushd "%ROOT%\dashboard\frontend"
        npm install --silent
        popd
    )
)

echo.
echo [*] Starting services...

:: Drone simulator
echo [+] drone_sim    ^>  UDP 14550
start "DroneShield — Drone Sim" /min "%ROOT%\venv\Scripts\python.exe" "%ROOT%\sim\drone_sim.py"
timeout /t 1 /nobreak >nul

:: IDS proxy + WebSocket
echo [+] ids_proxy    ^>  UDP 14551 (IDS proxy)  /  HTTP 8000 (WebSocket)
start "DroneShield — IDS Proxy" /min "%ROOT%\venv\Scripts\python.exe" "%ROOT%\ids\ids_proxy.py"
timeout /t 2 /nobreak >nul

:: React dashboard
if "!HAVE_NODE!"=="1" (
    echo [+] vite dev    ^>  http://localhost:5173
    pushd "%ROOT%\dashboard\frontend"
    start "DroneShield — Dashboard" npm run dev -- --open
    popd
)

echo.
echo   ┌──────────────────────────────────────────────────────┐
echo   │  DroneShield is running!                             │
echo   │                                                      │
echo   │  Dashboard   :  http://localhost:5173                │
echo   │  WebSocket   :  ws://localhost:8000/ws               │
echo   │  IDS Health  :  http://localhost:8000/health         │
echo   │  Drone sim   :  UDP 14550                            │
echo   │  IDS proxy   :  UDP 14551                            │
echo   │                                                      │
echo   │  Close the console windows to stop all services.     │
echo   └──────────────────────────────────────────────────────┘
echo.
pause
