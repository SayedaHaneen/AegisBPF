import os
import sys
import json
import signal
import asyncio
import threading
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from bcc import BPF
from agent.threat_engine import ThreatEngine

app = FastAPI(title="AegisBPF Tactical SOC Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State
connected_clients = set()
event_loop = None
async_queue = None
threat_engine = ThreatEngine()

telemetry_stats = {
    "total_events": 0,
    "critical_threats": 0,
    "active_probes": 3,
    "kernel_version": os.uname().release if hasattr(os, "uname") else "Linux",
}

PROJECT_ROOT = Path(__file__).parent.parent
PROBE_SOURCE = PROJECT_ROOT / "agent" / "probes.c"
DASHBOARD_FILE = PROJECT_ROOT / "dashboard" / "index.html"

# BPF Event Callback (Runs in worker thread)
def perf_event_callback(cpu, data, size):
    global telemetry_stats
    event = b["events"].event(data)
    enriched = threat_engine.evaluate(event)

    telemetry_stats["total_events"] += 1
    if enriched.get("severity") == "CRITICAL":
        telemetry_stats["critical_threats"] += 1

    # Print clean colorized terminal alert
    sev = enriched["severity"]
    if sev == "CRITICAL":
        print(f"\033[91m[CRITICAL THREAT] {enriched['threat']} | PID: {enriched['pid']} | {enriched['comm']}\033[0m")
    elif sev == "LOW":
        print(f"\033[93m[NOTICE] {enriched['event_type']} | {enriched.get('description')}\033[0m")

    # Pass to AsyncIO queue for WebSocket distribution
    if async_queue and event_loop:
        asyncio.run_coroutine_threadsafe(async_queue.put(enriched), event_loop)

# Background BPF Polling Loop
def bpf_polling_loop():
    while True:
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Polling exception: {e}")

# WebSocket Broadcast Task
async def broadcast_loop():
    while True:
        event = await async_queue.get()
        message = json.dumps(event)
        disconnected = set()
        for client in connected_clients:
            try:
                await client.send_text(message)
            except Exception:
                disconnected.add(client)
        connected_clients.difference_update(disconnected)

@app.on_event("startup")
async def startup_event():
    global b, event_loop, async_queue
    event_loop = asyncio.get_running_loop()
    async_queue = asyncio.Queue()

    print("[*] Initializing eBPF Probes from:", PROBE_SOURCE)
    with open(PROBE_SOURCE, "r") as f:
        probe_code = f.read()

    b = BPF(text=probe_code)
    b["events"].open_perf_buffer(perf_event_callback)
    print("[+] eBPF Probes loaded successfully into Linux Kernel!")

    # Start BPF poller in separate OS thread
    t = threading.Thread(target=bpf_polling_loop, daemon=True)
    t.start()

    # Start WebSocket broadcaster
    asyncio.create_task(broadcast_loop())

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    if not DASHBOARD_FILE.exists():
        return HTMLResponse("<h1>Dashboard index.html not found!</h1>", status_code=404)
    with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/api/stats")
async def get_stats():
    return JSONResponse(content=telemetry_stats)

@app.post("/api/simulate")
async def trigger_simulation(data: dict):
    sim_type = data.get("type")
    sim_dir = PROJECT_ROOT / "simulations"

    if sim_type == "reverse_shell":
        script = sim_dir / "test_reverse_shell.py"
        subprocess.Popen([sys.executable, str(script)])
        return {"status": "success", "message": "Triggered Reverse Shell (T1071) Simulation"}
    elif sim_type == "ram_exec":
        script = sim_dir / "test_ram_exec.sh"
        subprocess.Popen(["bash", str(script)])
        return {"status": "success", "message": "Triggered Fileless RAM Exec (T1059) Simulation"}
    elif sim_type == "injection":
        script = sim_dir / "test_injection.py"
        subprocess.Popen([sys.executable, str(script)])
        return {"status": "success", "message": "Triggered Process Injection (T1055) Simulation"}
    else:
        return JSONResponse({"status": "error", "message": "Unknown simulation type"}, status_code=400)

@app.post("/api/kill")
async def kill_process(data: dict):
    pid = data.get("pid")
    if not pid:
        return JSONResponse({"status": "error", "message": "Missing PID"}, status_code=400)
    try:
        os.kill(int(pid), signal.SIGKILL)
        print(f"\033[92m[CONTAINMENT] Process {pid} terminated via SIGKILL.\033[0m")
        return {"status": "success", "message": f"PID {pid} successfully neutralized via SIGKILL"}
    except ProcessLookupError:
        return {"status": "warning", "message": f"PID {pid} already dead"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        while True:
            # Keep-alive ping
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.discard(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=8000, reload=False)
