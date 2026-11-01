"""
start.py — One-Click Master Launcher for AegisMesh-AI Full Application.

Launches:
  1. The 5 distributed UDP mesh nodes on localhost ports (51820 - 51824).
  2. The Groq-powered Autonomous AI Control Plane with FastMCP tool calling.
  3. The real-time Cybercore Web Dashboard on http://127.0.0.1:8080.
  4. Automatically opens your web browser to display the live network visualizer!

Run:
    python start.py
"""

import os
import sys
import time
import socket
import webbrowser
import threading

# Ensure both the parent folder (for 'import aegismesh') and local folder are in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)

for path in [PARENT_DIR, CURRENT_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

import uvicorn
from aegismesh.dashboard.server import app


def free_port(port: int):
    """If port is in use, automatically terminate the stale process so startup never fails."""
    try:
        import psutil
        current_pid = os.getpid()
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port == port and conn.pid and conn.pid != current_pid:
                try:
                    proc = psutil.Process(conn.pid)
                    print(f"[!] Port {port} occupied by PID {conn.pid} ({proc.name()}). Releasing...")
                    proc.kill()
                    proc.wait(timeout=2)
                except Exception:
                    pass
    except Exception:
        pass

    # Ensure port is released
    for _ in range(5):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) != 0:
                break
        time.sleep(0.3)


def main():
    port = 8080
    url = f"http://127.0.0.1:{port}"

    print("\n" + "=" * 70)
    print("      AEGIS-MESH AI: AUTONOMOUS SELF-HEALING MESH SDN")
    print("=" * 70)

    # Free port 8080 if lingering from a previous run
    free_port(port)

    print(f"\n[+] Booting 5 UDP Mesh Nodes (Ports 51820 - 51824)...")
    print(f"[+] Initializing Groq AI Control Plane (Llama-3.3-70B · FastMCP)...")
    print(f"[+] Starting Cybercore Real-Time Visualizer on {url}...")
    print(f"[+] Press Ctrl+C in this terminal to shut down.\n")

    # Automatically open browser after 1.2 seconds
    def open_browser():
        time.sleep(1.2)
        print(f"[BROWSER] Opening live visualizer dashboard at {url}...")
        webbrowser.open(url)

    t = threading.Thread(target=open_browser, daemon=True)
    t.start()

    # Start FastAPI / Uvicorn server
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
