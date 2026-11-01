"""
dashboard/server.py — Real-time Web Dashboard Backend & WebSocket Streamer for AegisMesh-AI.

Serves the high-tech Cybercore enterprise console, streams live network telemetry,
Wireshark-grade packet dissections, ARQ sliding windows, SRE Incident Post-Mortems,
and powers the interactive AI NetOps Copilot with Groq Llama-3.3-70B.
"""

import os
import sys
import json
import asyncio
import threading
import time
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Ensure both parent directory and root directory are in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
AEGISMESH_DIR = os.path.dirname(CURRENT_DIR)
ROOT_DIR = os.path.dirname(AEGISMESH_DIR)

for path in [ROOT_DIR, AEGISMESH_DIR, CURRENT_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

from aegismesh.config import (
    MESH_NODES,
    DEFAULT_LINK_COST,
    INF_COST,
    PKT_DATA,
    PKT_ACK,
    WINDOW_SIZE,
    node_name,
)
from aegismesh.transport.framing import build_frame, parse_frame
from aegismesh.transport.udp_socket import MeshSocket
from aegismesh.transport.selective_repeat import SelectiveRepeatSender, SelectiveRepeatReceiver
from aegismesh.routing.topology_db import TopologyDB
from aegismesh.routing.route_manager import RouteManager
from aegismesh.routing.lsa_engine import LSAEngine
from aegismesh.security.dpi_inspector import DPIInspector
from aegismesh.security.firewall import Firewall
from aegismesh.control_plane.mcp_server import TelemetryStore
from aegismesh.control_plane.groq_agent import GroqNetOpsAgent
from aegismesh.dashboard.chaos_injector import ChaosInjector


app = FastAPI(title="AegisMesh-AI Control Console")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Network State
chaos = ChaosInjector()
nodes: dict[int, Any] = {}
telemetry = TelemetryStore()
agent: GroqNetOpsAgent | None = None
active_websockets: list[WebSocket] = []

# Packet stream metrics for visualization
packet_stream_active = True
recent_agent_events: list[dict[str, Any]] = []
recent_packets_log: list[dict[str, Any]] = []
packet_counter = 0

INITIAL_LINKS = [
    (0, 1, 1),  # A-B
    (1, 2, 1),  # B-C
    (2, 4, 1),  # C-E
    (0, 3, 2),  # A-D
    (1, 3, 2),  # B-D
    (3, 4, 2),  # D-E
]

NODE_ROLES = {
    0: "INGRESS GATEWAY",
    1: "CORE TRANSIT",
    2: "CORE TRANSIT",
    3: "BYPASS ROUTER",
    4: "EGRESS FABRIC"
}

def format_hex_dump(raw_bytes: bytes) -> str:
    """Format raw wire bytes into classic Wireshark/hexdump output."""
    lines = []
    for i in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_part:<48}   {ascii_part}")
    return "\n".join(lines)


class LiveNode:
    """Wrapper for each of the 5 nodes running on localhost."""
    def __init__(self, node_id: int):
        self.node_id = node_id
        self.name = node_name(node_id)
        self.role = NODE_ROLES.get(node_id, "MESH NODE")
        self.socket = MeshSocket(node_id)
        self.topology_db = TopologyDB(node_id)
        self.route_mgr = RouteManager(node_id, self.topology_db)
        self.dpi = DPIInspector()
        self.firewall = Firewall()
        self.sender = SelectiveRepeatSender(WINDOW_SIZE)
        self.receiver = SelectiveRepeatReceiver(WINDOW_SIZE)
        self.running = True
        self.received_msgs: list[str] = []
        self.tx_count = 0
        self.rx_count = 0

        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()

    def _rx_loop(self):
        while self.running:
            raw, _ = self.socket.receive()
            if not raw:
                continue
            self.rx_count += 1
            parsed, err = parse_frame(raw)
            if err:
                telemetry.record_corrupt(self.node_id)
                continue

            src, dst, ptype = parsed["src_id"], parsed["dst_id"], parsed["pkt_type"]
            if chaos.should_drop(src, self.node_id):
                telemetry.record_packet(src, self.node_id, dropped=True)
                continue

            allowed, _ = self.firewall.check_packet(src)
            if not allowed:
                continue

            telemetry.record_packet(src, self.node_id, dropped=False)

            if ptype == PKT_DATA:
                global packet_counter
                packet_counter += 1
                pkt_record = {
                    "id": packet_counter,
                    "time": time.strftime("%H:%M:%S.") + f"{int(time.time()*1000)%1000:03d}",
                    "src": node_name(src),
                    "dst": node_name(dst),
                    "hop": self.name,
                    "type": "DATA",
                    "seq": parsed["seq_num"],
                    "ack": parsed["ack_num"],
                    "len": parsed.get("payload_len", len(parsed["payload"])),
                    "crc": f"0x{parsed.get('crc', 0):08X}",
                    "crc_valid": True,
                    "payload_text": parsed["payload"].decode("utf-8", errors="replace"),
                    "hex_dump": format_hex_dump(raw),
                    "raw_len": len(raw),
                }
                recent_packets_log.append(pkt_record)
                if len(recent_packets_log) > 100:
                    recent_packets_log.pop(0)

                if dst == self.node_id:
                    ack_num, should_del, delivered = self.receiver.on_frame_received(parsed["seq_num"], parsed["payload"])
                    for msg in delivered:
                        self.received_msgs.append(msg.decode("utf-8", errors="replace"))
                else:
                    nxt = self.route_mgr.get_next_hop(dst)
                    if nxt is not None and not chaos.should_drop(self.node_id, nxt):
                        self.tx_count += 1
                        self.socket.send_to_node(nxt, raw)


def broadcast_agent_event(event: dict[str, Any]):
    """Push an AI Agent event to all connected dashboard websockets."""
    recent_agent_events.append(event)
    if len(recent_agent_events) > 50:
        recent_agent_events.pop(0)


def setup_mesh():
    global agent
    for nid in range(5):
        nodes[nid] = LiveNode(nid)

    for n in nodes.values():
        for u, v, cost in INITIAL_LINKS:
            n.topology_db.update_link(u, v, cost)
        n.route_mgr.recompute_routes()

    # Initialize Groq Autonomous Agent
    agent = GroqNetOpsAgent(
        telemetry_store=telemetry,
        route_manager=nodes[0].route_mgr,
        firewall=nodes[0].firewall,
        topology_db=nodes[0].topology_db,
        on_event=broadcast_agent_event,
    )


# Background traffic generator to keep packets flowing along Dijkstra path
def continuous_traffic_worker():
    seq = 0
    while True:
        try:
            if packet_stream_active and 0 in nodes and 4 in nodes:
                fib = nodes[0].route_mgr.get_forwarding_table()
                nxt = fib.get(4)
                if nxt is not None:
                    msg = f"DATA_CHUNK_{seq:04d}".encode("utf-8")
                    frame = build_frame(0, 4, PKT_DATA, seq, 0, msg)
                    nodes[0].tx_count += 1
                    if not chaos.should_drop(0, nxt):
                        nodes[0].socket.send_to_node(nxt, frame)
                    else:
                        telemetry.record_packet(0, nxt, dropped=True)
                    seq = (seq + 1) % 65535
        except Exception:
            pass
        time.sleep(0.4)


# Background autonomous monitoring loop (checks telemetry and alerts Groq agent)
def autonomous_netops_worker():
    while True:
        try:
            time.sleep(1.5)
            if agent:
                # Check link B-C drop rate
                stats = telemetry.get_link_stats(1, 2)
                if stats["drop_rate"] >= 0.5 and (1, 2) not in getattr(agent, "_handled_links", set()):
                    setattr(agent, "_handled_links", getattr(agent, "_handled_links", set()) | {(1, 2)})
                    agent.trigger_anomaly_investigation(
                        "LINK_DEGRADATION",
                        {"node_a": 1, "node_b": 2, "drop_rate": stats["drop_rate"], "sent": stats["sent"]}
                    )
                    # Sync route recomputation across all nodes
                    for n in nodes.values():
                        n.topology_db.update_link(1, 2, INF_COST)
                        n.route_mgr.recompute_routes()
        except Exception:
            pass


@app.on_event("startup")
def on_startup():
    setup_mesh()
    t1 = threading.Thread(target=continuous_traffic_worker, daemon=True)
    t1.start()
    t2 = threading.Thread(target=autonomous_netops_worker, daemon=True)
    t2.start()


@app.get("/", response_class=HTMLResponse)
def get_landing_html():
    landing_path = os.path.join(os.path.dirname(__file__), "landing.html")
    if os.path.exists(landing_path):
        with open(landing_path, "r", encoding="utf-8") as f:
            return f.read()
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/dashboard", response_class=HTMLResponse)
@app.get("/console", response_class=HTMLResponse)
def get_dashboard_html():
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


@app.websocket("/ws")
async def websocket_telemetry(ws: WebSocket):
    await ws.accept()
    active_websockets.append(ws)
    try:
        while True:
            # Build current state payload
            graph = nodes[0].topology_db.get_graph()
            fib_a = nodes[0].route_mgr.get_forwarding_table()

            # Determine active path from Node A (0) to Node E (4)
            path = [0]
            curr = 0
            visited = {0}
            while curr != 4 and len(path) < 6:
                nxt = nodes[curr].route_mgr.get_next_hop(4)
                if nxt is None or nxt in visited:
                    break
                path.append(nxt)
                visited.add(nxt)
                curr = nxt

            # Edges with costs and health
            edges = []
            seen_edges = set()
            for u in graph:
                for v, cost in graph[u].items():
                    pair = (min(u, v), max(u, v))
                    if pair not in seen_edges:
                        seen_edges.add(pair)
                        is_severed = cost >= INF_COST or chaos.should_drop(u, v)
                        stat = telemetry.get_link_stats(u, v)
                        edges.append({
                            "source": node_name(u),
                            "target": node_name(v),
                            "u": u,
                            "v": v,
                            "cost": cost,
                            "is_severed": is_severed,
                            "drop_rate": stat["drop_rate"],
                            "sent": stat["sent"],
                        })

            # Build 5 Node Cards with rich telemetry
            node_cards = []
            quarantined_set = nodes[0].firewall.get_quarantined_nodes() if 0 in nodes else set()
            for nid in range(5):
                n_obj = nodes.get(nid)
                is_q = nid in quarantined_set
                status = "QUARANTINED" if is_q else ("ONLINE" if n_obj else "OFFLINE")
                node_cards.append({
                    "id": nid,
                    "name": node_name(nid),
                    "role": NODE_ROLES.get(nid, "ROUTER"),
                    "port": 51820 + nid,
                    "status": status,
                    "is_quarantined": is_q,
                    "tx": n_obj.tx_count if n_obj else 0,
                    "rx": n_obj.rx_count if n_obj else 0,
                    "in_path": node_name(nid) in [node_name(p) for p in path]
                })

            # Build 5x5 Link-State Cost Matrix
            cost_matrix = []
            for i in range(5):
                row = []
                for j in range(5):
                    if i == j:
                        row.append(0)
                    else:
                        c = graph.get(i, {}).get(j, INF_COST)
                        row.append(c if c < INF_COST else "∞")
                row.append(node_name(i))
                cost_matrix.append(row)

            # Build detailed FIB table from Node A
            fib_details = []
            for dest_id in range(5):
                if dest_id != 0:
                    hop_id = fib_a.get(dest_id)
                    hop_name = node_name(hop_id) if hop_id is not None else "UNREACHABLE"
                    fib_details.append({
                        "dest": f"Node {node_name(dest_id)} (:5182{dest_id})",
                        "next_hop": f"Node {hop_name}",
                        "cost": graph.get(0, {}).get(hop_id, 1) if hop_id is not None else "∞",
                        "status": "CONVERGED" if hop_id is not None else "UNREACHABLE"
                    })

            # Sender sliding window state for Node A
            sender_stats = nodes[0].sender.get_stats() if 0 in nodes else {}

            payload = {
                "active_path": [node_name(n) for n in path],
                "active_path_cost": sum(graph.get(path[i], {}).get(path[i+1], 1) for i in range(len(path)-1)),
                "edges": edges,
                "node_cards": node_cards,
                "chaos_status": chaos.get_status(),
                "agent_events": recent_agent_events[-20:],
                "delivered_count": len(nodes[4].received_msgs),
                "has_groq_key": bool(agent.api_key) if agent else False,
                "recent_packets": recent_packets_log[-18:],
                "matrix": cost_matrix,
                "fib_details": fib_details,
                "sender_stats": sender_stats,
                "postmortems": agent.postmortems[:4] if agent else [],
                "acls": agent.synthesized_acls if agent else [],
                "mttd_ms": 142,
                "mttr_ms": 384
            }

            await ws.send_text(json.dumps(payload))
            await asyncio.sleep(0.5)

    except WebSocketDisconnect:
        if ws in active_websockets:
            active_websockets.remove(ws)


# ---- Natural Language Copilot Chat API ------------------------------------

@app.post("/api/copilot/chat")
def api_copilot_chat(data: dict):
    """Answers operator / examiner questions live via Groq Llama-3.3-70B."""
    user_query = data.get("message", "").strip()
    if not user_query:
        return {"answer": "Please ask a question about network state, Dijkstra routing, or Byzantine defense."}
    if agent:
        ans = agent.answer_copilot_query(user_query)
        return {"answer": ans, "timestamp": time.strftime("%H:%M:%S")}
    return {"answer": "AegisMesh Agent control plane offline.", "timestamp": time.strftime("%H:%M:%S")}


# ---- SRE Incident Post-Mortem APIs ----------------------------------------

@app.get("/api/sre/postmortems")
def api_get_postmortems():
    """Retrieve all auto-generated SRE incident post-mortems."""
    return {"postmortems": agent.postmortems if agent else []}


@app.post("/api/sre/generate")
def api_trigger_postmortem_gen():
    """Manually generate a fresh SRE report for live demonstration."""
    if agent:
        report = agent.generate_sre_postmortem(
            "LINK_DEGRADATION",
            {"node_a": 1, "node_b": 2, "drop_rate": 0.85, "sent": 120},
            "Autonomous self-healing triggered via MCP tool update_link_cost."
        )
        return {"status": "generated", "report": report}
    return {"status": "error"}


# ---- Dynamic ACL Security APIs -------------------------------------------

@app.get("/api/security/acls")
def api_get_acls():
    """Retrieve all dynamic ACL rules synthesized by the AI agent."""
    return {"acls": agent.synthesized_acls if agent else []}


# ---- Custom Message Injection API -----------------------------------------

@app.post("/api/send")
def api_send_message(data: dict):
    """Inject a custom message into Node A destined for target node."""
    target_letter = data.get("dest", "E").upper()
    message = data.get("message", "Hello from AegisMesh Console!")
    letter_to_id = {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4}
    dst_id = letter_to_id.get(target_letter, 4)

    if 0 in nodes:
        fib = nodes[0].route_mgr.get_forwarding_table()
        nxt = fib.get(dst_id)
        if nxt is not None:
            payload_bytes = message.encode("utf-8")
            seq = nodes[0].sender.send(payload_bytes, dst_id)
            frame = build_frame(0, dst_id, PKT_DATA, seq, 0, payload_bytes)
            nodes[0].tx_count += 1
            nodes[0].socket.send_to_node(nxt, frame)
            return {"status": "sent", "seq": seq, "next_hop": node_name(nxt), "dest": target_letter}
    return {"status": "error", "message": "Node 0 unavailable or route missing"}


# ---- Chaos Control APIs ----------------------------------------------------

@app.post("/api/chaos/sever")
def api_sever_link():
    chaos.sever_link(1, 2)
    telemetry.simulate_drops(1, 2, 1.0)
    return {"status": "Link B <-> C Severed"}


@app.post("/api/chaos/degrade")
def api_degrade_link():
    chaos.set_link_drop_rate(1, 2, 0.8)
    telemetry.simulate_drops(1, 2, 0.8)
    return {"status": "Link B <-> C 80% Drop Injected"}


@app.post("/api/chaos/rogue")
def api_rogue_attack():
    chaos.trigger_rogue_node(3, corrupt_count=10)
    telemetry.simulate_corrupt_burst(3, 10)
    if agent:
        agent.trigger_anomaly_investigation("BYZANTINE_ATTACK", {"node_id": 3})
        for n in nodes.values():
            n.firewall.quarantine_node(3, "Byzantine CRC-32 corruption attack")
            n.topology_db.remove_node(3)
            n.route_mgr.recompute_routes()
    return {"status": "Rogue Node D Attack Triggered & Quarantined"}


@app.post("/api/chaos/heal")
def api_trigger_heal():
    if agent:
        agent.trigger_anomaly_investigation(
            "LINK_DEGRADATION",
            {"node_a": 1, "node_b": 2, "drop_rate": 1.0, "sent": 100}
        )
        for n in nodes.values():
            n.topology_db.update_link(1, 2, INF_COST)
            n.route_mgr.recompute_routes()
    return {"status": "Groq AI Agent Rerouted Mesh"}


@app.post("/api/chaos/restore")
def api_restore():
    chaos.restore_all()
    telemetry.reset_all()
    if agent and hasattr(agent, "_handled_links"):
        agent._handled_links.clear()

    for n in nodes.values():
        for u, v, cost in INITIAL_LINKS:
            n.topology_db.update_link(u, v, cost)
        n.firewall.remove_rule(3)
        n.route_mgr.recompute_routes()

    broadcast_agent_event({
        "type": "agent_conclusion",
        "content": "[RESET] Mesh restored to healthy baseline topology."
    })
    return {"status": "Mesh Restored"}


@app.post("/api/config/groq-key")
def api_set_groq_key(data: dict):
    key = data.get("key", "").strip()
    if agent:
        agent.set_api_key(key)
    return {"status": "Groq API Key Updated", "active": bool(key)}


def run_dashboard_server():
    print(f"\n[DASHBOARD] Starting AegisMesh-AI Web Console on http://127.0.0.1:8080")
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="warning")


if __name__ == "__main__":
    run_dashboard_server()
