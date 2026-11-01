"""
main.py — Entry point for running a physical or local AegisMesh node.

Usage:
    python main.py --node-id 0

This script initializes all networking layers on the local machine:
  1. Opens UDP socket bound to port config.MESH_NODES[node_id].
  2. Bootstraps Link-State Database (LSDB) and Dijkstra Forwarding Table (FIB).
  3. Launches background threads for:
     • Receiving and parsing frames (DPI + Firewall check).
     • Forwarding transit packets along shortest paths.
     • Periodic Link-State Advertisement (LSA) flooding.
     • Autonomous AI NetOps Agent for self-healing.
  4. Provides an interactive terminal console to send messages and view live routes.
"""

import os
import sys
import time
import argparse
import threading

# Ensure both parent directory and root directory are in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)

for path in [PARENT_DIR, CURRENT_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

from aegismesh.config import (
    MESH_NODES,
    DEFAULT_LINK_COST,
    PKT_DATA,
    PKT_ACK,
    PKT_LSA_FLOOD,
    PKT_QUARANTINE,
    LSA_INTERVAL,
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
from aegismesh.control_plane.netops_agent import NetOpsAgent


# Initial default topology adjacency for 5-node diamond mesh:
#  A(0) --- B(1) --- C(2)
#   |        |        |
#   +------- D(3) --- E(4)
DEFAULT_TOPOLOGY = [
    (0, 1, 1),  # A <-> B (cost 1)
    (1, 2, 1),  # B <-> C (cost 1)
    (2, 4, 1),  # C <-> E (cost 1)
    (0, 3, 2),  # A <-> D (cost 2)
    (1, 3, 2),  # B <-> D (cost 2)
    (3, 4, 2),  # D <-> E (cost 2)
]


class AegisNode:
    """Encapsulates a full AegisMesh SDN Node instance."""

    def __init__(self, node_id: int):
        self.node_id = node_id
        self.name = node_name(node_id)
        self.running = False

        print(f"\n[BOOT] Initializing AegisMesh Node {self.name} (ID: {self.node_id})...")

        # 1. Transport Layer
        self.socket = MeshSocket(node_id)
        self.sender = SelectiveRepeatSender(window_size=WINDOW_SIZE)
        self.receiver = SelectiveRepeatReceiver(window_size=WINDOW_SIZE)

        # 2. Security Layer
        self.dpi = DPIInspector()
        self.firewall = Firewall()

        # 3. Routing Layer
        self.topology_db = TopologyDB(node_id)
        self._bootstrap_topology()
        self.route_mgr = RouteManager(node_id, self.topology_db)
        self.route_mgr.recompute_routes()

        self.lsa_engine = LSAEngine(
            node_id,
            self.topology_db,
            self.socket,
            log_fn=lambda msg: print(f"[{self.name}-LSA] {msg}"),
        )

        # 4. Telemetry & AI Control Plane
        self.telemetry = TelemetryStore()
        self.agent = NetOpsAgent(
            self.telemetry,
            self.route_mgr,
            self.firewall,
            self.topology_db,
            log_fn=lambda msg: print(f"\033[96m{msg}\033[0m"),
        )

        self._threads: list[threading.Thread] = []

    def _bootstrap_topology(self):
        """Populate initial baseline topology graph."""
        for u, v, cost in DEFAULT_TOPOLOGY:
            self.topology_db.update_link(u, v, cost)

    def start(self):
        """Start all receiver, routing, and AI threads."""
        self.running = True

        # Thread 1: Inbound packet receiver
        rx_thread = threading.Thread(target=self._receive_loop, daemon=True, name="RxLoop")
        rx_thread.start()
        self._threads.append(rx_thread)

        # Thread 2: Periodic LSA broadcaster
        lsa_thread = threading.Thread(target=self._lsa_loop, daemon=True, name="LsaLoop")
        lsa_thread.start()
        self._threads.append(lsa_thread)

        # Thread 3: Autonomous AI NetOps Agent
        self.agent.start_background_loop(interval=1.0)

        print(f"[READY] Node {self.name} listening on {self.socket.bound_addr}")
        self.print_status()

    def stop(self):
        """Gracefully shut down node."""
        self.running = False
        self.agent.stop_background_loop()
        self.socket.close()
        print(f"\n[STOP] Node {self.name} stopped.")

    def _receive_loop(self):
        """Main packet processing loop running on raw UDP socket."""
        while self.running:
            raw_bytes, addr = self.socket.receive()
            if not raw_bytes:
                continue

            # 1. Parse Frame & Verify CRC-32
            parsed, err = parse_frame(raw_bytes)
            if err:
                # Frame corrupted on wire — record corruption telemetry
                # Best-effort extract source ID if header readable
                if len(raw_bytes) >= 4:
                    suspect_src = raw_bytes[1]
                    self.telemetry.record_corrupt(suspect_src)
                continue

            src_id = parsed["src_id"]
            dst_id = parsed["dst_id"]
            pkt_type = parsed["pkt_type"]
            seq_num = parsed["seq_num"]
            payload = parsed["payload"]

            # 2. Firewall Check
            allowed, reason = self.firewall.check_packet(src_id)
            if not allowed:
                continue

            # 3. DPI Security Check
            valid, reason = self.dpi.inspect_frame(parsed)
            if not valid:
                self.telemetry.record_corrupt(src_id)
                continue

            # Record telemetry stats
            self.telemetry.record_packet(src_id, self.node_id, dropped=False)

            # 4. Handle by Packet Type
            if pkt_type == PKT_DATA:
                if dst_id == self.node_id:
                    # Packet reached final destination
                    ack_num, should_del, delivered = self.receiver.on_frame_received(seq_num, payload)
                    # Send ACK back to source
                    self._send_ack(src_id, ack_num)
                    for msg in delivered:
                        text = msg.decode("utf-8", errors="replace")
                        print(f"\n\033[92m[RECEIVED from Node {node_name(src_id)}] {text}\033[0m")
                        print(f"{self.name}> ", end="", flush=True)
                else:
                    # Transit packet: Forward to next hop according to Dijkstra FIB
                    next_hop = self.route_mgr.get_next_hop(dst_id)
                    if next_hop is not None:
                        # Forward exact wire bytes to next hop
                        self.socket.send_to_node(next_hop, raw_bytes)
                    else:
                        print(f"[DROP] Destination Node {node_name(dst_id)} is unreachable!")

            elif pkt_type == PKT_ACK:
                self.sender.on_ack_received(seq_num)

            elif pkt_type == PKT_LSA_FLOOD:
                # Update local topology and re-flood if sequence is newer
                changed = self.lsa_engine.process_received_lsa(src_id, payload)
                if changed:
                    self.route_mgr.recompute_routes()

    def _lsa_loop(self):
        """Periodically announce local link states to maintain network convergence."""
        while self.running:
            try:
                self.lsa_engine.flood_lsa()
            except Exception:
                pass
            time.sleep(LSA_INTERVAL)

    def _send_ack(self, dest_node_id: int, ack_num: int):
        """Transmit ACK frame back along the reverse path."""
        next_hop = self.route_mgr.get_next_hop(dest_node_id)
        if next_hop is None:
            return
        ack_frame = build_frame(
            src_id=self.node_id,
            dst_id=dest_node_id,
            pkt_type=PKT_ACK,
            seq_num=ack_num,
            ack_num=ack_num,
            payload=b"",
        )
        self.socket.send_to_node(next_hop, ack_frame)

    def send_message(self, dest_node_id: int, message: str):
        """Send application message to destination node via Selective Repeat ARQ."""
        if dest_node_id == self.node_id:
            print("Cannot send to self.")
            return

        next_hop = self.route_mgr.get_next_hop(dest_node_id)
        if next_hop is None:
            print(f"[ERROR] Destination Node {node_name(dest_node_id)} unreachable in current FIB.")
            return

        payload = message.encode("utf-8")
        seq = self.sender.send(payload, dest_node_id)
        frame = build_frame(
            src_id=self.node_id,
            dst_id=dest_node_id,
            pkt_type=PKT_DATA,
            seq_num=seq,
            ack_num=0,
            payload=payload,
        )
        self.socket.send_to_node(next_hop, frame)
        print(f"[SENT] Message to Node {node_name(dest_node_id)} via Next Hop Node {node_name(next_hop)} (Seq: {seq})")

    def print_status(self):
        """Print current forwarding table and topology status."""
        fib = self.route_mgr.get_forwarding_table()
        print("\n" + "-" * 45)
        print(f"  NODE {self.name} FORWARDING TABLE (Dijkstra FIB)")
        print("-" * 45)
        for dest, hop in sorted(fib.items()):
            if dest != self.node_id:
                hop_str = f"Node {node_name(hop)}" if hop is not None else "UNREACHABLE"
                print(f"  Destination {node_name(dest)}  --->  Next Hop: {hop_str}")
        print("-" * 45 + "\n")


def main():
    parser = argparse.ArgumentParser(description="AegisMesh SDN Node")
    parser.add_argument("--node-id", type=int, required=True, choices=[0, 1, 2, 3, 4],
                        help="Node ID (0=A, 1=B, 2=C, 3=D, 4=E)")
    args = parser.parse_args()

    node = AegisNode(args.node_id)
    node.start()

    print("\nCommands:")
    print("  send <node_letter> <message>  (e.g., 'send E Hello from A!')")
    print("  routes                        (Display current Dijkstra FIB)")
    print("  quit                          (Shutdown node)")

    try:
        while True:
            cmd = input(f"{node.name}> ").strip()
            if not cmd:
                continue
            parts = cmd.split(maxsplit=2)
            op = parts[0].lower()

            if op == "quit" or op == "exit":
                break
            elif op == "routes" or op == "status":
                node.print_status()
            elif op == "send":
                if len(parts) < 3:
                    print("Usage: send <node_letter_A-E> <message>")
                    continue
                target_letter = parts[1].upper()
                letter_to_id = {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4}
                if target_letter not in letter_to_id:
                    print("Invalid node letter. Choose A, B, C, D, or E.")
                    continue
                node.send_message(letter_to_id[target_letter], parts[2])
            else:
                print("Unknown command. Use 'send', 'routes', or 'quit'.")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        node.stop()


if __name__ == "__main__":
    main()
