"""
control_plane/netops_agent.py — Autonomous AI NetOps Agent for self-healing and quarantine.

This agent represents the cognitive control plane of AegisMesh.
In an autonomous Software-Defined Network (SDN), human network reliability engineers
(SREs / NetOps) are assisted or replaced by closed-loop intelligent agents that:
  1. Continually observe wire telemetry (loss rates, RTT, corrupt packet counts).
  2. Reason over holistic topological health using graph theory.
  3. Act autonomously via control tools (re-weighting links to trigger Dijkstra
     rerouting or placing malicious nodes in quarantine).
  4. Generate human-readable forensic logs and post-mortem explanations.
"""

import time
import threading
from typing import Callable, Any

from aegismesh.config import (
    DROP_RATE_HIGH,
    DROP_RATE_RECOVER,
    INF_COST,
    DEFAULT_LINK_COST,
    CORRUPT_FRAME_THRESHOLD,
    CORRUPT_WINDOW_SECS,
    node_name,
)
from aegismesh.control_plane.mcp_server import TelemetryStore
from aegismesh.routing.route_manager import RouteManager
from aegismesh.routing.topology_db import TopologyDB
from aegismesh.security.firewall import Firewall


class NetOpsAgent:
    """
    Autonomous closed-loop NetOps agent.

    Monitors telemetry and automatically takes remedial action when link degradation
    or rogue node attacks occur.
    """

    def __init__(
        self,
        telemetry_store: TelemetryStore,
        route_manager: RouteManager,
        firewall: Firewall,
        topology_db: TopologyDB,
        log_fn: Callable[[str], None] | None = None,
    ):
        self.telemetry = telemetry_store
        self.route_mgr = route_manager
        self.firewall = firewall
        self.topology_db = topology_db
        self.log = log_fn or (lambda msg: None)

        # Track which links have been artificially marked as degraded by the AI
        # { (min(u,v), max(u,v)): original_cost }
        self._degraded_links: dict[tuple[int, int], int] = {}

        # Track quarantined nodes
        self._quarantined_nodes: set[int] = set()

        # Audit decision log: [{timestamp, type, target, reasoning, action}]
        self._decision_log: list[dict[str, Any]] = []
        self._lock = threading.Lock()

        self._running = False
        self._thread: threading.Thread | None = None

    def _record_decision(self, dec_type: str, target: str, reasoning: str, action: str):
        record = {
            "timestamp": time.time(),
            "time_str": time.strftime("%H:%M:%S"),
            "type": dec_type,
            "target": target,
            "reasoning": reasoning,
            "action": action,
        }
        with self._lock:
            self._decision_log.append(record)
        self.log(f"[AEGIS-AI] {reasoning}")
        self.log(f"[AEGIS-AI] ACTION -> {action}")

    def monitor_cycle(self) -> list[dict[str, Any]]:
        """
        Execute one full evaluation cycle across all links and nodes.
        Returns a list of actions taken during this cycle.
        """
        actions_taken = []
        now = time.time()

        # ------------------------------------------------------------------
        # 1. Evaluate Link Degradation (Packet Drop / Congestion)
        # ------------------------------------------------------------------
        all_link_stats = self.telemetry.get_all_link_stats()

        for stat in all_link_stats:
            u, v = stat["node_a"], stat["node_b"]
            link_key = (min(u, v), max(u, v))
            link_str = f"Node {node_name(u)} <-> Node {node_name(v)}"
            drop_rate = stat["drop_rate"]
            sent = stat["sent"]

            # Only evaluate if sufficient packets have traversed the link
            if sent >= 5:
                # Case A: Heavy packet loss detected on active link
                if drop_rate >= DROP_RATE_HIGH and link_key not in self._degraded_links:
                    reasoning = (
                        f"High packet loss ({drop_rate*100:.1f}%) detected on {link_str}. "
                        f"Exceeds SLA threshold ({DROP_RATE_HIGH*100:.0f}%). "
                        f"Evaluating alternate mesh topology..."
                    )
                    action = f"update_link_cost({node_name(u)}, {node_name(v)}, cost={INF_COST})"

                    # Save existing cost and inflate metric to force Dijkstra reroute
                    current_graph = self.topology_db.get_graph()
                    old_cost = current_graph.get(u, {}).get(v, DEFAULT_LINK_COST)
                    self._degraded_links[link_key] = old_cost

                    self.route_mgr.override_link_cost(u, v, INF_COST)
                    self._record_decision("LINK_DEGRADE", link_str, reasoning, action)
                    actions_taken.append({"type": "LINK_REROUTE", "link": link_str, "drop_rate": drop_rate})

                # Case B: Previously degraded link has stabilized
                elif drop_rate <= DROP_RATE_RECOVER and link_key in self._degraded_links:
                    old_cost = self._degraded_links.pop(link_key)
                    reasoning = (
                        f"Link {link_str} has recovered. Drop rate dropped to {drop_rate*100:.1f}%. "
                        f"Restoring link cost to {old_cost}."
                    )
                    action = f"update_link_cost({node_name(u)}, {node_name(v)}, cost={old_cost})"
                    self.route_mgr.override_link_cost(u, v, old_cost)
                    self._record_decision("LINK_RESTORE", link_str, reasoning, action)
                    actions_taken.append({"type": "LINK_RESTORE", "link": link_str})

        # ------------------------------------------------------------------
        # 2. Evaluate Byzantine / Rogue Node Attacks (Corrupt Frame Flood)
        # ------------------------------------------------------------------
        # Check corrupt counts in last CORRUPT_WINDOW_SECS
        for node_id in range(5):
            if node_id in self._quarantined_nodes:
                continue

            corrupt_count = self.telemetry.get_recent_corrupt_count(node_id, CORRUPT_WINDOW_SECS)
            if corrupt_count >= CORRUPT_FRAME_THRESHOLD:
                node_label = f"Node {node_name(node_id)}"
                reasoning = (
                    f"Byzantine anomaly detected from {node_label}! "
                    f"{corrupt_count} corrupted frames received within {CORRUPT_WINDOW_SECS}s. "
                    f"Signature matches active frame manipulation / spoofing."
                )
                action = f"quarantine_node({node_name(node_id)}, reason='Corrupt frame flood')"

                self._quarantined_nodes.add(node_id)
                self.firewall.quarantine_node(node_id, "Corrupted frame threshold exceeded")
                self.topology_db.remove_node(node_id)
                self.route_mgr.recompute_routes()

                self._record_decision("NODE_QUARANTINE", node_label, reasoning, action)
                actions_taken.append({"type": "NODE_QUARANTINED", "node": node_label})

        return actions_taken

    def get_decision_log(self) -> list[dict[str, Any]]:
        """Return a copy of all timestamped decisions made by the agent."""
        with self._lock:
            return list(self._decision_log)

    def start_background_loop(self, interval: float = 1.0) -> None:
        """Start autonomous monitoring loop in a background thread."""
        if self._running:
            return
        self._running = True

        def _loop():
            while self._running:
                try:
                    self.monitor_cycle()
                except Exception as e:
                    self.log(f"[AEGIS-AI ERROR] {e}")
                time.sleep(interval)

        self._thread = threading.Thread(target=_loop, daemon=True, name="NetOpsAgentLoop")
        self._thread.start()

    def stop_background_loop(self) -> None:
        """Stop the background monitoring loop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
