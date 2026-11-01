"""
control_plane/mcp_server.py — FastMCP server exposing network control tools.

MCP (Model Context Protocol) lets an AI model (or any MCP client) call
*tools* exposed by a server.  This module exposes the entire AegisMesh
control plane as MCP tools that a Gemini-based agent could invoke:

  • get_mesh_topology()     — view the full LSDB graph
  • get_link_telemetry()    — per-link packet stats
  • update_link_cost()      — influence Dijkstra routing
  • quarantine_node()       — firewall a misbehaving node
  • get_forwarding_table()  — current FIB
  • get_node_stats()        — ARQ transport stats

It also defines TelemetryStore, a lightweight in-memory metrics collector
that tracks per-link packet counts, drop rates, and round-trip times.
"""

import time
import threading
import json
from collections import defaultdict

from aegismesh.config import node_name, DEFAULT_LINK_COST

# NOTE: fastmcp import is optional — the demo works without it if the
# package is not installed (the MCP server just won't start).
try:
    from fastmcp import FastMCP
    HAS_FASTMCP = True
except ImportError:
    HAS_FASTMCP = False


# ────────────────────────────────────────────────────────────────────────────
# Telemetry Store
# ────────────────────────────────────────────────────────────────────────────

class TelemetryStore:
    """
    In-memory telemetry collector for per-link network statistics.

    Tracks:
      • packets_sent   — total frames sent on a link
      • packets_dropped — total frames lost / corrupted on a link
      • rtt_samples    — round-trip time measurements
      • corrupt_count  — frames flagged as corrupted per source node
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Per-link counters:  key = (node_a, node_b) with a < b
        self._link_sent:    dict[tuple[int, int], int]   = defaultdict(int)
        self._link_dropped: dict[tuple[int, int], int]   = defaultdict(int)
        self._link_rtt:     dict[tuple[int, int], list[float]] = defaultdict(list)

        # Per-node corruption counter: {node_id: [(timestamp, count)]}
        self._corrupt: dict[int, list[float]] = defaultdict(list)

    @staticmethod
    def _key(a: int, b: int) -> tuple[int, int]:
        """Normalise link key so (a,b) and (b,a) map to the same entry."""
        return (min(a, b), max(a, b))

    # ---- Recording --------------------------------------------------------

    def record_send(self, node_a: int, node_b: int) -> None:
        """Record one frame sent on link (a ↔ b)."""
        with self._lock:
            self._link_sent[self._key(node_a, node_b)] += 1

    def record_drop(self, node_a: int, node_b: int) -> None:
        """Record one dropped frame on link (a ↔ b)."""
        with self._lock:
            self._link_dropped[self._key(node_a, node_b)] += 1

    def record_packet(self, node_a: int, node_b: int, dropped: bool = False) -> None:
        """Unified method to record a sent or dropped frame."""
        with self._lock:
            k = self._key(node_a, node_b)
            self._link_sent[k] += 1
            if dropped:
                self._link_dropped[k] += 1

    def record_rtt(self, node_a: int, node_b: int, rtt: float) -> None:
        """Record a round-trip time sample on link (a ↔ b)."""
        with self._lock:
            samples = self._link_rtt[self._key(node_a, node_b)]
            samples.append(rtt)
            if len(samples) > 100:      # Keep only last 100 samples
                samples[:] = samples[-100:]

    def record_corrupt_frame(self, src_node: int) -> None:
        """Record that *src_node* sent a corrupted frame."""
        with self._lock:
            self._corrupt[src_node].append(time.time())

    def record_corrupt(self, src_node: int) -> None:
        """Alias for record_corrupt_frame."""
        self.record_corrupt_frame(src_node)

    # ---- Queries -----------------------------------------------------------

    def get_link_stats(self, node_a: int, node_b: int) -> dict:
        """Return telemetry dict for link (a ↔ b)."""
        k = self._key(node_a, node_b)
        with self._lock:
            sent    = self._link_sent.get(k, 0)
            dropped = self._link_dropped.get(k, 0)
            rtts    = list(self._link_rtt.get(k, []))

        drop_rate = dropped / max(sent, 1)
        avg_rtt   = sum(rtts) / max(len(rtts), 1) if rtts else 0.0

        return {
            "node_a":    node_a,
            "node_b":    node_b,
            "link":      f"{node_name(node_a)}<->{node_name(node_b)}",
            "sent":      sent,
            "dropped":   dropped,
            "drop_rate": round(drop_rate, 4),
            "avg_rtt":   round(avg_rtt, 4),
            "rtt_samples": len(rtts),
        }

    def get_all_link_stats(self) -> list[dict]:
        """Return telemetry for every link that has at least one sample."""
        with self._lock:
            keys = set(self._link_sent.keys()) | set(self._link_dropped.keys())
        return [self.get_link_stats(a, b) for a, b in sorted(keys)]

    def get_corrupt_count(self, src_node: int, window_secs: float = 10.0) -> int:
        """Count corrupted frames from *src_node* in the last *window_secs*."""
        cutoff = time.time() - window_secs
        with self._lock:
            timestamps = self._corrupt.get(src_node, [])
            # Prune old entries
            recent = [t for t in timestamps if t > cutoff]
            self._corrupt[src_node] = recent
            return len(recent)

    def get_recent_corrupt_count(self, src_node: int, window_secs: float = 10.0) -> int:
        """Alias for get_corrupt_count."""
        return self.get_corrupt_count(src_node, window_secs)

    def get_drop_rate(self, node_a: int, node_b: int) -> float:
        """Get the current drop rate for link (a ↔ b)."""
        k = self._key(node_a, node_b)
        with self._lock:
            sent    = self._link_sent.get(k, 0)
            dropped = self._link_dropped.get(k, 0)
        return dropped / max(sent, 1)

    # ---- Simulation helpers (used by ChaosInjector) -----------------------

    def simulate_drops(self, node_a: int, node_b: int, drop_rate: float) -> None:
        """
        Artificially set the drop counters to reflect *drop_rate*.

        For demo purposes: sets sent=100, dropped=int(100*drop_rate).
        """
        k = self._key(node_a, node_b)
        with self._lock:
            self._link_sent[k]    = 100
            self._link_dropped[k] = int(100 * drop_rate)

    def simulate_corrupt_burst(self, src_node: int, count: int = 6) -> None:
        """Inject *count* fake corruption timestamps for *src_node*."""
        now = time.time()
        with self._lock:
            for i in range(count):
                self._corrupt[src_node].append(now - i * 0.5)

    def reset_link(self, node_a: int, node_b: int) -> None:
        """Clear all telemetry for link (a ↔ b)."""
        k = self._key(node_a, node_b)
        with self._lock:
            self._link_sent.pop(k, None)
            self._link_dropped.pop(k, None)
            self._link_rtt.pop(k, None)

    def reset_all(self) -> None:
        """Clear ALL telemetry data."""
        with self._lock:
            self._link_sent.clear()
            self._link_dropped.clear()
            self._link_rtt.clear()
            self._corrupt.clear()


# ────────────────────────────────────────────────────────────────────────────
# MCP Server (optional — requires fastmcp)
# ────────────────────────────────────────────────────────────────────────────

def create_mcp_server(
    route_manager,
    firewall,
    topology_db,
    telemetry_store: TelemetryStore,
):
    """
    Create and return a FastMCP server with AegisMesh control tools.

    Returns None if fastmcp is not installed.
    """
    if not HAS_FASTMCP:
        return None

    mcp = FastMCP("AegisMesh-AI Control Plane")

    @mcp.tool()
    def get_mesh_topology() -> str:
        """Return the full LSDB graph as JSON."""
        graph = topology_db.get_graph()
        # Convert int keys to strings for JSON
        friendly = {}
        for n, nbrs in graph.items():
            friendly[node_name(n)] = {node_name(nb): c for nb, c in nbrs.items()}
        return json.dumps(friendly, indent=2)

    @mcp.tool()
    def get_link_telemetry(node_a: int, node_b: int) -> str:
        """Return per-link telemetry (sent, dropped, drop_rate, avg_rtt)."""
        stats = telemetry_store.get_link_stats(node_a, node_b)
        return json.dumps(stats, indent=2)

    @mcp.tool()
    def update_link_cost(node_a: int, node_b: int, new_cost: int) -> str:
        """Update cost of link (a ↔ b) and recompute Dijkstra routes."""
        route_manager.override_link_cost(node_a, node_b, new_cost)
        return json.dumps({
            "status": "ok",
            "link": f"{node_name(node_a)}<->{node_name(node_b)}",
            "new_cost": new_cost,
        })

    @mcp.tool()
    def quarantine_node(node_id: int, reason: str = "MCP quarantine") -> str:
        """Add firewall DROP rule and remove node from topology."""
        firewall.quarantine_node(node_id, reason)
        topology_db.remove_node(node_id)
        route_manager.recompute_routes()
        return json.dumps({
            "status": "quarantined",
            "node": node_name(node_id),
            "reason": reason,
        })

    @mcp.tool()
    def get_forwarding_table() -> str:
        """Return the current Forwarding Information Base (FIB) as JSON."""
        fib = route_manager.get_forwarding_table()
        friendly = {node_name(d): node_name(h) if h is not None else "UNREACHABLE"
                    for d, h in fib.items()}
        return json.dumps(friendly, indent=2)

    @mcp.tool()
    def get_node_stats() -> str:
        """Return all link telemetry stats."""
        stats = telemetry_store.get_all_link_stats()
        return json.dumps(stats, indent=2)

    return mcp
