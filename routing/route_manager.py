"""
routing/route_manager.py — Forwarding Information Base (FIB) manager.

This module ties together the topology database and Dijkstra's algorithm.
Whenever the topology changes (LSA update, link cost override, node
quarantine), the route manager recomputes shortest paths and updates the
FIB that the data-plane uses to forward packets.

Think of this as the "control plane" of a traditional router: it decides
*where* packets should go, but doesn't move them itself.
"""

import threading
from aegismesh.routing.topology_db import TopologyDB
from aegismesh.routing.dijkstra import compute_forwarding_table
from aegismesh.config import node_name


class RouteManager:
    """
    Manages the Forwarding Information Base (FIB) for a single node.

    The FIB maps each destination node to the *next hop* neighbour on the
    shortest path.
    """

    def __init__(self, my_node_id: int, topology_db: TopologyDB):
        self.my_node_id = my_node_id
        self.topology_db = topology_db

        # {dest_node_id: next_hop_node_id}
        self._fib: dict[int, int | None] = {}

        self._lock = threading.Lock()

    # ---- Route computation -----------------------------------------------

    def recompute_routes(self) -> dict[int, int | None]:
        """
        Run Dijkstra on the current topology and rebuild the FIB.

        Returns the new forwarding table.
        """
        graph = self.topology_db.get_graph()
        fib = compute_forwarding_table(graph, self.my_node_id)

        with self._lock:
            self._fib = fib
        return fib

    # ---- Lookups ---------------------------------------------------------

    def get_next_hop(self, dest_node_id: int) -> int | None:
        """
        Return the next-hop node for reaching *dest_node_id*, or None
        if the destination is unreachable.
        """
        with self._lock:
            return self._fib.get(dest_node_id)

    def get_forwarding_table(self) -> dict[int, int | None]:
        """Return a copy of the current FIB."""
        with self._lock:
            return dict(self._fib)

    # ---- Link cost overrides ---------------------------------------------

    def override_link_cost(self, node_a: int, node_b: int, new_cost: int) -> None:
        """
        Update the cost of the link (node_a ↔ node_b) in the topology
        and immediately recompute all routes.

        This is the primary lever the AI agent uses to steer traffic
        away from degraded links.
        """
        self.topology_db.update_link(node_a, node_b, new_cost)
        self.recompute_routes()

    def format_fib(self) -> str:
        """Pretty-print the current FIB for terminal display."""
        with self._lock:
            if not self._fib:
                return "  (empty — no routes computed yet)"
            lines = []
            for dest, hop in sorted(self._fib.items()):
                hop_str = node_name(hop) if hop is not None else "UNREACHABLE"
                lines.append(f"    dest {node_name(dest)} → next-hop {hop_str}")
            return "\n".join(lines)
