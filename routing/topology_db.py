"""
routing/topology_db.py — Link-State Database (LSDB) for the mesh.

In link-state routing, every node maintains a *complete picture* of the
network topology — a graph where nodes are vertices and links are
weighted edges.  This class is that graph.

Each node floods Link-State Advertisements (LSAs) to share its local
connectivity.  When an LSA arrives, this database is updated.  Then
Dijkstra's algorithm runs on the full graph to compute shortest paths.
"""

import threading


class TopologyDB:
    """
    Thread-safe adjacency-list representation of the network graph.

    The graph is undirected: ``update_link(A, B, cost)`` implies both
    A→B and B→A exist with the same cost.
    """

    def __init__(self, my_node_id: int):
        self.my_node_id = my_node_id

        # adjacency: {node_id: {neighbor_id: cost, ...}, ...}
        self._graph: dict[int, dict[int, int]] = {}

        self._lock = threading.Lock()

    # ---- Mutators ------------------------------------------------------

    def update_link(self, node_a: int, node_b: int, cost: int) -> None:
        """Add or update an undirected edge between *node_a* and *node_b*."""
        with self._lock:
            self._graph.setdefault(node_a, {})[node_b] = cost
            self._graph.setdefault(node_b, {})[node_a] = cost

    def remove_link(self, node_a: int, node_b: int) -> None:
        """Remove the edge between *node_a* and *node_b* (if it exists)."""
        with self._lock:
            if node_a in self._graph:
                self._graph[node_a].pop(node_b, None)
            if node_b in self._graph:
                self._graph[node_b].pop(node_a, None)

    def remove_node(self, node_id: int) -> None:
        """
        Remove *node_id* and every edge touching it.

        Used when a node is quarantined or declared dead.
        """
        with self._lock:
            # Remove all edges TO this node from its neighbours
            neighbors = list(self._graph.get(node_id, {}).keys())
            for nb in neighbors:
                if nb in self._graph:
                    self._graph[nb].pop(node_id, None)
            # Remove the node's own adjacency entry
            self._graph.pop(node_id, None)

    # ---- Queries -------------------------------------------------------

    def get_graph(self) -> dict[int, dict[int, int]]:
        """Return a deep copy of the adjacency list."""
        with self._lock:
            return {n: dict(nbrs) for n, nbrs in self._graph.items()}

    def get_neighbors(self, node_id: int) -> list[tuple[int, int]]:
        """Return [(neighbor_id, cost), ...] for *node_id*."""
        with self._lock:
            return list(self._graph.get(node_id, {}).items())

    def get_all_nodes(self) -> set[int]:
        """Return the set of all node IDs currently in the graph."""
        with self._lock:
            nodes: set[int] = set()
            for n, nbrs in self._graph.items():
                nodes.add(n)
                nodes.update(nbrs.keys())
            return nodes

    def __repr__(self) -> str:
        return f"<TopologyDB nodes={self.get_all_nodes()}>"
