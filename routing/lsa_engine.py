"""
routing/lsa_engine.py — Link-State Advertisement flooding engine.

In link-state routing (used by OSPF and IS-IS), every node periodically
broadcasts a Link-State Advertisement (LSA) describing its directly
connected neighbors and the cost of each link.

Each LSA carries a *sequence number*.  When a node receives an LSA it has
not seen before (or with a higher sequence number), it:
  1. Updates its local topology database.
  2. Re-floods the LSA to all of *its* neighbours (except the one that
     sent it) — this is called *reliable flooding*.

Once every node has received every other node's LSA, they all share the
same topology graph.  Dijkstra's algorithm then computes consistent
shortest-path trees everywhere.
"""

import json
import threading
import time

from aegismesh.config import (
    PKT_LSA_FLOOD,
    DEFAULT_LINK_COST,
    node_name,
)
from aegismesh.transport.framing import build_frame


class LSAEngine:
    """
    Generates, floods, and processes Link-State Advertisements.
    """

    def __init__(self, my_node_id, topology_db, mesh_socket, log_fn=None):
        """
        Parameters
        ----------
        my_node_id   : This node's integer ID.
        topology_db  : A TopologyDB instance (shared reference).
        mesh_socket  : A MeshSocket instance for sending frames.
        log_fn       : Optional callable(str) for debug logging.
        """
        self.my_node_id = my_node_id
        self.topology_db = topology_db
        self.mesh_socket = mesh_socket
        self.log = log_fn or (lambda msg: None)

        # Monotonically increasing sequence number for our own LSAs
        self._my_lsa_seq = 0

        # Track the highest LSA seq seen from each node to prevent loops
        # {origin_node_id: highest_seq_seen}
        self._seen_lsa: dict[int, int] = {}

        self._lock = threading.Lock()

    # ---- Generate our own LSA ------------------------------------------

    def generate_lsa(self) -> bytes:
        """
        Build an LSA payload describing our current neighbors and costs.

        The payload is a JSON-encoded dict::

            {"origin": 0, "seq": 7,
             "neighbors": {1: 1, 2: 1}}

        We increment the sequence number each time so that receivers know
        this LSA is newer than any previous one from us.
        """
        with self._lock:
            self._my_lsa_seq += 1
            neighbors = self.topology_db.get_neighbors(self.my_node_id)
            lsa = {
                "origin":    self.my_node_id,
                "seq":       self._my_lsa_seq,
                "neighbors": {n: c for n, c in neighbors},
                "timestamp": time.time(),
            }
            return json.dumps(lsa).encode()

    # ---- Flood an LSA to all neighbours --------------------------------

    def flood_lsa(self, lsa_payload: bytes, exclude_node: int | None = None) -> None:
        """
        Send *lsa_payload* as an LSA_FLOOD frame to all known neighbours,
        optionally excluding *exclude_node* (the sender we got it from).
        """
        neighbors = self.topology_db.get_neighbors(self.my_node_id)
        for nbr_id, _cost in neighbors:
            if nbr_id == exclude_node:
                continue
            frame = build_frame(
                src_id=self.my_node_id,
                dst_id=nbr_id,
                pkt_type=PKT_LSA_FLOOD,
                seq_num=0,
                ack_num=0,
                payload=lsa_payload,
            )
            self.mesh_socket.send_to_node(nbr_id, frame)

    # ---- Process a received LSA ----------------------------------------

    def process_received_lsa(self, src_node: int, lsa_payload: bytes) -> bool:
        """
        Handle an incoming LSA.

        1. Decode the JSON payload.
        2. Check the sequence number — drop if we've already seen it.
        3. Update our topology database with the advertised links.
        4. Re-flood to all neighbours except *src_node*.

        Returns True if the LSA was new and applied, False if it was stale.
        """
        try:
            lsa = json.loads(lsa_payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.log(f"  [LSA] Malformed LSA payload from node {node_name(src_node)}")
            return False

        origin = lsa.get("origin")
        seq    = lsa.get("seq", 0)
        nbrs   = lsa.get("neighbors", {})

        if origin is None:
            return False

        with self._lock:
            # Duplicate / stale detection
            if origin in self._seen_lsa and seq <= self._seen_lsa[origin]:
                return False  # Already processed a newer or equal LSA

            self._seen_lsa[origin] = seq

        # Update topology DB with the advertised edges
        for nbr_str, cost in nbrs.items():
            nbr_id = int(nbr_str)
            self.topology_db.update_link(origin, nbr_id, cost)

        self.log(
            f"  [LSA] Applied LSA from {node_name(origin)} "
            f"(seq={seq}, neighbors={list(nbrs.keys())})"
        )

        # Re-flood to propagate the update
        self.flood_lsa(lsa_payload, exclude_node=src_node)
        return True
