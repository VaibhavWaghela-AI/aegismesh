"""
security/firewall.py — Dynamic firewall with per-node DROP rules.

A firewall filters packets based on a set of rules.  In a real SDN,
the controller pushes flow rules to hardware switches via OpenFlow.
Our software overlay maintains a simple rule table:

  Rule = (node_id, action, reason, timestamp)

Packets from a node with a DROP rule are silently discarded before they
reach the routing or application logic.  The AI agent can dynamically
add/remove rules in response to detected anomalies (e.g., a node
flooding corrupted frames).
"""

import time
import threading


class Firewall:
    """
    A dynamic per-node firewall with DROP-based quarantine capability.
    """

    def __init__(self):
        # {node_id: {"action": "DROP", "reason": str, "time": float}}
        self._rules: dict[int, dict] = {}
        self._lock = threading.Lock()

    # ---- Rule management -------------------------------------------------

    def add_rule(self, node_id: int, action: str = "DROP", reason: str = "") -> None:
        """
        Add a firewall rule for *node_id*.

        Currently only "DROP" action is supported (silently discard all
        traffic from this node).
        """
        with self._lock:
            self._rules[node_id] = {
                "action": action,
                "reason": reason,
                "time":   time.time(),
            }

    def remove_rule(self, node_id: int) -> None:
        """Remove the firewall rule for *node_id* (if any)."""
        with self._lock:
            self._rules.pop(node_id, None)

    # ---- Packet filtering ------------------------------------------------

    def check_packet(self, src_node_id: int) -> tuple[bool, str]:
        """
        Check whether traffic from *src_node_id* is allowed.

        Returns
        -------
        (allowed, reason)
            allowed : True if the packet should be processed normally.
            reason  : Explanation if blocked.
        """
        with self._lock:
            rule = self._rules.get(src_node_id)
            if rule and rule["action"] == "DROP":
                return False, rule["reason"]
            return True, ""

    # ---- Quarantine helpers -----------------------------------------------

    def quarantine_node(self, node_id: int, reason: str = "") -> None:
        """
        Convenience method: add a DROP rule for *node_id* with a reason.

        This is the API the AI agent calls when it decides a node is
        misbehaving.
        """
        self.add_rule(node_id, "DROP", reason)

    def unquarantine_node(self, node_id: int) -> None:
        """Remove quarantine (DROP rule) for *node_id*."""
        self.remove_rule(node_id)

    # ---- Introspection ----------------------------------------------------

    def get_rules(self) -> list[dict]:
        """Return a list of all active firewall rules."""
        with self._lock:
            result = []
            for nid, rule in self._rules.items():
                result.append({"node_id": nid, **rule})
            return result

    def get_quarantined_nodes(self) -> set[int]:
        """Return the set of currently quarantined (blocked) node IDs."""
        with self._lock:
            return {nid for nid, r in self._rules.items() if r["action"] == "DROP"}

    def is_quarantined(self, node_id: int) -> bool:
        """Check if *node_id* is currently quarantined."""
        with self._lock:
            rule = self._rules.get(node_id)
            return rule is not None and rule["action"] == "DROP"
