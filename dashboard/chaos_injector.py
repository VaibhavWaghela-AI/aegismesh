"""
dashboard/chaos_injector.py — Chaos Engineering framework for live viva demonstrations.

In distributed systems, Chaos Engineering (pioneered by Netflix Chaos Monkey)
deliberately injects failures — packet drops, latency, partitions, rogue corruption —
to prove that self-healing mechanisms and consensus protocols actually work.

This module provides both a programmatic API and an interactive CLI for injecting
controlled chaos during the live viva demo in front of examiners.
"""

import os
import sys
import time
import random
import threading
from typing import Any

# Ensure both parent directory and root directory are in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
AEGISMESH_DIR = os.path.dirname(CURRENT_DIR)
ROOT_DIR = os.path.dirname(AEGISMESH_DIR)

for path in [ROOT_DIR, AEGISMESH_DIR, CURRENT_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

from aegismesh.config import node_name, MESH_NODES
from aegismesh.control_plane.mcp_server import TelemetryStore


class ChaosInjector:
    """
    Manages controlled network impairments across the mesh.

    Can be queried by socket senders/receivers via ``should_drop(u, v)``
    or used to push simulated metrics to the telemetry collector.
    """

    def __init__(self, telemetry_store: TelemetryStore | None = None):
        self.telemetry = telemetry_store
        self._lock = threading.Lock()

        # Configured impairments:
        # { (min(u,v), max(u,v)): drop_probability (0.0 to 1.0) }
        self._impaired_links: dict[tuple[int, int], float] = {}

        # Set of nodes actively behaving maliciously
        self._rogue_nodes: set[int] = set()

    def set_link_drop_rate(self, node_a: int, node_b: int, drop_rate: float) -> None:
        """
        Configure a packet drop probability (0.0 to 1.0) on link (a <-> b).
        """
        key = (min(node_a, node_b), max(node_a, node_b))
        with self._lock:
            if drop_rate <= 0.0:
                self._impaired_links.pop(key, None)
            else:
                self._impaired_links[key] = min(1.0, max(0.0, drop_rate))

    def sever_link(self, node_a: int, node_b: int) -> None:
        """Completely cut communication on link (a <-> b) (100% loss)."""
        self.set_link_drop_rate(node_a, node_b, 1.0)

    def restore_link(self, node_a: int, node_b: int) -> None:
        """Restore link (a <-> b) to healthy 0% drop state."""
        self.set_link_drop_rate(node_a, node_b, 0.0)

    def trigger_rogue_node(self, node_id: int, corrupt_count: int = 8) -> None:
        """
        Simulate a Byzantine / compromised node sending corrupted frames.
        Records simulated corrupt frames into the telemetry store.
        """
        with self._lock:
            self._rogue_nodes.add(node_id)

        if self.telemetry:
            for _ in range(corrupt_count):
                self.telemetry.record_corrupt(node_id)

    def restore_all(self) -> None:
        """Clear all active impairments and restore full mesh health."""
        with self._lock:
            self._impaired_links.clear()
            self._rogue_nodes.clear()

    def should_drop(self, node_a: int, node_b: int) -> bool:
        """
        Evaluates whether a frame traveling between node_a and node_b
        should be dropped according to active chaos rules.
        """
        key = (min(node_a, node_b), max(node_a, node_b))
        with self._lock:
            rate = self._impaired_links.get(key, 0.0)
            if rate <= 0.0:
                return False
            if rate >= 1.0:
                return True
            return random.random() < rate

    def get_status(self) -> dict[str, Any]:
        """Return human-readable summary of active chaos impairments."""
        with self._lock:
            links = {
                f"{node_name(u)}<->{node_name(v)}": f"{rate*100:.0f}% drop"
                for (u, v), rate in self._impaired_links.items()
            }
            rogues = [node_name(n) for n in self._rogue_nodes]
            return {
                "impaired_links": links,
                "rogue_nodes": rogues,
                "is_healthy": len(links) == 0 and len(rogues) == 0,
            }


# ---------------------------------------------------------------------------
# Interactive CLI Menu for Demonstration
# ---------------------------------------------------------------------------

def run_chaos_cli(injector: ChaosInjector | None = None):
    """Interactive command-line menu for live chaos demonstration."""
    if injector is None:
        injector = ChaosInjector()

    print("\n" + "=" * 60)
    print("      AEGIS-MESH CHAOS ENGINEERING CONSOLE")
    print("=" * 60)

    while True:
        status = injector.get_status()
        print("\nActive Chaos Status:")
        if status["is_healthy"]:
            print("  [HEALTHY] No active network impairments.")
        else:
            for link, rate in status["impaired_links"].items():
                print(f"  [IMPAIRED] Link {link}: {rate}")
            for node in status["rogue_nodes"]:
                print(f"  [ROGUE] Node {node} is flagged as malicious")

        print("\nActions:")
        print("  1. Inject 80% Packet Loss on Link B <-> C (Viva Scenario 1)")
        print("  2. Sever Link B <-> C Completely (100% Cut)")
        print("  3. Flag Node D as Rogue Attacker (Viva Scenario 2)")
        print("  4. Custom Link Impairment")
        print("  5. Restore All Links to Healthy")
        print("  6. Exit Chaos Console")

        choice = input("\nEnter choice [1-6]: ").strip()

        if choice == "1":
            injector.set_link_drop_rate(1, 2, 0.8)
            print("\n[CHAOS APPLIED] Link B <-> C set to 80% packet drop.")
        elif choice == "2":
            injector.sever_link(1, 2)
            print("\n[CHAOS APPLIED] Link B <-> C SEVERED (100% loss).")
        elif choice == "3":
            injector.trigger_rogue_node(3, corrupt_count=10)
            print("\n[CHAOS APPLIED] Node D marked as ROGUE (corrupted frames injected).")
        elif choice == "4":
            try:
                a = int(input("  Enter Node A (0-4): ").strip())
                b = int(input("  Enter Node B (0-4): ").strip())
                rate = float(input("  Enter Drop Rate (0.0 - 1.0, e.g. 0.5): ").strip())
                injector.set_link_drop_rate(a, b, rate)
                print(f"\n[CHAOS APPLIED] Link {node_name(a)}<->{node_name(b)} set to {rate*100:.0f}% drop.")
            except Exception as e:
                print(f"Invalid input: {e}")
        elif choice == "5":
            injector.restore_all()
            print("\n[RESTORED] All links and nodes restored to healthy state.")
        elif choice == "6":
            print("Exiting Chaos Console.")
            break
        else:
            print("Invalid selection.")


if __name__ == "__main__":
    run_chaos_cli()
