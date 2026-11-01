"""
security/dpi_inspector.py — Deep Packet Inspection (DPI) engine.

DPI examines frames *beyond* just their headers — inspecting payload
content, validating protocol invariants, and flagging anomalies that
simple header checks would miss.

In production SDN controllers, DPI is used for:
  • Intrusion Detection (spotting malformed or malicious traffic)
  • Quality of Service (classifying traffic types)
  • Compliance enforcement

Our lightweight DPI focuses on protocol-level sanity checks:
  1. Is the packet type valid?
  2. Is the payload length within bounds?
  3. Are source and destination IDs in the legal range?
  4. Is source ≠ destination (no self-sends)?
  5. Is the sequence number in a plausible range?
"""

import time
import threading
from collections import deque

from aegismesh.config import (
    VALID_PACKET_TYPES,
    PACKET_TYPE_NAMES,
    MAX_PAYLOAD,
    MAX_SEQ_NUM,
    NUM_NODES,
    DPI_LOG_SIZE,
    node_name,
)


class DPIInspector:
    """
    Stateless deep-packet inspector with a rolling inspection log.
    """

    def __init__(self):
        # Recent inspection results: deque of dicts
        self._log: deque[dict] = deque(maxlen=DPI_LOG_SIZE)
        self._lock = threading.Lock()

    def inspect_frame(self, parsed: dict) -> tuple[bool, str]:
        """
        Run all DPI checks on a parsed frame.

        Parameters
        ----------
        parsed : dict produced by ``framing.parse_frame()``.

        Returns
        -------
        (is_valid, reason)
            is_valid : True if the frame passes all checks.
            reason   : Human-readable explanation (empty string if valid).
        """
        checks = [
            self._check_packet_type,
            self._check_node_ids,
            self._check_no_self_send,
            self._check_payload_size,
            self._check_seq_range,
        ]

        for check_fn in checks:
            ok, reason = check_fn(parsed)
            if not ok:
                self._record(parsed, ok, reason)
                return False, reason

        self._record(parsed, True, "")
        return True, ""

    # ---- Individual checks -----------------------------------------------

    @staticmethod
    def _check_packet_type(p: dict) -> tuple[bool, str]:
        if p["pkt_type"] not in VALID_PACKET_TYPES:
            return False, f"Unknown packet type 0x{p['pkt_type']:02X}"
        return True, ""

    @staticmethod
    def _check_node_ids(p: dict) -> tuple[bool, str]:
        for field in ("src_id", "dst_id"):
            if not (0 <= p[field] < NUM_NODES):
                return False, f"Invalid {field}={p[field]} (must be 0-{NUM_NODES-1})"
        return True, ""

    @staticmethod
    def _check_no_self_send(p: dict) -> tuple[bool, str]:
        if p["src_id"] == p["dst_id"]:
            return False, f"Self-send detected: src==dst=={p['src_id']}"
        return True, ""

    @staticmethod
    def _check_payload_size(p: dict) -> tuple[bool, str]:
        length = p.get("payload_len", len(p.get("payload", b"")))
        if length > MAX_PAYLOAD:
            return False, f"Payload too large: {length} > {MAX_PAYLOAD}"
        return True, ""

    @staticmethod
    def _check_seq_range(p: dict) -> tuple[bool, str]:
        if not (0 <= p["seq_num"] <= MAX_SEQ_NUM):
            return False, f"Sequence number out of range: {p['seq_num']}"
        return True, ""

    # ---- Logging ---------------------------------------------------------

    def _record(self, parsed: dict, is_valid: bool, reason: str) -> None:
        entry = {
            "timestamp": time.time(),
            "src":       parsed.get("src_id"),
            "dst":       parsed.get("dst_id"),
            "type":      PACKET_TYPE_NAMES.get(parsed.get("pkt_type"), "?"),
            "valid":     is_valid,
            "reason":    reason,
        }
        with self._lock:
            self._log.append(entry)

    def get_inspection_log(self) -> list[dict]:
        """Return a copy of the recent inspection log."""
        with self._lock:
            return list(self._log)
