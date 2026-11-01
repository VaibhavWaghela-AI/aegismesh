"""
config.py — Central configuration for the AegisMesh-AI overlay network.

This module defines all constants, node addresses, and tunable parameters
used across the entire mesh SDN system.  Every node reads this file on
startup so that the whole cluster shares the same protocol constants.

NETWORKING CONCEPTS:
  • Overlay network  — a virtual network built *on top of* the physical
    network (in our case, UDP sockets on the host OS).
  • Port             — a 16-bit number that identifies a specific process
    on a host so the OS can demultiplex incoming packets.
  • Window size      — how many unacknowledged frames can be in-flight at
    once (Selective Repeat ARQ).
"""

import os

# ---------------------------------------------------------------------------
# Node addressing
# ---------------------------------------------------------------------------
# Each mesh node is identified by an integer 0-4.
# For single-machine testing we bind to 127.0.0.1 with distinct ports.
# For real LAN deployment, set AEGIS_NODE_<id>_IP / _PORT env vars.

def _node_addr(node_id: int, default_port: int) -> tuple[str, int]:
    """Return (ip, port) for *node_id*, honouring environment overrides."""
    ip   = os.environ.get(f"AEGIS_NODE_{node_id}_IP", "127.0.0.1")
    port = int(os.environ.get(f"AEGIS_NODE_{node_id}_PORT", str(default_port)))
    return (ip, port)

MESH_NODES: dict[int, tuple[str, int]] = {
    0: _node_addr(0, 51820),
    1: _node_addr(1, 51821),
    2: _node_addr(2, 51822),
    3: _node_addr(3, 51823),
    4: _node_addr(4, 51824),
}

NUM_NODES = len(MESH_NODES)

# ---------------------------------------------------------------------------
# Frame delimiters & byte-stuffing
# ---------------------------------------------------------------------------
# FLAG (0x7E) marks the start and end of every frame — identical to HDLC.
# ESC  (0x7D) signals that the next byte has been XOR-ed with 0x20 to avoid
# accidental FLAG / ESC bytes inside the payload.
FLAG: int = 0x7E
ESC:  int = 0x7D
ESC_XOR: int = 0x20

# ---------------------------------------------------------------------------
# Packet type codes (fit in 1 unsigned byte)
# ---------------------------------------------------------------------------
PKT_DATA:       int = 0x01   # Normal data payload
PKT_ACK:        int = 0x02   # Selective acknowledgement
PKT_NACK:       int = 0x03   # Negative acknowledgement (request retransmit)
PKT_LSA_FLOOD:  int = 0x04   # Link-State Advertisement flooding
PKT_HEARTBEAT:  int = 0x05   # Keepalive probe
PKT_QUARANTINE: int = 0x06   # Node quarantine notification

PACKET_TYPE_NAMES: dict[int, str] = {
    PKT_DATA:       "DATA",
    PKT_ACK:        "ACK",
    PKT_NACK:       "NACK",
    PKT_LSA_FLOOD:  "LSA_FLOOD",
    PKT_HEARTBEAT:  "HEARTBEAT",
    PKT_QUARANTINE: "QUARANTINE",
}

VALID_PACKET_TYPES: set[int] = set(PACKET_TYPE_NAMES.keys())

# ---------------------------------------------------------------------------
# Transport-layer parameters
# ---------------------------------------------------------------------------
WINDOW_SIZE: int    = 8       # Selective Repeat ARQ window (frames)
ARQ_TIMEOUT: float  = 2.0    # Seconds before a frame is considered lost
MAX_PAYLOAD: int    = 1024    # Maximum payload bytes per frame
MAX_SEQ_NUM: int    = 65535   # 16-bit sequence space (0 .. 65535)

# ---------------------------------------------------------------------------
# Routing parameters
# ---------------------------------------------------------------------------
HEARTBEAT_INTERVAL: float = 2.0   # Seconds between keepalive probes
LSA_INTERVAL:       float = 3.0   # Seconds between LSA floods
DEFAULT_LINK_COST:  int   = 1     # Default cost for a healthy link
INF_COST:           int   = 9999  # "Infinite" cost — effectively unusable

# ---------------------------------------------------------------------------
# Security / DPI parameters
# ---------------------------------------------------------------------------
DPI_LOG_SIZE:          int   = 100   # Max recent inspection results to keep
CORRUPT_FRAME_THRESHOLD: int = 5    # Corrupted frames in window → quarantine
CORRUPT_WINDOW_SECS:   float = 10.0 # Time window for corruption counting

# ---------------------------------------------------------------------------
# Telemetry thresholds (used by the NetOps AI agent)
# ---------------------------------------------------------------------------
DROP_RATE_HIGH:    float = 0.50   # >50 % drops → degrade link
DROP_RATE_RECOVER: float = 0.10   # <10 % drops → link recovered

# ---------------------------------------------------------------------------
# Socket settings
# ---------------------------------------------------------------------------
SOCKET_TIMEOUT: float = 0.1      # Non-blocking recv timeout (seconds)
SOCKET_BUFSIZE: int   = 4096     # Maximum UDP datagram we'll read

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------
NODE_NAMES: dict[int, str] = {
    0: "A", 1: "B", 2: "C", 3: "D", 4: "E",
}

def node_name(node_id: int) -> str:
    """Human-friendly single-letter name for a node."""
    return NODE_NAMES.get(node_id, f"?{node_id}")
