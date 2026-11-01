"""
transport/udp_socket.py — Thin wrapper around a raw UDP socket.

UDP (User Datagram Protocol) is a connectionless, unreliable transport
protocol.  Each ``sendto`` / ``recvfrom`` call corresponds to exactly one
datagram — there is no stream, no connection setup, and no built-in
retransmission.

We use UDP intentionally: the overlay implements its *own* reliability
(Selective Repeat ARQ) and its *own* routing (Link-State / Dijkstra),
so we only need the OS to move datagrams between ports.
"""

import socket
from aegismesh.config import MESH_NODES, SOCKET_TIMEOUT, SOCKET_BUFSIZE


class MeshSocket:
    """
    A non-blocking UDP socket bound to a specific mesh node.

    Each node owns exactly one MeshSocket, bound to the (ip, port) pair
    listed in ``config.MESH_NODES[node_id]``.
    """

    def __init__(self, node_id: int, bind_port: int | None = None):
        """
        Create and bind a UDP socket for *node_id*.

        Parameters
        ----------
        node_id   : This node's integer ID (0-4).
        bind_port : Override the default port from config (useful for tests).
        """
        self.node_id = node_id

        ip, default_port = MESH_NODES[node_id]
        port = bind_port if bind_port is not None else default_port

        # AF_INET  = IPv4,  SOCK_DGRAM = UDP
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # SO_REUSEADDR lets us rebind quickly after a restart
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Non-blocking with a short timeout so the receive loop does not
        # block forever and can periodically run housekeeping tasks.
        self._sock.settimeout(SOCKET_TIMEOUT)

        self._sock.bind((ip, port))
        self.bound_addr = (ip, port)

    # ---- sending -------------------------------------------------------

    def send_to_node(self, dest_node_id: int, raw_frame: bytes) -> None:
        """
        Send *raw_frame* (already framed and CRC-protected) to *dest_node_id*.

        This is a simple UDP ``sendto`` — fire and forget.
        """
        if dest_node_id not in MESH_NODES:
            return  # Unknown node — silently drop
        dest_addr = MESH_NODES[dest_node_id]
        try:
            self._sock.sendto(raw_frame, dest_addr)
        except OSError:
            pass  # Network hiccup — upper layers will handle via ARQ timeout

    # ---- receiving -----------------------------------------------------

    def receive(self) -> tuple[bytes, tuple[str, int]] | tuple[None, None]:
        """
        Attempt a non-blocking receive.

        Returns (data, (ip, port)) or (None, None) on timeout / error.
        """
        try:
            data, addr = self._sock.recvfrom(SOCKET_BUFSIZE)
            return data, addr
        except socket.timeout:
            return None, None
        except OSError:
            return None, None

    # ---- lifecycle -----------------------------------------------------

    def close(self) -> None:
        """Release the socket."""
        try:
            self._sock.close()
        except OSError:
            pass

    def __repr__(self) -> str:
        return f"<MeshSocket node={self.node_id} bound={self.bound_addr}>"
