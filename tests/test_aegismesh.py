"""
tests/test_aegismesh.py — Automated test suite for AegisMesh-AI core protocols.
"""

import sys
import os
# Insert the root project directory (parent of aegismesh) into sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from aegismesh.transport.crc32 import compute_crc32, verify_crc32
from aegismesh.transport.framing import build_frame, parse_frame, byte_stuff, byte_destuff
from aegismesh.transport.selective_repeat import SelectiveRepeatSender, SelectiveRepeatReceiver
from aegismesh.routing.dijkstra import dijkstra, compute_forwarding_table
from aegismesh.security.dpi_inspector import DPIInspector
from aegismesh.security.firewall import Firewall
from aegismesh.config import PKT_DATA, PKT_ACK


def test_crc32():
    data = b"Hello, AegisMesh!"
    crc = compute_crc32(data)
    assert verify_crc32(data, crc) is True
    # 1-bit corruption detection
    corrupted = bytearray(data)
    corrupted[0] ^= 0x01
    assert verify_crc32(bytes(corrupted), crc) is False
    print("[PASS] CRC-32 error detection test passed.")


def test_byte_stuffing_and_framing():
    # Payload containing reserved flag (0x7E) and escape (0x7D)
    tricky_payload = b"Start\x7EData\x7DMore\x7EEnd"
    frame = build_frame(src_id=0, dst_id=4, pkt_type=PKT_DATA, seq_num=101, ack_num=0, payload=tricky_payload)

    parsed, err = parse_frame(frame)
    assert err is None
    assert parsed["src_id"] == 0
    assert parsed["dst_id"] == 4
    assert parsed["seq_num"] == 101
    assert parsed["payload"] == tricky_payload
    print("[PASS] Byte stuffing & frame framing/deframing test passed.")


def test_selective_repeat_arq():
    sender = SelectiveRepeatSender(window_size=4)
    receiver = SelectiveRepeatReceiver(window_size=4)

    # Send 4 frames (seq 0, 1, 2, 3)
    p0, p1, p2, p3 = b"Msg0", b"Msg1", b"Msg2", b"Msg3"
    s0 = sender.send(p0, 1)
    s1 = sender.send(p1, 1)
    s2 = sender.send(p2, 1)
    s3 = sender.send(p3, 1)

    # Deliver out of order: frame 1 arrives before frame 0
    ack1, del1, msgs1 = receiver.on_frame_received(s1, p1)
    assert del1 is False  # Cannot deliver yet, waiting for frame 0!

    # Now frame 0 arrives
    ack0, del0, msgs0 = receiver.on_frame_received(s0, p0)
    assert del0 is True
    assert msgs0 == [p0, p1]  # Both delivered in correct order!

    print("[PASS] Selective Repeat out-of-order reassembly test passed.")


def test_dijkstra_routing():
    # Diamond graph:
    # 0 --(1)-- 1 --(1)-- 2 --(1)-- 4 (Total: 3)
    # 0 --(2)-- 3 --(2)-- 4           (Total: 4)
    graph = {
        0: {1: 1, 3: 2},
        1: {0: 1, 2: 1},
        2: {1: 1, 4: 1},
        3: {0: 2, 4: 2},
        4: {2: 1, 3: 2},
    }
    fib = compute_forwarding_table(graph, source=0)
    # Path to 4 should be via 1
    assert fib[4] == 1

    # Now sever link 1-2 (cost=9999)
    graph[1][2] = 9999
    graph[2][1] = 9999
    fib_healed = compute_forwarding_table(graph, source=0)
    # Path to 4 should now flip to 3!
    assert fib_healed[4] == 3
    print("[PASS] Dijkstra dynamic re-routing test passed.")


def test_security_dpi_and_firewall():
    dpi = DPIInspector()
    firewall = Firewall()

    # Valid frame
    valid_frame = {
        "src_id": 0, "dst_id": 1, "pkt_type": PKT_DATA,
        "seq_num": 5, "ack_num": 0, "payload": b"Valid Data"
    }
    ok, _ = dpi.inspect_frame(valid_frame)
    assert ok is True

    # Invalid frame (src == dst)
    invalid_frame = dict(valid_frame, src_id=1, dst_id=1)
    ok_inv, _ = dpi.inspect_frame(invalid_frame)
    assert ok_inv is False

    # Firewall check
    allowed, _ = firewall.check_packet(src_node_id=3)
    assert allowed is True
    firewall.quarantine_node(3, "Test Quarantine")
    blocked, _ = firewall.check_packet(src_node_id=3)
    assert blocked is False
    print("[PASS] DPI & Firewall security test passed.")


if __name__ == "__main__":
    test_crc32()
    test_byte_stuffing_and_framing()
    test_selective_repeat_arq()
    test_dijkstra_routing()
    test_security_dpi_and_firewall()
    print("\nALL UNIT TESTS PASSED (100% GREEN)!")
