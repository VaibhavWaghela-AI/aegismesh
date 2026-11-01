"""
transport/framing.py — Binary frame construction and parsing.

Every piece of data sent between mesh nodes is wrapped in a *frame* — a
structured envelope that includes:
  • Start / stop FLAG delimiters (0x7E) so the receiver knows where a
    frame begins and ends, even in a continuous byte stream.
  • A fixed-size header carrying addressing and control fields.
  • A variable-length payload that has been *byte-stuffed* to remove any
    accidental FLAG bytes.
  • A CRC-32 checksum for error detection.

Frame wire format (byte offsets after FLAG):
  [0x7E]                        ← start delimiter
  [src:1][dst:1][type:1]        ← 3 bytes addressing & packet type
  [seq:2][ack:2]                ← 4 bytes sequence / ack numbers (big-endian)
  [payload_len:2]               ← 2 bytes original (pre-stuff) payload length
  [--- stuffed payload ---]     ← variable length
  [crc32:4]                     ← 4 bytes CRC over header + original payload
  [0x7E]                        ← end delimiter

Byte stuffing (identical to PPP / HDLC):
  • 0x7E in payload → 0x7D 0x5E
  • 0x7D in payload → 0x7D 0x5D
"""

import struct
from aegismesh.config import FLAG, ESC, ESC_XOR
from aegismesh.transport.crc32 import compute_crc32, verify_crc32

# Header struct: src(B) dst(B) type(B) seq(H) ack(H) payload_len(H)
# B = unsigned byte, H = unsigned short (2 bytes, big-endian)
HEADER_FMT = "!BBB HH H"         # "!" = network (big-endian) byte order
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 9 bytes


# ── Byte stuffing ──────────────────────────────────────────────────────────

def byte_stuff(data: bytes) -> bytes:
    """
    Escape FLAG (0x7E) and ESC (0x7D) bytes inside *data*.

    This prevents the receiver from mistaking payload content for frame
    delimiters.  The technique is called *byte stuffing* (or *character
    stuffing*) and is used in HDLC / PPP.

    Escaping rule:
      original byte  →  escaped sequence
      0x7E           →  0x7D  0x5E   (ESC, then 0x7E ^ 0x20)
      0x7D           →  0x7D  0x5D   (ESC, then 0x7D ^ 0x20)
    """
    out = bytearray()
    for b in data:
        if b == FLAG:
            out.append(ESC)
            out.append(FLAG ^ ESC_XOR)
        elif b == ESC:
            out.append(ESC)
            out.append(ESC ^ ESC_XOR)
        else:
            out.append(b)
    return bytes(out)


def byte_destuff(data: bytes) -> bytes:
    """
    Reverse the byte-stuffing applied by :func:`byte_stuff`.

    Reads through *data* and whenever it encounters 0x7D (ESC), it XORs
    the following byte with 0x20 to recover the original value.
    """
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == ESC and i + 1 < len(data):
            out.append(data[i + 1] ^ ESC_XOR)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


# ── Frame building ─────────────────────────────────────────────────────────

def build_frame(
    src_id: int,
    dst_id: int,
    pkt_type: int,
    seq_num: int,
    ack_num: int,
    payload: bytes = b"",
) -> bytes:
    """
    Construct a complete wire-ready frame.

    Parameters
    ----------
    src_id   : Source node ID (0-4).
    dst_id   : Destination node ID (0-4).
    pkt_type : One of PKT_DATA, PKT_ACK, etc.
    seq_num  : Sequence number for this frame.
    ack_num  : Acknowledgement number (piggybacked).
    payload  : Raw payload bytes (will be byte-stuffed).

    Returns
    -------
    bytes : The framed, stuffed, CRC-protected datagram ready for UDP send.
    """
    # 1. Pack the fixed header
    header = struct.pack(
        HEADER_FMT,
        src_id, dst_id, pkt_type,
        seq_num, ack_num,
        len(payload),
    )

    # 2. CRC is computed over the raw (unstuffed) header + payload
    crc = compute_crc32(header + payload)
    crc_bytes = struct.pack("!I", crc)          # 4-byte big-endian unsigned int

    # 3. Byte-stuff the payload to remove accidental FLAG / ESC bytes
    stuffed_payload = byte_stuff(payload)

    # 4. Assemble:  FLAG | header | stuffed_payload | crc | FLAG
    frame = bytearray()
    frame.append(FLAG)
    frame.extend(header)
    frame.extend(stuffed_payload)
    frame.extend(crc_bytes)
    frame.append(FLAG)

    return bytes(frame)


# ── Frame parsing ──────────────────────────────────────────────────────────

def parse_frame(raw: bytes) -> tuple[dict | None, str | None]:
    """
    Parse a raw byte sequence into structured frame fields.

    Returns
    -------
    (fields_dict, None)         on success.
    (None, error_description)   on failure.

    The returned dict contains keys:
      src_id, dst_id, pkt_type, seq_num, ack_num, payload_len, payload, crc
    """
    # --- Delimiter check ---
    if len(raw) < 2 or raw[0] != FLAG or raw[-1] != FLAG:
        return None, "Missing FLAG delimiters"

    # Strip leading/trailing FLAG
    inner = raw[1:-1]

    # --- Minimum length: header(9) + crc(4) ---
    if len(inner) < HEADER_SIZE + 4:
        return None, f"Frame too short ({len(inner)} bytes inside flags)"

    # --- Unpack header ---
    header_bytes = inner[:HEADER_SIZE]
    src_id, dst_id, pkt_type, seq_num, ack_num, payload_len = struct.unpack(
        HEADER_FMT, header_bytes,
    )

    # --- Extract stuffed payload and CRC ---
    stuffed_payload = inner[HEADER_SIZE:-4]
    crc_bytes = inner[-4:]
    received_crc = struct.unpack("!I", crc_bytes)[0]

    # --- De-stuff payload ---
    payload = byte_destuff(stuffed_payload)

    # --- Payload length sanity check ---
    if len(payload) != payload_len:
        return None, (
            f"Payload length mismatch: header says {payload_len}, "
            f"got {len(payload)} after de-stuffing"
        )

    # --- CRC verification ---
    #   CRC was computed over raw header + raw payload (before stuffing).
    if not verify_crc32(header_bytes + payload, received_crc):
        return None, "CRC-32 mismatch — frame is corrupted"

    fields = {
        "src_id":      src_id,
        "dst_id":      dst_id,
        "pkt_type":    pkt_type,
        "seq_num":     seq_num,
        "ack_num":     ack_num,
        "payload_len": payload_len,
        "payload":     payload,
        "crc":         received_crc,
    }
    return fields, None
