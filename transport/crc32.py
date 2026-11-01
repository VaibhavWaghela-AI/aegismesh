"""
transport/crc32.py — CRC-32 error-detection utilities.

CRC (Cyclic Redundancy Check) is a mathematical "fingerprint" appended to
each frame.  The sender computes a 32-bit checksum over the frame contents;
the receiver recomputes it and compares.  If even a single bit flipped in
transit, the checksums will almost certainly differ, catching the error.

We use Python's built-in zlib.crc32 which implements the same CRC-32
polynomial used in Ethernet, HDLC, and many other protocols.
"""

import zlib


def compute_crc32(data: bytes) -> int:
    """
    Compute the CRC-32 checksum for *data*.

    Returns an unsigned 32-bit integer.  zlib.crc32 may return a signed
    value on some platforms, so we mask with 0xFFFFFFFF to guarantee an
    unsigned result.
    """
    return zlib.crc32(data) & 0xFFFFFFFF


def verify_crc32(data: bytes, expected: int) -> bool:
    """
    Recompute the CRC-32 of *data* and compare it to *expected*.

    Returns True if the data is uncorrupted (checksums match).
    """
    return compute_crc32(data) == (expected & 0xFFFFFFFF)
