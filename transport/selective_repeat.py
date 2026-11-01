"""
transport/selective_repeat.py — Selective Repeat ARQ implementation.

ARQ (Automatic Repeat reQuest) is a reliability mechanism layered on top
of an unreliable channel (UDP in our case).  *Selective Repeat* is the
most efficient variant:

  • The sender may have up to WINDOW_SIZE frames in-flight (unacknowledged).
  • Each frame has its own retransmission timer.
  • The receiver can accept frames out of order, buffering early arrivals
    and delivering them to the application in sequence once gaps are filled.
  • Only the specific lost frames are retransmitted — not the entire window
    (contrast with Go-Back-N, which retransmits everything after a loss).

Key concepts:
  • send_base        — oldest unacknowledged sequence number.
  • next_seq_num     — next sequence number to assign.
  • Window range     — [send_base, send_base + window_size).
  • Sliding window   — the window *slides forward* as the lowest outstanding
                       frame is acknowledged.
"""

import time
import threading
from collections import OrderedDict

from aegismesh.config import WINDOW_SIZE, ARQ_TIMEOUT, MAX_SEQ_NUM


class SelectiveRepeatSender:
    """
    Sender side of the Selective Repeat ARQ protocol.

    Maintains an outgoing window of up to *window_size* unacknowledged
    frames, each with its own retransmission timer.
    """

    def __init__(self, window_size: int = WINDOW_SIZE, timeout: float = ARQ_TIMEOUT):
        self.window_size = window_size
        self.timeout = timeout

        # --- Window state ---
        self.send_base = 0          # Oldest unacked seq
        self.next_seq_num = 0       # Next seq to assign

        # Buffer: seq_num -> {"payload": bytes, "frame": bytes,
        #                     "dest": int, "time": float, "acked": bool}
        self.buffer: OrderedDict[int, dict] = OrderedDict()

        # --- Statistics ---
        self.stats = {"sent": 0, "acked": 0, "retransmitted": 0}

        self._lock = threading.Lock()

    # ----- public API -------------------------------------------------

    def send(self, frame_bytes: bytes, dest_node_id: int, payload: bytes = b"") -> int | None:
        """
        Register a new frame for transmission.

        Returns the assigned sequence number, or None if the window is full
        (the caller should wait / back-pressure).
        """
        with self._lock:
            if self._window_count() >= self.window_size:
                return None  # Window full — caller must wait

            seq = self.next_seq_num
            self.buffer[seq] = {
                "frame":   frame_bytes,
                "payload": payload,
                "dest":    dest_node_id,
                "time":    time.time(),
                "acked":   False,
            }
            self.next_seq_num = (self.next_seq_num + 1) % (MAX_SEQ_NUM + 1)
            self.stats["sent"] += 1
            return seq

    def on_ack_received(self, seq_num: int) -> bool:
        """
        Mark *seq_num* as acknowledged.

        Returns True if the ack was valid and caused a state change.
        After marking, the window may slide forward.
        """
        with self._lock:
            entry = self.buffer.get(seq_num)
            if entry is None or entry["acked"]:
                return False          # Duplicate or unknown ack

            entry["acked"] = True
            self.stats["acked"] += 1

            # Slide the window: advance send_base past consecutive acked frames
            while self.buffer:
                first_seq = next(iter(self.buffer))
                if self.buffer[first_seq]["acked"]:
                    self.buffer.pop(first_seq)
                    self.send_base = (first_seq + 1) % (MAX_SEQ_NUM + 1)
                else:
                    break
            return True

    def check_timeouts(self) -> list[tuple[int, bytes, int]]:
        """
        Check for timed-out (lost) frames that need retransmission.

        Returns a list of (seq_num, frame_bytes, dest_node_id) tuples.
        Each returned frame has its timer reset.
        """
        now = time.time()
        retransmissions: list[tuple[int, bytes, int]] = []
        with self._lock:
            for seq, entry in self.buffer.items():
                if not entry["acked"] and (now - entry["time"]) > self.timeout:
                    retransmissions.append((seq, entry["frame"], entry["dest"]))
                    entry["time"] = now          # Reset timer
                    self.stats["retransmitted"] += 1
        return retransmissions

    def get_stats(self) -> dict:
        """Return a snapshot of sender-side ARQ statistics."""
        with self._lock:
            pending = sum(1 for e in self.buffer.values() if not e["acked"])
            return {**self.stats, "pending": pending}

    # ----- internals --------------------------------------------------

    def _window_count(self) -> int:
        """Number of frames currently occupying the window."""
        return sum(1 for e in self.buffer.values() if not e["acked"])


class SelectiveRepeatReceiver:
    """
    Receiver side of the Selective Repeat ARQ protocol.

    Buffers out-of-order frames and delivers them to the application
    in order once contiguous sequences are available.
    """

    def __init__(self, window_size: int = WINDOW_SIZE):
        self.window_size = window_size
        self.expected_seq = 0               # Next seq we expect in-order

        # Buffer for early (out-of-order) arrivals: seq_num -> payload
        self.recv_buffer: dict[int, bytes] = {}

        # --- Statistics ---
        self.stats = {"received": 0, "delivered": 0, "buffered": 0, "duplicates": 0}

        self._lock = threading.Lock()

    def on_frame_received(
        self, seq_num: int, payload: bytes,
    ) -> tuple[int, bool, list[bytes]]:
        """
        Process a received frame.

        Parameters
        ----------
        seq_num : The sequence number of the received frame.
        payload : The raw payload bytes.

        Returns
        -------
        ack_num          : The seq_num to acknowledge back.
        should_deliver   : True if at least one in-order payload is ready.
        delivered_payloads : List of payloads delivered in-order.
        """
        with self._lock:
            self.stats["received"] += 1
            ack_num = seq_num              # We always ACK the frame we received

            # Duplicate detection
            if seq_num < self.expected_seq and seq_num not in self.recv_buffer:
                # This is a frame we already delivered
                self.stats["duplicates"] += 1
                return ack_num, False, []

            if seq_num in self.recv_buffer:
                self.stats["duplicates"] += 1
                return ack_num, False, []

            # Buffer the frame
            self.recv_buffer[seq_num] = payload
            self.stats["buffered"] = len(self.recv_buffer)

            # Try to deliver contiguous frames starting from expected_seq
            delivered: list[bytes] = []
            while self.expected_seq in self.recv_buffer:
                delivered.append(self.recv_buffer.pop(self.expected_seq))
                self.expected_seq = (self.expected_seq + 1) % (MAX_SEQ_NUM + 1)
                self.stats["delivered"] += 1

            self.stats["buffered"] = len(self.recv_buffer)
            return ack_num, len(delivered) > 0, delivered

    def get_stats(self) -> dict:
        """Return a snapshot of receiver-side ARQ statistics."""
        with self._lock:
            return dict(self.stats)
