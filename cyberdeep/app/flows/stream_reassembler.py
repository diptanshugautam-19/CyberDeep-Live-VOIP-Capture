"""
TCP Stream Reassembler and UDP Flow Reconstructor module.
Reconstructs out-of-order TCP segments and datagram streams for Deep Packet Inspection.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class TCPStreamBuffer:
    """
    Manages sequence numbers and out-of-order data segments for a single TCP direction.
    """
    def __init__(self, initial_seq: int = 0):
        self.next_expected_seq = initial_seq
        self.out_of_order_segments: Dict[int, bytes] = {}
        self.reassembled_bytes = bytearray()
        self.total_bytes = 0

    def add_segment(self, seq: int, payload: bytes) -> bytes:
        """
        Adds a segment to the buffer and returns any newly contiguous reassembled data bytes.
        """
        if not payload:
            return b""

        self.total_bytes += len(payload)

        # First segment observed
        if self.next_expected_seq == 0:
            self.next_expected_seq = seq

        if seq < self.next_expected_seq:
            # Overlapping or duplicate past segment
            overlap = self.next_expected_seq - seq
            if overlap < len(payload):
                payload = payload[overlap:]
                seq = self.next_expected_seq
            else:
                return b""

        if seq == self.next_expected_seq:
            # Contiguous segment
            new_data = bytearray(payload)
            self.next_expected_seq += len(payload)

            # Drain any buffered out-of-order segments that now connect
            while self.next_expected_seq in self.out_of_order_segments:
                next_seg = self.out_of_order_segments.pop(self.next_expected_seq)
                new_data.extend(next_seg)
                self.next_expected_seq += len(next_seg)

            self.reassembled_bytes.extend(new_data)
            return bytes(new_data)
        else:
            # Out of order segment - buffer it (cap size at 5MB per stream direction)
            if len(self.out_of_order_segments) < 500:
                self.out_of_order_segments[seq] = payload
            return b""

class TCPStreamReassembler:
    """
    Tracks and reassembles bidirectional TCP streams.
    """
    def __init__(self):
        # flow_key -> { "c2s": TCPStreamBuffer, "s2c": TCPStreamBuffer }
        self.streams: Dict[str, Dict[str, TCPStreamBuffer]] = defaultdict(
            lambda: {"c2s": TCPStreamBuffer(), "s2c": TCPStreamBuffer()}
        )

    def process_segment(self, flow_key: str, is_c2s: bool, seq: int, payload: bytes) -> bytes:
        direction = "c2s" if is_c2s else "s2c"
        buf = self.streams[flow_key][direction]
        return buf.add_segment(seq, payload)

    def get_reassembled_stream(self, flow_key: str, is_c2s: bool) -> bytes:
        direction = "c2s" if is_c2s else "s2c"
        if flow_key in self.streams:
            return bytes(self.streams[flow_key][direction].reassembled_bytes)
        return b""

    def remove_stream(self, flow_key: str):
        if flow_key in self.streams:
            del self.streams[flow_key]

class UDPFlowReconstructor:
    """
    Reconstructs datagram payloads and sequences for UDP flows.
    """
    def __init__(self):
        # flow_key -> bytearray of aggregated datagrams
        self.flows: Dict[str, bytearray] = defaultdict(bytearray)
        self.packet_counts: Dict[str, int] = defaultdict(int)

    def process_datagram(self, flow_key: str, payload: bytes) -> bytes:
        if payload:
            self.flows[flow_key].extend(payload)
            self.packet_counts[flow_key] += 1
        return payload

    def get_payload(self, flow_key: str) -> bytes:
        return bytes(self.flows.get(flow_key, b""))

    def remove_flow(self, flow_key: str):
        self.flows.pop(flow_key, None)
        self.packet_counts.pop(flow_key, None)

stream_reassembler = TCPStreamReassembler()
udp_reconstructor = UDPFlowReconstructor()
