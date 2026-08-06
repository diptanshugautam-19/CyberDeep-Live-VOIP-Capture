"""
Deep Packet Inspection (DPI) Engine.
Performs signature matching, protocol identification, TLS/QUIC/SSH decoding,
and payload entropy analysis.
"""

import math
import collections
import logging
from typing import Dict, List, Any, Optional
from app.core.fingerprint import get_tls_fingerprints, parse_ssh_hassh
from app.protocols.quic import parse_quic_packet

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
# High-entropy threshold for encrypted/obfuscated payload detection.
# Override via config or subclass if a different sensitivity is required.
DPI_ENTROPY_THRESHOLD = 7.5

# STUN magic cookie (RFC 5389 §6.  Binding Request) — must be present at bytes 4–8.
STUN_MAGIC_COOKIE = b"\x21\x12\xa4\x42"

# Protocol signatures for DPI pattern matching.
# Position-0 anchored signatures (startswith): reliable, no false positives.
# NOTE: For high-throughput deployments, replace this dict + loop with a
# pyahocorasick Automaton (O(N) multi-pattern search vs O(N×M) here):
#   import ahocorasick; A = ahocorasick.Automaton()
#   for sig, info in DPI_SIGNATURES.items(): A.add_word(sig, (sig, info))
#   A.make_automaton()
#   for _, (sig, info) in A.iter(payload): ...
DPI_SIGNATURES_STARTSWITH = {
    b"HTTP/1.": {"protocol": "HTTP", "layer": "L7", "desc": "HTTP/1.x Web Protocol"},
    b"HTTP/2.": {"protocol": "HTTP/2", "layer": "L7", "desc": "HTTP/2 Binary Frame"},
    b"GET ": {"protocol": "HTTP", "layer": "L7", "desc": "HTTP GET Request"},
    b"POST ": {"protocol": "HTTP", "layer": "L7", "desc": "HTTP POST Request"},
    b"SSH-2.0": {"protocol": "SSH", "layer": "L7", "desc": "Secure Shell Protocol v2"},
    b"SSH-1.99": {"protocol": "SSH", "layer": "L7", "desc": "Secure Shell Protocol v1.99"},
    b"d1:ad2:id": {"protocol": "BitTorrent", "layer": "L7", "desc": "BitTorrent DHT Protocol"},
    b"BitTorrent protocol": {"protocol": "BitTorrent", "layer": "L7", "desc": "BitTorrent P2P Protocol"},
    b"220 ": {"protocol": "FTP/SMTP", "layer": "L7", "desc": "Service Ready Response"},
}
# Anywhere-in-payload signatures (not position-0): used for TLS record header detection.
DPI_SIGNATURES_CONTAINS = {
    b"\x16\x03\x01": {"protocol": "TLS 1.0", "layer": "L7", "desc": "TLS Handshake v1.0"},
    b"\x16\x03\x02": {"protocol": "TLS 1.1", "layer": "L7", "desc": "TLS Handshake v1.1"},
    b"\x16\x03\x03": {"protocol": "TLS 1.2/1.3", "layer": "L7", "desc": "TLS Handshake v1.2/v1.3"},
}

def _is_stun_payload(payload: bytes) -> bool:
    """
    Validates STUN packets using both the legacy first-byte pattern and the RFC 5389
    magic cookie at bytes 4–8 (avoids false positives from other binary protocols).
    """
    if len(payload) < 20:
        return False
    # RFC 5389: first two bits must be 0b00; message type in bytes 0–1
    if (payload[0] & 0xC0) != 0x00:
        return False
    # Magic cookie at bytes 4–8 (mandatory per RFC 5389)
    return payload[4:8] == STUN_MAGIC_COOKIE

def calculate_payload_entropy(payload: bytes) -> float:
    """Calculates Shannon entropy of raw payload bytes (0.0 to 8.0)."""
    if not payload:
        return 0.0
    length = len(payload)
    # Use Counter for O(N) byte frequency — faster than manual dict loop
    freq = collections.Counter(payload)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)

class DPIEngine:
    def __init__(self):
        self.total_inspected = 0
        self.matched_protocols: Dict[str, int] = {}
        # Dynamic rules added at runtime via load_rule()
        self._dynamic_signatures: Dict[bytes, dict] = {}

    def load_rule(self, name: str, pattern: bytes, info: dict) -> None:
        """Dynamically add a user-defined DPI rule at runtime (wired to /api/rules endpoint)."""
        self._dynamic_signatures[pattern] = {**info, "name": name}
        logger.info(f"DPI rule loaded: '{name}' pattern={pattern!r}")

    def get_stats(self) -> dict:
        """Return DPI inspection statistics including matched protocol counts."""
        return {
            "total_inspected": self.total_inspected,
            "matched_protocols": dict(self.matched_protocols),
        }

    def inspect_packet(self, packet: dict, raw_payload: bytes | None = None) -> list[dict]:
        """
        Deeply inspects a packet payload to extract DPI metadata, protocols, and fingerprints.
        """
        results: List[Dict[str, Any]] = []
        payload = raw_payload or packet.get("raw_bytes") or b""
        if not payload:
            return results

        self.total_inspected += 1
        protocol = packet.get("protocol", "")
        src_port = packet.get("source_port", 0)
        dst_port = packet.get("destination_port", 0)

        entropy = calculate_payload_entropy(payload)

        # 1. Pattern & Signature Matching (position-0 anchored)
        for sig, info in DPI_SIGNATURES_STARTSWITH.items():
            if payload.startswith(sig):
                tag = {
                    "type": "signature_match",
                    "protocol": info["protocol"],
                    "description": info["desc"],
                    "confidence": 95,
                    "entropy": entropy
                }
                results.append(tag)
                self.matched_protocols[info["protocol"]] = self.matched_protocols.get(info["protocol"], 0) + 1

        # TLS record header sigs (can appear at any position)
        for sig, info in DPI_SIGNATURES_CONTAINS.items():
            if sig in payload:
                tag = {
                    "type": "signature_match",
                    "protocol": info["protocol"],
                    "description": info["desc"],
                    "confidence": 90,
                    "entropy": entropy
                }
                results.append(tag)
                self.matched_protocols[info["protocol"]] = self.matched_protocols.get(info["protocol"], 0) + 1

        # STUN: validate magic cookie (RFC 5389) to avoid false positives
        if _is_stun_payload(payload):
            results.append({
                "type": "signature_match",
                "protocol": "STUN",
                "description": "Session Traversal Utilities for NAT (RFC 5389)",
                "confidence": 99,
                "entropy": entropy
            })
            self.matched_protocols["STUN"] = self.matched_protocols.get("STUN", 0) + 1

        # Dynamic user-defined rules
        for sig, info in self._dynamic_signatures.items():
            if payload.startswith(sig):
                results.append({
                    "type": "signature_match",
                    "protocol": info.get("protocol", "CUSTOM"),
                    "description": info.get("desc", info.get("name", "Custom Rule")),
                    "confidence": 80,
                    "entropy": entropy
                })

        # 2. TLS / SSL Inspection
        if protocol == "TCP" and (src_port in (443, 8443) or dst_port in (443, 8443)):
            tls_fp = get_tls_fingerprints(payload)
            if tls_fp:
                tag = {
                    "type": "tls_fingerprint",
                    "protocol": "TLS",
                    "confidence": 100,
                    "fingerprints": tls_fp,
                    "entropy": entropy
                }
                results.append(tag)

        # 3. SSH HASSH Inspection
        if protocol == "TCP" and (src_port == 22 or dst_port == 22):
            ssh_fp = parse_ssh_hassh(payload)
            if ssh_fp:
                tag = {
                    "type": "ssh_hassh",
                    "protocol": "SSH",
                    "confidence": 100,
                    "hassh": ssh_fp.get("hassh"),
                    "hassh_server": ssh_fp.get("hassh_server"),
                    "entropy": entropy
                }
                results.append(tag)

        # 4. QUIC Inspection
        if protocol == "UDP" and (src_port == 443 or dst_port == 443):
            quic_info = parse_quic_packet(payload)
            if quic_info:
                tag = {
                    "type": "quic_decoded",
                    "protocol": "QUIC",
                    "confidence": 90,
                    "version": quic_info.get("version_name"),
                    "sni": quic_info.get("sni"),
                    "alpn": quic_info.get("alpn"),
                    "entropy": entropy
                }
                results.append(tag)

        # 5. Encrypted / High-Entropy Alert
        if entropy > DPI_ENTROPY_THRESHOLD and len(payload) > 64 and not results:
            results.append({
                "type": "entropy_anomaly",
                "protocol": "UNKNOWN-ENCRYPTED",
                "confidence": 70,
                "description": f"High payload entropy (>{DPI_ENTROPY_THRESHOLD}) indicating strong encryption or obfuscation",
                "entropy": entropy
            })

        return results

dpi_engine = DPIEngine()
