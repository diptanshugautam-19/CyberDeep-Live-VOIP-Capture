"""
QUIC Protocol Decoder module.
Parses QUIC Initial and Handshake packets to extract Version, Connection IDs,
Server Name Indication (SNI), and Application-Layer Protocol Negotiation (ALPN).
"""

import struct
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Known QUIC versions
QUIC_VERSIONS = {
    0x00000001: "QUIC v1",
    0x6b3343cf: "QUIC v2",
    0xff00001d: "Draft-29",
    0x51303530: "Q050",
    0x51303436: "Q046",
    0x00000000: "Version Negotiation"
}

def parse_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Parses a QUIC variable-length integer (RFC 9000).
    Returns (value, new_offset).
    """
    if offset >= len(data):
        return 0, offset

    first = data[offset]
    prefix = (first & 0xC0) >> 6
    length = 1 << prefix

    if offset + length > len(data):
        return 0, offset

    val = first & 0x3F
    for i in range(1, length):
        val = (val << 8) | data[offset + i]

    return val, offset + length

def parse_quic_packet(payload: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses a raw UDP payload to determine if it is a QUIC packet and extracts metadata.
    """
    try:
        if not payload or len(payload) < 5:
            return None

        first_byte = payload[0]
        is_long_header = bool(first_byte & 0x80)

        if not is_long_header:
            # Short Header (1RTT) Packet
            dcid_len = 8  # Standard DCID length estimation for short headers
            if len(payload) < 1 + dcid_len:
                return None

            dcid = payload[1:1 + dcid_len].hex()
            return {
                "packet_type": "Short (1RTT)",
                "is_long_header": False,
                "dcid": dcid,
                "scid": None,
                "version": None,
                "version_name": "QUIC Short Header"
            }

        # Long Header Packet
        if len(payload) < 6:
            return None

        version_raw = struct.unpack("!I", payload[1:5])[0]
        version_name = QUIC_VERSIONS.get(version_raw, f"Unknown (0x{version_raw:08x})")

        # Packet Type (bits 4-5 of first byte)
        packet_type_bits = (first_byte & 0x30) >> 4
        type_names = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
        packet_type = type_names.get(packet_type_bits, "Long Header")

        offset = 5

        # Destination Connection ID Length (1 byte)
        if offset >= len(payload):
            return None
        dcid_len = payload[offset]
        offset += 1

        if offset + dcid_len > len(payload):
            return None
        dcid = payload[offset:offset + dcid_len].hex()
        offset += dcid_len

        # Source Connection ID Length (1 byte)
        if offset >= len(payload):
            return None
        scid_len = payload[offset]
        offset += 1

        if offset + scid_len > len(payload):
            return None
        scid = payload[offset:offset + scid_len].hex()
        offset += scid_len

        sni = None
        alpn = None

        # Search payload for TLS ClientHello extension heuristics (SNI / ALPN)
        rem_data = payload[offset:]
        
        # SNI Search Heuristic (0x0000 extension type)
        sni_idx = rem_data.find(b"\x00\x00")
        if sni_idx != -1 and sni_idx + 9 < len(rem_data):
            try:
                name_len = struct.unpack("!H", rem_data[sni_idx + 7:sni_idx + 9])[0]
                if name_len > 0 and sni_idx + 9 + name_len <= len(rem_data):
                    candidate_sni = rem_data[sni_idx + 9:sni_idx + 9 + name_len].decode("utf-8", errors="ignore")
                    if "." in candidate_sni and all(c.isalnum() or c in ".-" for c in candidate_sni):
                        sni = candidate_sni
            except Exception:
                pass

        # ALPN Search Heuristic (e.g. h3, h3-29)
        if b"h3" in rem_data:
            if b"h3-29" in rem_data:
                alpn = "h3-29"
            else:
                alpn = "h3"

        return {
            "packet_type": packet_type,
            "is_long_header": True,
            "version": version_raw,
            "version_name": version_name,
            "dcid": dcid,
            "scid": scid,
            "sni": sni,
            "alpn": alpn
        }

    except Exception as e:
        logger.debug(f"QUIC parsing exception: {e}")
        return None
