import struct
import time
import logging
from typing import Dict, Tuple
from scapy.layers.l2 import Ether, Loopback
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from app.core.flow_engine import flow_engine, make_flow_key
from app.core.security import security_engine
from app.core.enrichment import enrichment_engine
from app.protocols.voip_manager import voip_manager

logger = logging.getLogger(__name__)

# ---- Flow Cache ----
# 5-tuple -> flow_key string cache to avoid repeated string formatting
FLOW_CACHE: Dict[Tuple[str, str, int, int, str], str] = {}
FLOW_CACHE_MAX = 50_000


def _cached_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
    """Look up or create a flow key from the 5-tuple cache."""
    key = (src_ip, dst_ip, src_port, dst_port, protocol)
    cached = FLOW_CACHE.get(key)
    if cached is not None:
        return cached
    flow_key = make_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
    if len(FLOW_CACHE) < FLOW_CACHE_MAX:
        FLOW_CACHE[key] = flow_key
    return flow_key


# ---- Port-Independent Signature Checkers ----

def is_stun_packet(payload: bytes) -> bool:
    """Check STUN magic cookie (0x2112A442) at bytes 4-8, first 2 bits == 0."""
    if len(payload) < 20:
        return False
    if payload[0] & 0xC0:
        return False
    return struct.unpack_from(">I", payload, 4)[0] == 0x2112A442


def is_stun_tcp_packet(payload: bytes) -> bool:
    """Check for RFC 4571 TCP-framed STUN packet (2-byte length prefix)."""
    if len(payload) < 22:
        return False
    length = struct.unpack_from(">H", payload, 0)[0]
    if length + 2 > len(payload):
        return False
    # Check magic cookie inside the framed STUN packet (offset 2 + 4 = 6)
    magic_cookie = struct.unpack_from(">I", payload, 6)[0]
    return magic_cookie == 0x2112A442


def is_rtp_tcp_packet(payload: bytes) -> bool:
    """Check for RFC 4571 TCP-framed RTP packet (2-byte length prefix + RTP version 2)."""
    if len(payload) < 14:
        return False
    length = struct.unpack_from(">H", payload, 0)[0]
    if length + 2 > len(payload):
        return False
    # Check RTP version inside the framed packet (offset 2)
    version = (payload[2] & 0xC0) >> 6
    return version == 2


def is_turn_channel_data(payload: bytes) -> bool:
    """Check if payload is TURN Channel Data (RFC 5766, channel 0x4000 to 0x7FFF)."""
    if len(payload) < 4:
        return False
    channel = struct.unpack_from(">H", payload, 0)[0]
    if 0x4000 <= channel <= 0x7FFF:
        length = struct.unpack_from(">H", payload, 2)[0]
        return 4 + length <= len(payload) <= 4 + length + 3
    return False


def is_rtp_packet(payload: bytes) -> bool:
    """Check RTP version 2."""
    if len(payload) < 12:
        return False
    version = (payload[0] & 0xC0) >> 6
    return version == 2


def is_dns_packet(payload: bytes) -> bool:
    """Check for DNS header structure: valid flags field, reasonable counts."""
    if len(payload) < 12:
        return False
    # DNS flags byte: check opcode (bits 1-4 of flags[0]) is standard (0-2)
    flags_hi = payload[2]
    opcode = (flags_hi >> 3) & 0x0F
    if opcode > 2:
        return False
    # Question count should be > 0 for queries, or answer count > 0 for responses
    qdcount = struct.unpack_from(">H", payload, 4)[0]
    ancount = struct.unpack_from(">H", payload, 6)[0]
    return qdcount > 0 or ancount > 0


def is_tls_packet(payload: bytes) -> bool:
    """Check TLS record header: content type 20-23, version 0x0300-0x0304."""
    if len(payload) < 5:
        return False
    content_type = payload[0]
    if content_type not in (20, 21, 22, 23):
        return False
    if payload[1] != 0x03:
        return False
    return payload[2] in (0x00, 0x01, 0x02, 0x03, 0x04)


# ---- Packet Parser ----

def parse_packet_meta(pkt_meta: dict) -> dict:
    """Parses raw packet bytes to extract L3/L4 headers and payload previews."""
    raw = pkt_meta["raw_bytes"]

    packet = None

    # 1. Try Loopback first (very common on localhost verification)
    try:
        pkt = Loopback(raw)
        if IP in pkt or IPv6 in pkt:
            packet = pkt
    except Exception:
        pass

    # 2. Try Ethernet next
    if packet is None:
        try:
            pkt = Ether(raw)
            if IP in pkt or IPv6 in pkt:
                packet = pkt
        except Exception:
            pass

    # 3. Try Raw IP fallback
    if packet is None:
        try:
            pkt = IP(raw)
            if pkt.version == 4:
                packet = pkt
        except Exception:
            pass

    # 4. Try Raw IPv6 fallback
    if packet is None:
        try:
            pkt = IPv6(raw)
            if pkt.version == 6:
                packet = pkt
        except Exception:
            pass

    # 5. Default fallback to generic Packet
    if packet is None:
        packet = Packet(raw)

    parsed = {
        "timestamp": pkt_meta["timestamp"],
        "length": pkt_meta["length"],
        "raw_bytes": raw,
        "payload": b"",
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "protocol": "IP",
        "tcp_flags": "",
        "summary": packet.summary(),
        "payload_preview": "",
        "payload_kind": "plaintext",
        "decoded_fields": {}
    }

    if IP in packet:
        parsed["source_ip"] = packet[IP].src
        parsed["destination_ip"] = packet[IP].dst
    elif IPv6 in packet:
        parsed["source_ip"] = packet[IPv6].src
        parsed["destination_ip"] = packet[IPv6].dst

    payload = b""

    if TCP in packet:
        parsed["source_port"] = packet[TCP].sport
        parsed["destination_port"] = packet[TCP].dport
        parsed["protocol"] = "TCP"

        # TCP Flags decoding
        flags = []
        f_val = int(packet[TCP].flags)
        if f_val & 0x01: flags.append("F")
        if f_val & 0x02: flags.append("S")
        if f_val & 0x04: flags.append("R")
        if f_val & 0x08: flags.append("P")
        if f_val & 0x10: flags.append("A")
        if f_val & 0x20: flags.append("U")
        parsed["tcp_flags"] = "".join(flags)

        payload = bytes(packet[TCP].payload)
        
        # Check if TCP payload is RFC 4571 framed STUN or RTP
        if payload and is_stun_tcp_packet(payload):
            length = struct.unpack_from(">H", payload, 0)[0]
            payload = payload[2:2+length]
        elif payload and is_rtp_tcp_packet(payload):
            length = struct.unpack_from(">H", payload, 0)[0]
            payload = payload[2:2+length]
            
        parsed["payload"] = payload
        if payload:
            parsed["payload_preview"] = payload[:200].decode("utf-8", errors="ignore")

    elif UDP in packet:
        parsed["source_port"] = packet[UDP].sport
        parsed["destination_port"] = packet[UDP].dport
        parsed["protocol"] = "UDP"

        payload = bytes(packet[UDP].payload)
        
        # Check if UDP payload is TURN Channel Data wrapping an RTP packet
        if payload and is_turn_channel_data(payload):
            length = struct.unpack_from(">H", payload, 2)[0]
            # Unwrap: extract the inner RTP packet
            payload = payload[4:4+length]
            
        parsed["payload"] = payload
        if payload:
            parsed["payload_preview"] = payload[:200].decode("utf-8", errors="ignore")

    elif ICMP in packet:
        parsed["protocol"] = "ICMP"

    # ---- Signature-Based Protocol Detection ----
    # Dispatch to protocol-specific parsers based on payload signatures,
    # not just port numbers, since RTP/STUN often run on dynamic ports.
    sport = parsed.get("source_port")
    dport = parsed.get("destination_port")

    if payload and is_stun_packet(payload):
        parsed["protocol"] = "STUN"
    elif payload and is_rtp_packet(payload) and not is_stun_packet(payload):
        # RTP check must come after STUN since both are UDP version-2 packets
        parsed["protocol"] = "RTP"
    elif sport == 5060 or dport == 5060 or sport == 5061 or dport == 5061:
        parsed["protocol"] = "SIP"
    elif payload and is_dns_packet(payload) and (sport == 53 or dport == 53 or sport == 5353 or dport == 5353):
        parsed["protocol"] = "DNS"
        # Simple DNS Query Extraction for summary
        if len(payload) > 12:
            try:
                dns_data = payload[12:]
                parts = []
                idx = 0
                while idx < len(dns_data) and dns_data[idx] > 0:
                    l = dns_data[idx]
                    parts.append(dns_data[idx+1:idx+1+l].decode("utf-8", errors="ignore"))
                    idx += 1 + l
                if parts:
                    parsed["dns_query"] = ".".join(parts)
                    parsed["summary"] = f"DNS Query: {parsed['dns_query']}"
            except Exception:
                pass
    elif payload and is_tls_packet(payload):
        parsed["protocol"] = "TLS"

    return parsed


async def packet_pipeline_handler(pkt_meta: dict):
    """Async packet processing pipeline coordinator.

    Dispatches to:
      1. Protocol-specific parsers (STUN/RTP/SIP/DNS/TLS detection via signatures)
      2. Security engine (disabled for VoIP focus)
      3. VoIP session manager (Call-ID correlation, ICE/TLS SNI/DNS tracking)
      4. Flow engine (5-tuple tracking, SQLite batch persistence)
      5. Enrichment engine (GeoIP, threat intel)
    """
    from app.core.bridge import broadcast_manager

    # 1. Parse headers with signature-based protocol detection
    parsed = parse_packet_meta(pkt_meta)

    # 2. Security Detection Engine (disabled — returns empty list)
    security_engine.process_packet(pkt_meta, parsed)

    # 3. VoIP call state updates (SIP Call-ID correlation, DNS/TLS SNI caching)
    await voip_manager.process_packet(parsed)

    # 4. Flow tracker & SQLite batcher (uses 5-tuple flow cache)
    flow_key = flow_engine.process_packet(parsed)

    # 5. Asynchronous Enrichment (GeoIP and Threat Reputations)
    dst_ip = parsed.get("destination_ip")
    if dst_ip and flow_key:
        enrichment_engine.enqueue_ip(dst_ip, flow_key)
