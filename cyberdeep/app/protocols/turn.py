"""
TURN protocol parser — allocation tracking + channel binding.
Integrates ProductionWebRTCCaptureEngine.parse_turn_message() logic.
"""

import socket
import struct
import logging
from typing import Optional, Tuple, Dict, List
from datetime import datetime

from .stun import parse_stun_packet, decode_xor_mapped_address, STUN_MAGIC_COOKIE
from .ice import TURNAllocation

logger = logging.getLogger(__name__)

# TURN-specific method names
TURN_METHODS = {
    "Allocate",
    "Refresh",
    "Send",
    "Data",
    "CreatePermission",
    "ChannelBind",
}

# STUN attribute type constants (mirrored from Production WebRTC Capture Engine v3)
ATTR_XOR_MAPPED_ADDR   = 0x0020
ATTR_XOR_RELAYED_ADDR  = 0x0016
ATTR_XOR_PEER_ADDR     = 0x0012
ATTR_CHANNEL_NUMBER    = 0x000C
ATTR_LIFETIME          = 0x000D
ATTR_REALM             = 0x0014
ATTR_NONCE             = 0x0015
ATTR_REQUESTED_TRANSPORT = 0x0019

# STUN method codes
STUN_METHOD_ALLOCATE     = 0x0003
STUN_METHOD_CHANNEL_BIND = 0x0009

STUN_MAGIC = STUN_MAGIC_COOKIE


# ---------------------------------------------------------------------------
# Raw attribute dict parser (mirrors _parse_stun_attrs from engine v3)
# Used here because we need raw byte values before decode_xor_mapped_address
# ---------------------------------------------------------------------------

def _parse_stun_attrs_raw(data: bytes) -> Dict[int, bytes]:
    """Parse STUN TLV attributes into {attr_type: raw_value_bytes} dict."""
    attrs: Dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(data):
        try:
            attr_type, attr_len = struct.unpack('!HH', data[pos:pos + 4])
            value = data[pos + 4: pos + 4 + attr_len]
            padded_len = attr_len + ((4 - (attr_len % 4)) % 4)
            attrs[attr_type] = value
            pos += 4 + padded_len
        except struct.error:
            break
    return attrs


# ---------------------------------------------------------------------------
# XOR address decode for TURN (works for relayed/peer addresses)
# ---------------------------------------------------------------------------

def _decode_xor_addr_raw(raw: bytes, txn_id: bytes) -> Optional[Tuple[str, int]]:
    """
    Decode XOR-RELAYED-ADDRESS or XOR-PEER-ADDRESS from raw attribute bytes.
    Returns (ip, port) or None on failure.
    Mirrors the inline decoding in ProductionWebRTCCaptureEngine.parse_turn_message().
    """
    if len(raw) < 8:
        return None
    try:
        family = raw[1]
        if family == 0x01:  # IPv4
            xport = struct.unpack('!H', raw[2:4])[0]
            xip   = struct.unpack('!I', raw[4:8])[0]
            port  = xport ^ (STUN_MAGIC >> 16)
            ip    = socket.inet_ntoa(struct.pack('!I', xip ^ STUN_MAGIC))
            return ip, port
        elif family == 0x02 and len(raw) >= 20:  # IPv6
            xport   = struct.unpack('!H', raw[2:4])[0]
            xip     = raw[4:20]
            xor_key = struct.pack('!I', STUN_MAGIC) + txn_id
            port    = xport ^ struct.unpack('!H', xor_key[:2])[0]
            ip_bytes = bytes(a ^ b for a, b in zip(xip, (xor_key * 4)[:16]))
            ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
            return ip, port
    except (struct.error, ValueError, OSError) as e:
        logger.debug(f"[TURN] Failed to decode XOR address from raw bytes: {e}")
    except Exception as e:
        logger.debug(f"[TURN] Unexpected error decoding XOR address: {e}")
    return None


# ---------------------------------------------------------------------------
# Backward-compatible thin wrapper (existing callers rely on this)
# ---------------------------------------------------------------------------

def parse_turn_packet(payload_bytes: bytes) -> dict | None:
    """
    Parse a TURN message using STUN framing.
    Returns structured dict if this is a TURN message, else None.
    Kept for backward compatibility with voip_manager.py.
    """
    fields = parse_stun_packet(payload_bytes)
    if not fields:
        return None

    message_name = fields.get("message_name", "")
    is_turn = any(method in message_name for method in TURN_METHODS)
    if not is_turn:
        return None

    fields["is_turn"] = True
    fields["is_relay_creation"] = "Allocate" in message_name
    fields["is_channel_bind"] = "ChannelBind" in message_name

    if "xor_relayed_address" in fields:
        fields["xor_relayed_address"]["source"] = "relayed_allocation"
    if "xor_peer_address" in fields:
        fields["xor_peer_address"]["source"] = "peer_destination"

    return fields


# ---------------------------------------------------------------------------
# New: TURN Allocate Response parser → TURNAllocation
# (from ProductionWebRTCCaptureEngine.parse_turn_message — Allocate response branch)
# ---------------------------------------------------------------------------

def parse_turn_allocate_response(
    payload_bytes: bytes,
    client_addr: Tuple[str, int],
    txn_sessions: Dict[str, dict]
) -> Optional[TURNAllocation]:
    """
    Parse a TURN Allocate Success Response and build a TURNAllocation.

    Args:
        payload_bytes: raw UDP payload
        client_addr:   (ip, port) of the TURN client from packet header
        txn_sessions:  in-flight transaction dict keyed by txn_id hex
                       (populated by parse_turn_allocate_request())

    Returns TURNAllocation on success, None otherwise.
    """
    if len(payload_bytes) < 20:
        return None

    try:
        msg_type, msg_len, magic = struct.unpack('!HHI', payload_bytes[:8])
        txn_id = payload_bytes[8:20]
    except struct.error:
        return None

    if magic != STUN_MAGIC:
        return None

    # Must be an Allocate success response (0x0103)
    method = msg_type & 0x011F
    if method != STUN_METHOD_ALLOCATE:
        return None
    # Class bits: success response = 0b01
    msg_class = ((msg_type & 0x0100) >> 7) | ((msg_type & 0x0010) >> 4)
    if msg_class != 0b01:
        return None

    attrs = _parse_stun_attrs_raw(payload_bytes[20: 20 + msg_len])

    # Decode XOR-RELAYED-ADDRESS
    relayed_raw = attrs.get(ATTR_XOR_RELAYED_ADDR)
    if not relayed_raw:
        return None

    relay_result = _decode_xor_addr_raw(relayed_raw, txn_id)
    if not relay_result:
        return None
    relay_ip, relay_port = relay_result

    # Decode lifetime
    lifetime_raw = attrs.get(ATTR_LIFETIME, b'\x00\x00\x0e\x10')
    lifetime = struct.unpack('!I', lifetime_raw[:4])[0] if len(lifetime_raw) >= 4 else 600

    # Realm / Nonce
    realm = attrs.get(ATTR_REALM, b'').decode('utf-8', errors='ignore') or None
    nonce = attrs.get(ATTR_NONCE, b'').decode('utf-8', errors='ignore') or None

    # Use client from in-flight request if available, else fall back to packet src
    txn_hex = txn_id.hex()
    if txn_hex in txn_sessions and 'client' in txn_sessions[txn_hex]:
        resolved_client = txn_sessions[txn_hex]['client']
    else:
        resolved_client = client_addr

    allocation = TURNAllocation(
        relay_addr=relay_ip,
        relay_port=relay_port,
        client_addr=resolved_client[0],
        client_port=resolved_client[1],
        lifetime=lifetime,
        realm=realm,
        nonce=nonce,
    )

    logger.info(
        f"[TURN] Allocation: {resolved_client[0]}:{resolved_client[1]} "
        f"-> relay {relay_ip}:{relay_port} (lifetime={lifetime}s)"
    )

    # --- turn_xor_mapped_client (from ProductionWebRTCCaptureEngine.parse_turn_message) ---
    # XOR-MAPPED-ADDRESS in the Allocate response reveals the client's NAT-mapped address.
    # This is the 'turn_xor_mapped_client' source used in print_report() SRFLX category.
    xor_mapped_client = None
    xor_raw = attrs.get(ATTR_XOR_MAPPED_ADDR)
    if xor_raw:
        xor_result = _decode_xor_addr_raw(xor_raw, txn_id)
        if xor_result:
            xor_ip, xor_port = xor_result
            xor_mapped_client = (xor_ip, xor_port)
            logger.info(
                f"[TURN] XOR-MAPPED-ADDRESS (real client): {xor_ip}:{xor_port}"
            )

    # Return allocation with xor_mapped_client attached as an extra attribute
    # so voip_manager can record 'turn_xor_mapped_client' in ip_store
    allocation._xor_mapped_client = xor_mapped_client
    return allocation


# ---------------------------------------------------------------------------
# New: TURN Allocate Request tracker
# (from parse_turn_message — Allocate request branch)
# ---------------------------------------------------------------------------

def parse_turn_allocate_request(
    payload_bytes: bytes,
    src_addr: Tuple[str, int],
    txn_sessions: Dict[str, dict]
) -> bool:
    """
    Record in-flight TURN Allocate Request metadata keyed by transaction ID.

    Args:
        payload_bytes: raw payload
        src_addr:      (ip, port) of sender from packet header
        txn_sessions:  mutable dict to update (keyed by txn_id hex)

    Returns True if this was an Allocate request, False otherwise.
    """
    if len(payload_bytes) < 20:
        return False

    try:
        msg_type, msg_len, magic = struct.unpack('!HHI', payload_bytes[:8])
        txn_id = payload_bytes[8:20]
    except struct.error:
        return False

    if magic != STUN_MAGIC:
        return False

    method = msg_type & 0x011F
    # Class bits: request = 0b00
    msg_class = ((msg_type & 0x0100) >> 7) | ((msg_type & 0x0010) >> 4)
    if method != STUN_METHOD_ALLOCATE or msg_class != 0b00:
        return False

    attrs = _parse_stun_attrs_raw(payload_bytes[20: 20 + msg_len])

    # Requested transport: byte 0 is protocol number (17=UDP, 6=TCP)
    req_transport_raw = attrs.get(ATTR_REQUESTED_TRANSPORT, b'\x11')
    transport = 'TCP' if req_transport_raw[0] == 6 else 'UDP'

    txn_hex = txn_id.hex()
    txn_sessions[txn_hex] = {
        'client': src_addr,
        'requested_at': datetime.now(),
        'transport': transport,
    }
    return True


# ---------------------------------------------------------------------------
# New: TURN Channel Bind parser
# (from ProductionWebRTCCaptureEngine.parse_turn_message — ChannelBind branch)
# ---------------------------------------------------------------------------

def parse_turn_channel_bind(
    payload_bytes: bytes,
    src_addr: Tuple[str, int],
    allocations: Dict[str, TURNAllocation],
    client_to_allocation: Optional[Dict[str, List[str]]] = None
) -> bool:
    """
    Parse a TURN Channel Bind Request and update the matching TURNAllocation.

    Args:
        payload_bytes:        raw payload
        src_addr:             (ip, port) of sender
        allocations:          dict of relay_addr:port -> TURNAllocation to update
        client_to_allocation: optional reverse index (client_ip -> list of allocation keys) for O(1) lookup

    Returns True if a channel was successfully bound, False otherwise.
    """
    if len(payload_bytes) < 20:
        return False

    try:
        msg_type, msg_len, magic = struct.unpack('!HHI', payload_bytes[:8])
        txn_id = payload_bytes[8:20]
    except struct.error:
        return False

    if magic != STUN_MAGIC:
        return False

    method = msg_type & 0x011F
    msg_class = ((msg_type & 0x0100) >> 7) | ((msg_type & 0x0010) >> 4)
    if method != STUN_METHOD_CHANNEL_BIND or msg_class != 0b00:
        return False

    attrs = _parse_stun_attrs_raw(payload_bytes[20: 20 + msg_len])

    channel_raw = attrs.get(ATTR_CHANNEL_NUMBER)
    peer_raw    = attrs.get(ATTR_XOR_PEER_ADDR)

    if not channel_raw or not peer_raw:
        return False

    channel = struct.unpack('!H', channel_raw[:2])[0]
    peer_result = _decode_xor_addr_raw(peer_raw, txn_id)
    if not peer_result:
        return False
    peer_ip, peer_port = peer_result

    # O(1) Reverse index lookup if available
    target_keys = client_to_allocation.get(src_addr[0], []) if client_to_allocation is not None else allocations.keys()
    for key in target_keys:
        alloc = allocations.get(key)
        if alloc and alloc.client_addr == src_addr[0]:
            alloc.channels[channel] = (peer_ip, peer_port)
            logger.info(f"[TURN] Channel {channel} bound to peer {peer_ip}:{peer_port}")
            return True

    return False
