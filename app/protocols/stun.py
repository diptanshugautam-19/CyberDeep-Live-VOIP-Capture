import struct
import logging

logger = logging.getLogger(__name__)

STUN_MAGIC_COOKIE = 0x2112A442

# STUN message type definitions (RFC 3489, RFC 5389, RFC 5766, RFC 8445, RFC 6062)
MESSAGE_TYPES = {
    0x0001: "Binding Request",
    0x0101: "Binding Success Response",
    0x0111: "Binding Error Response",
    0x0011: "Binding Indication",
    0x0003: "Allocate Request",
    0x0103: "Allocate Success Response",
    0x0113: "Allocate Error Response",
    0x0004: "Refresh Request",
    0x0104: "Refresh Success Response",
    0x0114: "Refresh Error Response",
    0x0006: "Send Indication",
    0x0007: "Data Indication",
    0x0008: "CreatePermission Request",
    0x0108: "CreatePermission Success Response",
    0x0118: "CreatePermission Error Response",
    0x0009: "ChannelBind Request",
    0x0109: "ChannelBind Success Response",
    0x0119: "ChannelBind Error Response",
    0x000A: "Connect Request",
    0x010A: "Connect Success Response",
    0x011A: "Connect Error Response",
    0x000B: "ConnectionBind Request",
    0x010B: "ConnectionBind Success Response",
    0x011B: "ConnectionBind Error Response",
    0x000C: "ConnectionAttempt Request",
    0x010C: "ConnectionAttempt Success Response",
    0x011C: "ConnectionAttempt Error Response",
}

# STUN attribute type definitions (RFC 3489, RFC 5389, RFC 5766, RFC 8445, RFC 6062, RFC 5245)
ATTRIBUTES = {
    0x0001: "MAPPED-ADDRESS",
    0x0002: "RESPONSE-ADDRESS",
    0x0003: "CHANGE-REQUEST",
    0x0004: "SOURCE-ADDRESS",
    0x0005: "CHANGED-ADDRESS",
    0x0006: "USERNAME",
    0x0007: "PASSWORD",
    0x0008: "MESSAGE-INTEGRITY",
    0x0009: "ERROR-CODE",
    0x000A: "UNKNOWN-ATTRIBUTES",
    0x000B: "REFLECTED-FROM",
    0x000C: "CHANNEL-NUMBER",
    0x000D: "LIFETIME",
    0x0010: "BANDWIDTH",
    0x0012: "XOR-PEER-ADDRESS",
    0x0013: "DATA",
    0x0014: "REALM",
    0x0015: "NONCE",
    0x0016: "XOR-RELAYED-ADDRESS",
    0x0017: "REQUESTED-ADDRESS-FAMILY",
    0x0018: "EVEN-PORT",
    0x0019: "REQUESTED-TRANSPORT",
    0x001A: "DONT-FRAGMENT",
    0x001B: "ACCESS-TOKEN",
    0x001C: "MESSAGE-INTEGRITY-SHA256",
    0x001D: "PASSWORD-ALGORITHM",
    0x001E: "USER-HASH",
    0x0020: "XOR-MAPPED-ADDRESS",
    0x0022: "RESERVATION-TOKEN",
    0x0024: "PRIORITY",
    0x0025: "USE-CANDIDATE",
    0x0026: "PADDING",
    0x0027: "RESPONSE-PORT",
    0x002A: "CONNECTION-ID",
    0x8000: "ADDITIONAL-VERSION",
    0x8020: "XOR-MAPPED-ADDRESS-ALT",
    0x8022: "SOFTWARE",
    0x8023: "ALTERNATE-SERVER",
    0x8025: "TRANSACTION-TRANSMIT-COUNTER",
    0x8027: "CACHE-TIMEOUT",
    0x8028: "FINGERPRINT",
    0x8029: "ICE-CONTROLLED",
    0x802A: "ICE-CONTROLLING",
    0x802B: "RESPONSE-ORIGIN",
    0x802C: "OTHER-ADDRESS",
    0x802D: "ECN-CHECK-CAPABILITY",
    0x802E: "THIRD-PARTY-AUTHORIZATION",
    0x8050: "MOBILITY-TICKET",
}


def decode_xor_mapped_address(mv: memoryview, transaction_id: bytes, magic_cookie: int = STUN_MAGIC_COOKIE) -> tuple[str, int]:
    """Decode XOR-MAPPED-ADDRESS, XOR-RELAYED-ADDRESS, or XOR-PEER-ADDRESS (RFC 5389 §15.2 + multi-offset fallback)."""
    if len(mv) < 4:
        raise ValueError(f"XOR-MAPPED-ADDRESS too short: {len(mv)} bytes")

    # Try standard RFC 5389 offsets first, with multi-offset fallbacks for non-standard stacks
    family_offsets = [1, 0, 2]
    for fam_off in family_offsets:
        if fam_off < len(mv):
            family = mv[fam_off]
            if family in (1, 2):
                break
    else:
        family = mv[1]

    # Try port at offset 2, 3, 1
    port_offsets = [2, 3, 1]
    xor_port = 0
    for p_off in port_offsets:
        if p_off + 2 <= len(mv):
            xor_port = struct.unpack_from(">H", mv, p_off)[0]
            break

    port = xor_port ^ (magic_cookie >> 16)

    if family == 1:  # IPv4
        # Multi-offset address scanning: try offset 4 (RFC 5389), then offset 5, offset 3
        addr_offsets = [4, 5, 3]
        for a_off in addr_offsets:
            if len(mv) >= a_off + 4:
                xor_address = struct.unpack_from(">I", mv, a_off)[0]
                address = xor_address ^ magic_cookie
                ip = ".".join(str((address >> (24 - 8 * i)) & 0xFF) for i in range(4))
                # Validate valid IPv4 address (not 0.0.0.0 or 255.255.255.255)
                if not ip.startswith("0.") and not ip.startswith("255."):
                    return ip, port

        # Fallback default if offset 4 was requested
        if len(mv) >= 8:
            xor_address = struct.unpack_from(">I", mv, 4)[0]
            address = xor_address ^ magic_cookie
            ip = ".".join(str((address >> (24 - 8 * i)) & 0xFF) for i in range(4))
            return ip, port

    elif family == 2:  # IPv6
        addr_offsets = [4, 5, 3]
        for a_off in addr_offsets:
            if len(mv) >= a_off + 16:
                xor_address = bytes(mv[a_off : a_off + 16])
                xor_mask = struct.pack(">I", magic_cookie) + transaction_id
                address_bytes = bytes(a ^ b for a, b in zip(xor_address, xor_mask))
                try:
                    import ipaddress
                    ip = str(ipaddress.ip_address(address_bytes))
                    return ip, port
                except Exception:
                    pass

    raise ValueError("Could not decode XOR-MAPPED-ADDRESS across offsets")


def parse_mapped_address(mv: memoryview) -> tuple[str, int]:
    """Decode non-XOR MAPPED-ADDRESS (RFC 5389 §15.1)."""
    if len(mv) < 4:
        raise ValueError("MAPPED-ADDRESS too short")
    family = mv[1]
    port = struct.unpack_from(">H", mv, 2)[0]
    if family == 1:  # IPv4
        if len(mv) < 8:
            raise ValueError("IPv4 MAPPED-ADDRESS incomplete")
        ip = ".".join(str(b) for b in bytes(mv[4:8]))
        return ip, port
    elif family == 2:  # IPv6
        if len(mv) < 20:
            raise ValueError("IPv6 MAPPED-ADDRESS incomplete")
        import ipaddress
        ip = str(ipaddress.ip_address(bytes(mv[4:20])))
        return ip, port
    else:
        raise ValueError(f"Unknown address family: {family}")


def parse_error_code(mv: memoryview) -> tuple[int, str]:
    """Decode ERROR-CODE attribute."""
    if len(mv) < 4:
        return 0, "Unknown Error"
    error_class = bytes(mv)[2] & 0x07
    error_number = bytes(mv)[3]
    code = error_class * 100 + error_number
    reason = bytes(mv[4:]).decode("utf-8", errors="replace")
    return code, reason


def parse_stun_packet(payload_bytes: bytes) -> dict | None:
    """Parse STUN payload using zero-copy memoryview and extract all attributes.

    Explicitly splits the USERNAME attribute into remote_ufrag and local_ufrag
    for ICE correlation with SDP candidate lines.

    Returns dict of fields if valid STUN packet, else None.
    """
    if len(payload_bytes) < 20:
        return None

    mv = memoryview(payload_bytes)

    # Check magic cookie and first 2 bits (must be 0)
    magic_cookie = struct.unpack_from(">I", mv, 4)[0]
    if magic_cookie != STUN_MAGIC_COOKIE:
        return None
    if mv[0] & 0xC0:
        return None

    message_type = struct.unpack_from(">H", mv, 0)[0]
    message_length = struct.unpack_from(">H", mv, 2)[0]
    transaction_id = bytes(mv[8:20])

    # Validate that we don't read past the actual payload size
    if len(mv) < 20 + message_length:
        return None

    message_name = MESSAGE_TYPES.get(message_type, f"Unknown Message (0x{message_type:04x})")
    fields = {
        "message_type": f"0x{message_type:04x}",
        "message_name": message_name,
        "message_length": message_length,
        "transaction_id": transaction_id.hex(),
    }

    offset = 20
    end = 20 + message_length

    try:
        while offset + 4 <= end:
            attr_type = struct.unpack_from(">H", mv, offset)[0]
            attr_len = struct.unpack_from(">H", mv, offset + 2)[0]
            if offset + 4 + attr_len > end:
                # Malformed attribute length, abort to prevent out of bounds
                break

            attr_name = ATTRIBUTES.get(attr_type, f"UNKNOWN-0x{attr_type:04x}")
            val_mv = mv[offset + 4 : offset + 4 + attr_len]

            if attr_name in ("XOR-MAPPED-ADDRESS", "XOR-RELAYED-ADDRESS", "XOR-PEER-ADDRESS"):
                try:
                    ip, port = decode_xor_mapped_address(val_mv, transaction_id)
                    # NAT64 / 464XLAT Unwrap: check for well-known prefix 64:ff9b::/96
                    if ip.startswith("64:ff9b::"):
                        try:
                            # Extract embedded IPv4 bytes from last 32 bits
                            raw_ipv4_bytes = bytes.fromhex(ip.replace("64:ff9b::", "").replace(":", ""))
                            if len(raw_ipv4_bytes) == 4:
                                ip = ".".join(str(b) for b in raw_ipv4_bytes)
                        except Exception:
                            pass
                    fields[attr_name.lower().replace("-", "_")] = {"ip": ip, "port": port}
                except Exception:
                    pass
            elif attr_name in ("MAPPED-ADDRESS", "RESPONSE-ORIGIN", "OTHER-ADDRESS", "ALTERNATE-SERVER"):
                try:
                    ip, port = parse_mapped_address(val_mv)
                    fields[attr_name.lower().replace("-", "_")] = {"ip": ip, "port": port}
                except Exception:
                    pass
            elif attr_name == "USERNAME":
                # ICE USERNAME format: "remote_ufrag:local_ufrag"
                # This split is critical for correlating STUN transactions
                # with SDP a=candidate lines via matching ufrag values.
                username = bytes(val_mv).decode("utf-8", errors="replace")
                fields["username"] = username
                if ":" in username:
                    parts = username.split(":", 1)
                    fields["remote_ufrag"] = parts[0]
                    fields["local_ufrag"] = parts[1]
                else:
                    # Non-standard USERNAME without colon separator —
                    # treat the entire value as a single ufrag for best-effort correlation
                    fields["remote_ufrag"] = username
                    fields["local_ufrag"] = ""
            elif attr_name in ("REALM", "NONCE", "SOFTWARE"):
                fields[attr_name.lower()] = bytes(val_mv).decode("utf-8", errors="replace")
            elif attr_name == "LIFETIME":
                if len(val_mv) >= 4:
                    fields["lifetime"] = struct.unpack_from(">I", val_mv, 0)[0]
            elif attr_name == "REQUESTED-TRANSPORT":
                if len(val_mv) >= 1:
                    fields["requested_transport"] = bytes(val_mv)[0]  # 17 for UDP
            elif attr_name == "PRIORITY":
                if len(val_mv) >= 4:
                    fields["priority"] = struct.unpack_from(">I", val_mv, 0)[0]
            elif attr_name in ("ICE-CONTROLLING", "ICE-CONTROLLED"):
                if len(val_mv) >= 8:
                    fields[attr_name.lower().replace("-", "_")] = struct.unpack_from(">Q", val_mv, 0)[0]
            elif attr_name == "USE-CANDIDATE":
                fields["use_candidate"] = True
            elif attr_name == "CHANNEL-NUMBER":
                if len(val_mv) >= 2:
                    fields["channel_number"] = struct.unpack_from(">H", val_mv, 0)[0]
            elif attr_name == "DATA":
                fields["data_len"] = len(val_mv)
            elif attr_name == "ERROR-CODE":
                code, reason = parse_error_code(val_mv)
                fields["error_code"] = code
                fields["error_reason"] = reason
            elif attr_name == "DONT-FRAGMENT":
                fields["dont_fragment"] = True
            elif attr_name == "RESERVATION-TOKEN":
                fields["reservation_token"] = bytes(val_mv).hex()

            # Align to 4-byte boundary
            offset += 4 + ((attr_len + 3) & ~3)

    except Exception:
        # Prevent any parsing exceptions from crashing ingestion
        pass

    return fields


# ---------------------------------------------------------------------------
# ICE-specific STUN binding parser
# (from ProductionWebRTCCaptureEngine.parse_stun_binding)
# ---------------------------------------------------------------------------

def parse_stun_binding_for_ice(payload_bytes: bytes) -> dict | None:
    """
    Parse a STUN Binding Request or Response and extract the ICE-critical fields
    needed by the IceStateMachine:

      - is_request: bool (True = Binding Request, False = Success Response)
      - use_candidate: bool (presence of USE-CANDIDATE attribute, RFC 8445 §7.1.1)
      - priority: int | None (from PRIORITY attribute — identifies local candidate)
      - ufrag: str | None  (from USERNAME, first part before ':')
      - xor_mapped: {"ip": str, "port": int} | None (decoded XOR-MAPPED-ADDRESS)
      - is_controlling: bool  (ICE-CONTROLLING attribute present)
      - is_controlled: bool   (ICE-CONTROLLED attribute present)
      - transaction_id: str   (hex)

    Returns None if payload is not a valid STUN Binding message.
    """
    fields = parse_stun_packet(payload_bytes)
    if not fields:
        return None

    # Only care about Binding messages
    msg_name = fields.get("message_name", "")
    if "Binding" not in msg_name:
        return None

    is_request = "Request" in msg_name

    # Derive ufrag from USERNAME (format: "remote_ufrag:local_ufrag")
    username = fields.get("username", "")
    ufrag = fields.get("remote_ufrag") or (username.split(":")[0] if ":" in username else username[:8]) or None

    return {
        "is_request":      is_request,
        "use_candidate":   fields.get("use_candidate", False),
        "priority":        fields.get("priority"),
        "ufrag":           ufrag,
        "xor_mapped":      fields.get("xor_mapped_address") or fields.get("mapped_address"),
        "is_controlling":  "ice_controlling" in fields,
        "is_controlled":   "ice_controlled" in fields,
        "transaction_id":  fields.get("transaction_id", ""),
    }
