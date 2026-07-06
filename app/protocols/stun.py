import struct

STUN_MAGIC_COOKIE = 0x2112A442

# STUN message type definitions
MESSAGE_TYPES = {
    0x0001: "Binding Request",
    0x0101: "Binding Success Response",
    0x0111: "Binding Error Response",
    0x0003: "Allocate Request",
    0x0103: "Allocate Success Response",
    0x0113: "Allocate Error Response",
    0x0004: "Refresh Request",
    0x0104: "Refresh Success Response",
    0x0006: "Send Indication",
    0x0007: "Data Indication",
    0x0009: "CreatePermission Request",
    0x0109: "CreatePermission Success Response",
    0x000a: "ChannelBind Request",
    0x010a: "ChannelBind Success Response",
}

# STUN attribute type definitions
ATTRIBUTES = {
    0x0001: "MAPPED-ADDRESS",
    0x0006: "USERNAME",
    0x0008: "MESSAGE-INTEGRITY",
    0x0009: "ERROR-CODE",
    0x000c: "CHANNEL-NUMBER",
    0x000d: "LIFETIME",
    0x0012: "XOR-PEER-ADDRESS",
    0x0013: "DATA",
    0x0014: "REALM",
    0x0015: "NONCE",
    0x0016: "XOR-RELAYED-ADDRESS",
    0x0018: "EVEN-PORT",
    0x0019: "REQUESTED-TRANSPORT",
    0x001a: "DONT-FRAGMENT",
    0x0020: "XOR-MAPPED-ADDRESS",
    0x0022: "RESERVATION-TOKEN",
    0x0024: "PRIORITY",
    0x0025: "USE-CANDIDATE",
    0x8022: "SOFTWARE",
    0x8023: "ALTERNATE-SERVER",
    0x8028: "FINGERPRINT",
    0x8029: "ICE-CONTROLLED",
    0x802a: "ICE-CONTROLLING",
}


def decode_xor_mapped_address(attr_value: bytes, transaction_id: bytes, magic_cookie: int = STUN_MAGIC_COOKIE) -> tuple[str, int]:
    """Decode XOR-MAPPED-ADDRESS or XOR-RELAYED-ADDRESS / XOR-PEER-ADDRESS.

    Args:
        attr_value: Raw attribute bytes (reserved + family + xor_port + xor_address)
        transaction_id: 12-byte STUN transaction ID
        magic_cookie: STUN magic cookie (default 0x2112A442)

    Returns:
        (ip_string, port_int)
    """
    if len(attr_value) < 4:
        raise ValueError(f"XOR-MAPPED-ADDRESS too short: {len(attr_value)} bytes")

    family = struct.unpack(">H", attr_value[1:3])[0]
    xor_port = struct.unpack(">H", attr_value[3:5])[0]

    if family == 1:  # IPv4
        if len(attr_value) < 9:
            raise ValueError("IPv4 XOR-MAPPED-ADDRESS incomplete")
        xor_address = struct.unpack(">I", attr_value[5:9])[0]
        port = xor_port ^ (magic_cookie >> 16)
        address = xor_address ^ magic_cookie
        ip = ".".join(str((address >> (24 - 8 * i)) & 0xFF) for i in range(4))
        return ip, port

    elif family == 2:  # IPv6
        if len(attr_value) < 21:
            raise ValueError("IPv6 XOR-MAPPED-ADDRESS incomplete")
        xor_address = attr_value[5:21]
        port = xor_port ^ (magic_cookie >> 16)
        xor_mask = struct.pack(">I", magic_cookie) + transaction_id
        address_bytes = bytes(a ^ b for a, b in zip(xor_address, xor_mask))
        import ipaddress
        ip = str(ipaddress.ip_address(address_bytes))
        return ip, port

    else:
        raise ValueError(f"Unknown address family: {family}")


def parse_mapped_address(attr_value: bytes) -> tuple[str, int]:
    """Decode non-XOR MAPPED-ADDRESS."""
    if len(attr_value) < 4:
        raise ValueError("MAPPED-ADDRESS too short")
    family = struct.unpack(">H", attr_value[1:3])[0]
    port = struct.unpack(">H", attr_value[3:5])[0]
    if family == 1:  # IPv4
        if len(attr_value) < 9:
            raise ValueError("IPv4 MAPPED-ADDRESS incomplete")
        ip = ".".join(str(b) for b in attr_value[5:9])
        return ip, port
    elif family == 2:  # IPv6
        if len(attr_value) < 21:
            raise ValueError("IPv6 MAPPED-ADDRESS incomplete")
        import ipaddress
        ip = str(ipaddress.ip_address(attr_value[5:21]))
        return ip, port
    else:
        raise ValueError(f"Unknown address family: {family}")


def parse_error_code(attr_value: bytes) -> tuple[int, str]:
    """Decode ERROR-CODE attribute."""
    if len(attr_value) < 4:
        return 0, "Unknown Error"
    error_class = attr_value[2] & 0x07
    error_number = attr_value[3]
    code = error_class * 100 + error_number
    reason = attr_value[4:].decode("utf-8", errors="replace")
    return code, reason


def parse_stun_packet(payload_bytes: bytes) -> dict | None:
    """Parse STUN payload and extract all attributes safely.

    Returns dict of fields if valid STUN packet, else None.
    """
    if len(payload_bytes) < 20:
        return None

    # Check magic cookie and first 2 bits (must be 0)
    magic_cookie = struct.unpack(">I", payload_bytes[4:8])[0]
    if magic_cookie != STUN_MAGIC_COOKIE:
        return None
    if payload_bytes[0] & 0xC0:
        return None

    message_type = struct.unpack(">H", payload_bytes[:2])[0]
    message_length = struct.unpack(">H", payload_bytes[2:4])[0]
    transaction_id = payload_bytes[8:20]

    # Validate that we don't read past the actual payload size
    if len(payload_bytes) < 20 + message_length:
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
            attr_type, attr_len = struct.unpack(">HH", payload_bytes[offset:offset+4])
            if offset + 4 + attr_len > end:
                # Malformed attribute length, abort to prevent out of bounds
                break

            attr_name = ATTRIBUTES.get(attr_type, f"UNKNOWN-0x{attr_type:04x}")
            val_bytes = payload_bytes[offset+4:offset+4+attr_len]

            if attr_name in ("XOR-MAPPED-ADDRESS", "XOR-RELAYED-ADDRESS", "XOR-PEER-ADDRESS"):
                try:
                    ip, port = decode_xor_mapped_address(val_bytes, transaction_id)
                    fields[attr_name.lower().replace("-", "_")] = {"ip": ip, "port": port}
                except Exception:
                    pass
            elif attr_name == "MAPPED-ADDRESS":
                try:
                    ip, port = parse_mapped_address(val_bytes)
                    fields["mapped_address"] = {"ip": ip, "port": port}
                except Exception:
                    pass
            elif attr_name == "USERNAME":
                username = val_bytes.decode("utf-8", errors="replace")
                fields["username"] = username
                if ":" in username:
                    parts = username.split(":", 1)
                    fields["remote_ufrag"] = parts[0]
                    fields["local_ufrag"] = parts[1]
            elif attr_name in ("REALM", "NONCE", "SOFTWARE"):
                fields[attr_name.lower()] = val_bytes.decode("utf-8", errors="replace")
            elif attr_name == "LIFETIME":
                if len(val_bytes) >= 4:
                    fields["lifetime"] = struct.unpack(">I", val_bytes[:4])[0]
            elif attr_name == "REQUESTED-TRANSPORT":
                if len(val_bytes) >= 1:
                    fields["requested_transport"] = val_bytes[0]  # 17 for UDP
            elif attr_name == "PRIORITY":
                if len(val_bytes) >= 4:
                    fields["priority"] = struct.unpack(">I", val_bytes[:4])[0]
            elif attr_name in ("ICE-CONTROLLING", "ICE-CONTROLLED"):
                if len(val_bytes) >= 8:
                    fields[attr_name.lower().replace("-", "_")] = struct.unpack(">Q", val_bytes[:8])[0]
            elif attr_name == "USE-CANDIDATE":
                fields["use_candidate"] = True
            elif attr_name == "CHANNEL-NUMBER":
                if len(val_bytes) >= 2:
                    fields["channel_number"] = struct.unpack(">H", val_bytes[:2])[0]
            elif attr_name == "DATA":
                fields["data_len"] = len(val_bytes)
            elif attr_name == "ERROR-CODE":
                code, reason = parse_error_code(val_bytes)
                fields["error_code"] = code
                fields["error_reason"] = reason
            elif attr_name == "DONT-FRAGMENT":
                fields["dont_fragment"] = True
            elif attr_name == "RESERVATION-TOKEN":
                fields["reservation_token"] = val_bytes.hex()

            # Align to 4-byte boundary
            offset += 4 + ((attr_len + 3) & ~3)

    except Exception:
        # Prevent any parsing exceptions from crashing ingestion
        pass

    return fields
