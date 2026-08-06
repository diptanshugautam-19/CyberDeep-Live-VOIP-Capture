import struct
import logging

logger = logging.getLogger(__name__)


def extract_sni(payload: bytes) -> str | None:
    """
    Parse a TLS ClientHello to extract the Server Name Indication (SNI) hostname.

    This performs explicit parsing of the ClientHello handshake structure
    and walks the extensions to find extension type 0x0000 (server_name).
    Returns the hostname string, or None if this is not a ClientHello or
    the SNI extension is absent.
    """
    try:
        if len(payload) < 43:
            return None

        # TLS Record: content_type=0x16 (Handshake), version=0x03xx
        if payload[0] != 0x16 or payload[1] != 0x03:
            return None

        # Handshake type must be 0x01 (ClientHello)
        if payload[5] != 0x01:
            return None

        # Skip: TLS record header (5) + handshake header (4) + client version (2) + random (32)
        pos = 5 + 4 + 2 + 32

        # Session ID (1-byte length prefix)
        if pos >= len(payload):
            return None
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        # Cipher suites (2-byte length prefix)
        if pos + 2 > len(payload):
            return None
        cipher_len = struct.unpack_from(">H", payload, pos)[0]
        pos += 2 + cipher_len

        # Compression methods (1-byte length prefix)
        if pos + 1 > len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len

        # Extensions (2-byte length prefix)
        if pos + 2 > len(payload):
            return None
        extensions_len = struct.unpack_from(">H", payload, pos)[0]
        pos += 2

        end_pos = pos + extensions_len
        if end_pos > len(payload):
            end_pos = len(payload)

        # Walk extensions looking for type 0x0000 (server_name)
        while pos + 4 <= end_pos:
            ext_type = struct.unpack_from(">H", payload, pos)[0]
            ext_len = struct.unpack_from(">H", payload, pos + 2)[0]
            pos += 4

            if ext_type == 0x0000:
                # server_name extension found — parse the ServerNameList
                if pos + 2 > end_pos:
                    return None
                # list_length (2 bytes), then entries
                inner_pos = pos + 2  # skip ServerNameList length
                if inner_pos + 3 > end_pos:
                    return None
                name_type = payload[inner_pos]
                name_len = struct.unpack_from(">H", payload, inner_pos + 1)[0]
                if name_type == 0 and inner_pos + 3 + name_len <= end_pos:
                    return payload[inner_pos + 3 : inner_pos + 3 + name_len].decode(
                        "utf-8", errors="ignore"
                    )
                return None

            pos += ext_len

    except Exception:
        pass

    return None
