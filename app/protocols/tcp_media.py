"""
TCP media stream reassembly and protocol demultiplexing.

Improvements:
  - bytearray buffer (O(1) extend vs O(n²) bytes concatenation)
  - Optimized WebSocket unmasking using bytearray + XOR
  - Stricter bounds checking
"""

import re
import struct
import logging
from typing import Dict, Optional, Callable, Tuple

logger = logging.getLogger(__name__)

FRAMING_RFC4571    = "rfc4571"
FRAMING_WEBSOCKET  = "websocket"
FRAMING_SIP        = "sip"
FRAMING_UNKNOWN    = "unknown"

_CL_REGEX = re.compile(rb'Content-Length:\s*(\d+)', re.IGNORECASE)
MAX_TCP_BUFFER_SIZE = 1_048_576

_SIP_REQUEST_PREFIXES = (
    b'SIP/', b'INVITE ', b'REGISTER ', b'ACK ', b'BYE ',
    b'CANCEL ', b'OPTIONS ', b'SUBSCRIBE ', b'NOTIFY ',
    b'PUBLISH ', b'INFO ', b'REFER ', b'MESSAGE ',
    b'UPDATE ', b'PRACK ',
)


def make_tcp_stream() -> dict:
    """Create an empty TCP stream state dict with bytearray buffer."""
    return {
        'buffer': bytearray(),       # bytearray: O(1) extend vs O(n) bytes +=
        'framing_type': None,
        'identified_protocol': None,
    }


def detect_tcp_framing(data: bytes | bytearray) -> Optional[str]:
    """Detect framing type from the first bytes of a TCP stream."""
    first_bytes = bytes(data[:64])

    if len(first_bytes) >= 2:
        length = struct.unpack('!H', first_bytes[:2])[0]
        if 12 <= length <= 1500 and len(data) >= 2 + length:
            candidate = data[2: 2 + min(length, 20)]
            if len(candidate) >= 12 and ((candidate[0] >> 6) & 0x03) == 2:
                return FRAMING_RFC4571

    if first_bytes.startswith((b'GET ', b'HTTP/')):
        return FRAMING_WEBSOCKET
    if first_bytes:
        first = first_bytes[0]
        if (first & 0x80) and (first & 0x0F) in (0x00, 0x01, 0x02, 0x08, 0x09, 0x0A):
            return FRAMING_WEBSOCKET

    if first_bytes.startswith(_SIP_REQUEST_PREFIXES):
        return FRAMING_SIP

    return FRAMING_UNKNOWN


def process_rfc4571_frames(
    stream: dict,
    src_addr: Tuple[str, int],
    stream_key: str,
    on_rtp: Callable[[str, int, int, int, int, str], None],
) -> None:
    buf = stream['buffer']

    while len(buf) >= 2:
        length = struct.unpack('!H', buf[:2])[0]

        if len(buf) < 2 + length:
            break

        frame = buf[2: 2 + length]
        del buf[:2 + length]  # O(k) slice deletion on bytearray

        if len(frame) >= 12:
            version = (frame[0] >> 6) & 0x03
            if version == 2:
                pt   = frame[1] & 0x7F
                seq  = struct.unpack('!H', frame[2:4])[0]
                ssrc = struct.unpack('!I', frame[8:12])[0]
                on_rtp(src_addr[0], src_addr[1], pt, ssrc, seq, stream_key)


def process_websocket_frames(
    stream: dict,
    src_addr: Tuple[str, int],
    on_sip_bytes: Callable[[bytes, str, int], None],
) -> None:
    buf = stream['buffer']

    while len(buf) >= 2:
        b1, b2 = buf[0], buf[1]
        opcode     = b1 & 0x0F
        masked     = b2 & 0x80
        payload_len = b2 & 0x7F
        header_len  = 2

        if payload_len == 126:
            if len(buf) < 4:
                break
            payload_len = struct.unpack('!H', buf[2:4])[0]
            header_len = 4
        elif payload_len == 127:
            if len(buf) < 10:
                break
            payload_len = struct.unpack('!Q', buf[2:10])[0]
            header_len = 10

        mask_key = None
        if masked:
            if len(buf) < header_len + 4:
                break
            mask_key = buf[header_len: header_len + 4]
            header_len += 4

        if len(buf) < header_len + payload_len:
            break

        frame_payload = bytearray(buf[header_len: header_len + payload_len])
        if mask_key:
            # High-speed bytearray XOR unmasking
            for i in range(len(frame_payload)):
                frame_payload[i] ^= mask_key[i % 4]

        del buf[:header_len + payload_len]

        if opcode == 0x01 and frame_payload:
            on_sip_bytes(bytes(frame_payload), src_addr[0], src_addr[1])


def process_sip_tcp(
    stream: dict,
    src_addr: Tuple[str, int],
    on_sip_bytes: Callable[[bytes, str, int], None],
) -> None:
    buf = stream['buffer']

    while b'\r\n\r\n' in buf:
        header_end = buf.find(b'\r\n\r\n')
        header_text = bytes(buf[:header_end])

        cl_match = _CL_REGEX.search(header_text)
        if cl_match:
            body_len = int(cl_match.group(1))
            total_len = header_end + 4 + body_len
            if len(buf) >= total_len:
                message = bytes(buf[:total_len])
                del buf[:total_len]
                on_sip_bytes(message, src_addr[0], src_addr[1])
            else:
                break
        else:
            message = bytes(buf[:header_end + 4])
            del buf[:header_end + 4]
            on_sip_bytes(message, src_addr[0], src_addr[1])


def analyze_tcp_stream(
    data: bytes,
    stream: dict,
    src_addr: Tuple[str, int],
    dst_addr: Tuple[str, int],
    stream_key: str,
    on_rtp: Callable[[str, int, int, int, int, str], None],
    on_sip_bytes: Callable[[bytes, str, int], None],
) -> None:
    if 'buffer' not in stream or not isinstance(stream['buffer'], bytearray):
        stream['buffer'] = bytearray()

    if len(stream['buffer']) + len(data) > MAX_TCP_BUFFER_SIZE:
        logger.warning(f"TCP stream buffer for {stream_key} exceeded {MAX_TCP_BUFFER_SIZE} limit, resetting.")
        stream['buffer'].clear()
        stream['framing_type'] = None
        return

    stream['buffer'].extend(data)  # O(1) bytearray extend vs O(n²) bytes +=

    if stream['framing_type'] is None:
        framing = detect_tcp_framing(stream['buffer'])
        if framing is None:
            return
        stream['framing_type'] = framing

    framing = stream['framing_type']
    if framing == FRAMING_RFC4571:
        process_rfc4571_frames(stream, src_addr, stream_key, on_rtp)
    elif framing == FRAMING_WEBSOCKET:
        process_websocket_frames(stream, src_addr, on_sip_bytes)
    elif framing == FRAMING_SIP:
        process_sip_tcp(stream, src_addr, on_sip_bytes)
