"""
TCP media stream reassembly and protocol demultiplexing.

Ports analyze_tcp_stream(), _detect_tcp_framing(), _process_rfc4571_frames(),
_process_websocket_frames(), and _process_sip_tcp() from
ProductionWebRTCCaptureEngine v3 into the CyberDEEP module architecture.
"""

import re
import struct
import logging
from typing import Dict, Optional, Callable, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Framing type constants
# ---------------------------------------------------------------------------
FRAMING_RFC4571    = "rfc4571"    # RFC 4571 length-prefix (RTP or STUN over TCP)
FRAMING_WEBSOCKET  = "websocket"  # WebSocket frame header
FRAMING_SIP        = "sip"        # Plain SIP over TCP
FRAMING_UNKNOWN    = "unknown"

# SIP method line prefixes (for fast startswith check)
_SIP_REQUEST_PREFIXES = (
    b'SIP/', b'INVITE ', b'REGISTER ', b'ACK ', b'BYE ',
    b'CANCEL ', b'OPTIONS ', b'SUBSCRIBE ', b'NOTIFY ',
    b'PUBLISH ', b'INFO ', b'REFER ', b'MESSAGE ',
    b'UPDATE ', b'PRACK ',
)


# ---------------------------------------------------------------------------
# Per-stream state store (used by voip_manager as tcp_stream_buffers)
# ---------------------------------------------------------------------------

def make_tcp_stream() -> dict:
    """Create an empty TCP stream state dict."""
    return {
        'buffer': b'',
        'framing_type': None,
        'identified_protocol': None,
    }


# ---------------------------------------------------------------------------
# detect_tcp_framing  (mirrors _detect_tcp_framing)
# ---------------------------------------------------------------------------

def detect_tcp_framing(data: bytes) -> Optional[str]:
    """
    Detect framing type from the first bytes of a TCP stream.

    Priority order:
      1. RFC 4571  — 2-byte length prefix followed by a valid RTP version-2 header
      2. WebSocket — HTTP Upgrade handshake OR WebSocket binary/text frame FIN bit
      3. SIP       — starts with a known SIP method or 'SIP/2.0'
      4. unknown   — cannot determine yet (need more data)
    """
    if len(data) < 2:
        return None

    # --- RFC 4571: 2-byte big-endian length then RTP ---
    length = struct.unpack('!H', data[:2])[0]
    if 12 <= length <= 1500 and len(data) >= 2 + length:
        candidate = data[2: 2 + min(length, 20)]
        if len(candidate) >= 12 and ((candidate[0] >> 6) & 0x03) == 2:
            return FRAMING_RFC4571

    # --- WebSocket HTTP upgrade or frame header ---
    if data.startswith((b'GET ', b'HTTP/')):
        return FRAMING_WEBSOCKET
    first = data[0]
    if (first & 0x80) and (first & 0x0F) in (0x00, 0x01, 0x02, 0x08, 0x09, 0x0A):
        return FRAMING_WEBSOCKET

    # --- SIP ---
    if data.startswith(_SIP_REQUEST_PREFIXES):
        return FRAMING_SIP

    return FRAMING_UNKNOWN


# ---------------------------------------------------------------------------
# process_rfc4571_frames  (mirrors _process_rfc4571_frames)
# ---------------------------------------------------------------------------

def process_rfc4571_frames(
    stream: dict,
    src_addr: Tuple[str, int],
    stream_key: str,
    on_rtp: Callable[[str, int, int, int, int, str], None],
) -> None:
    """
    Consume a reassembly buffer containing RFC 4571 length-framed RTP.

    Calls on_rtp(ip, port, payload_type, ssrc, seq, stream_key) for each valid
    RTP frame extracted.

    Args:
        stream:     stream state dict with 'buffer' key
        src_addr:   (ip, port) of the TCP sender
        stream_key: opaque key for deduplication / context
        on_rtp:     callback invoked per valid RTP frame
    """
    buf = stream['buffer']

    while len(buf) >= 2:
        length = struct.unpack('!H', buf[:2])[0]

        if len(buf) < 2 + length:
            break  # Wait for more data

        frame = buf[2: 2 + length]
        buf = buf[2 + length:]

        if len(frame) >= 12:
            version = (frame[0] >> 6) & 0x03
            if version == 2:
                pt   = frame[1] & 0x7F
                seq  = struct.unpack('!H', frame[2:4])[0]
                ssrc = struct.unpack('!I', frame[8:12])[0]
                on_rtp(src_addr[0], src_addr[1], pt, ssrc, seq, stream_key)

    stream['buffer'] = buf


# ---------------------------------------------------------------------------
# process_websocket_frames  (mirrors _process_websocket_frames)
# ---------------------------------------------------------------------------

def process_websocket_frames(
    stream: dict,
    src_addr: Tuple[str, int],
    on_sip_bytes: Callable[[bytes, str, int], None],
) -> None:
    """
    Demultiplex WebSocket frames and forward text frames to SIP/SDP parser.

    Calls on_sip_bytes(payload_bytes, src_ip, src_port) for each unmasked
    text-opcode frame.

    Args:
        stream:       stream state dict with 'buffer' key
        src_addr:     (ip, port) of sender
        on_sip_bytes: callback for SIP payloads found inside WebSocket text frames
    """
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

        frame_payload = buf[header_len: header_len + payload_len]
        if mask_key:
            frame_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(frame_payload))

        buf = buf[header_len + payload_len:]

        # Text frame — could be SIP/SDP
        if opcode == 0x01 and frame_payload:
            on_sip_bytes(frame_payload, src_addr[0], src_addr[1])

    stream['buffer'] = buf


# ---------------------------------------------------------------------------
# process_sip_tcp  (mirrors _process_sip_tcp)
# ---------------------------------------------------------------------------

def process_sip_tcp(
    stream: dict,
    src_addr: Tuple[str, int],
    on_sip_bytes: Callable[[bytes, str, int], None],
) -> None:
    """
    Reassemble and deliver complete SIP messages from a TCP stream.

    Uses Content-Length framing (RFC 3261 §20.14) to detect message boundaries.

    Args:
        stream:       stream state dict with 'buffer' key
        src_addr:     (ip, port) of sender
        on_sip_bytes: callback invoked with the full SIP message bytes
    """
    buf = stream['buffer']

    while b'\r\n\r\n' in buf:
        header_end = buf.find(b'\r\n\r\n')
        header_text = buf[:header_end].decode('utf-8', errors='ignore')

        cl_match = re.search(r'Content-Length:\s*(\d+)', header_text, re.IGNORECASE)
        if cl_match:
            body_len = int(cl_match.group(1))
            total_len = header_end + 4 + body_len
            if len(buf) >= total_len:
                message = buf[:total_len]
                buf = buf[total_len:]
                on_sip_bytes(message, src_addr[0], src_addr[1])
            else:
                break  # Wait for full body
        else:
            # Header-only message (BYE, ACK with no body, etc.)
            message = buf[:header_end + 4]
            buf = buf[header_end + 4:]
            on_sip_bytes(message, src_addr[0], src_addr[1])

    stream['buffer'] = buf


# ---------------------------------------------------------------------------
# analyze_tcp_stream  (mirrors analyze_tcp_stream — main entry point)
# ---------------------------------------------------------------------------

def analyze_tcp_stream(
    data: bytes,
    stream: dict,
    src_addr: Tuple[str, int],
    dst_addr: Tuple[str, int],
    stream_key: str,
    on_rtp: Callable[[str, int, int, int, int, str], None],
    on_sip_bytes: Callable[[bytes, str, int], None],
) -> None:
    """
    Entry point for TCP stream analysis.

    Appends *data* to the stream buffer, auto-detects framing (once), then
    dispatches to the appropriate sub-processor:
      - RFC 4571  → process_rfc4571_frames  (RTP-over-TCP)
      - WebSocket → process_websocket_frames (SIP/SDP in WS text frames)
      - SIP       → process_sip_tcp          (SIP over plain TCP)

    Args:
        data:         new bytes received on this stream
        stream:       per-stream state dict (use make_tcp_stream() to create)
        src_addr:     (ip, port) of sender
        dst_addr:     (ip, port) of receiver
        stream_key:   opaque key for de-duplication context
        on_rtp:       callback(ip, port, pt, ssrc, seq, stream_key) per RTP frame
        on_sip_bytes: callback(payload_bytes, src_ip, src_port) per SIP message
    """
    stream['buffer'] += data

    # Auto-detect framing type once
    if stream['framing_type'] is None:
        detected = detect_tcp_framing(stream['buffer'])
        if detected:
            stream['framing_type'] = detected

    framing = stream['framing_type']

    if framing == FRAMING_RFC4571:
        process_rfc4571_frames(stream, src_addr, stream_key, on_rtp)
    elif framing == FRAMING_WEBSOCKET:
        process_websocket_frames(stream, src_addr, on_sip_bytes)
    elif framing == FRAMING_SIP:
        process_sip_tcp(stream, src_addr, on_sip_bytes)
    # UNKNOWN: accumulate until framing can be determined
