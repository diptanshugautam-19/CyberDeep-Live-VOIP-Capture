import re
import logging

logger = logging.getLogger(__name__)

SIP_METHODS = {
    "INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS",
    "PRACK", "UPDATE", "SUBSCRIBE", "NOTIFY", "PUBLISH",
    "INFO", "REFER", "MESSAGE",
}


def parse_sip_message(payload_bytes: bytes) -> dict | None:
    """Parse SIP text payload and extract forensic headers and SDP body.

    Extracts:
      - SIP method / response status
      - Call-ID (primary correlation key)
      - Via, From, To, Contact, CSeq, Record-Route, Route
      - User-Agent / Server
      - Session-ID, Replaces, Diversion, History-Info
      - SDP body (lazy — only parsed when Content-Type is application/sdp)
        - c= connection IP
        - m= media port
        - a=candidate: lines with candidate type (host/srflx/relay)
        - a=rtpmap: codec mappings
        - a=ice-ufrag / a=ice-pwd

    Returns dict if valid SIP format, else None.
    """
    try:
        text = payload_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None

    lines = text.splitlines()
    if not lines:
        return None

    first_line = lines[0].strip()
    is_request = False
    is_response = False
    method = ""
    status_code = ""
    reason = ""

    if first_line.startswith("SIP/2.0 "):
        is_response = True
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            status_code = parts[1]
        if len(parts) >= 3:
            reason = parts[2]
    elif " SIP/2.0" in first_line:
        is_request = True
        parts = first_line.split(" ", 2)
        if len(parts) >= 1:
            method = parts[0]
    else:
        return None

    headers = {}
    vias = []
    record_routes = []
    routes = []
    contact = ""
    from_uri = ""
    to_uri = ""
    user_agent = ""
    cseq = ""
    content_type = ""
    content_length = 0
    session_id = ""
    replaces = ""
    diversion = ""
    history_info = ""
    body_lines = []
    in_body = False

    for line in lines[1:]:
        if in_body:
            body_lines.append(line)
            continue
        if not line.strip():
            in_body = True
            continue

        if ":" in line:
            name, val = line.split(":", 1)
            name = name.strip().lower()
            val = val.strip()
            headers[name] = val

            if name in ("via", "v"):
                vias.append(val)
            elif name == "record-route":
                record_routes.append(val)
            elif name == "route":
                routes.append(val)
            elif name in ("contact", "m"):
                contact = val
            elif name in ("from", "f"):
                from_uri = val
            elif name in ("to", "t"):
                to_uri = val
            elif name in ("user-agent", "server"):
                user_agent = val
            elif name == "cseq":
                cseq = val
            elif name == "content-type":
                content_type = val.lower()
            elif name == "content-length":
                try:
                    content_length = int(val)
                except ValueError:
                    pass
            elif name == "session-id":
                session_id = val
            elif name == "replaces":
                replaces = val
            elif name == "diversion":
                diversion = val
            elif name == "history-info":
                history_info = val

    call_id = headers.get("call-id", headers.get("i", "")).strip()
    if not call_id:
        return None

    result = {
        "is_request": is_request,
        "is_response": is_response,
        "method": method,
        "status_code": status_code,
        "reason": reason,
        "call_id": call_id,
        "vias": vias,
        "record_routes": record_routes,
        "routes": routes,
        "contact": contact,
        "from_uri": from_uri,
        "to_uri": to_uri,
        "user_agent": user_agent,
        "cseq": cseq,
        "session_id": session_id,
        "replaces": replaces,
        "diversion": diversion,
        "history_info": history_info,
    }

    # Lazy SDP parsing: only parse body if Content-Type indicates SDP
    if "sdp" in content_type and body_lines:
        sdp = _parse_sdp_body(body_lines)
        result.update(sdp)
    else:
        # No SDP body — set empty defaults
        result["sdp_media_ip"] = ""
        result["sdp_media_port"] = None
        result["sdp_candidates"] = []
        result["direction"] = "sendrecv"
        result["codecs"] = []
        result["ice_ufrag"] = ""
        result["ice_pwd"] = ""

    return result


def _parse_sdp_body(body_lines: list[str]) -> dict:
    """Parse SDP body lines for media endpoints, ICE candidates, and codec maps.

    Extracts:
      - c= connection address (media IP)
      - m= media description (port + payload types)
      - a=candidate: ICE candidates with type (host/srflx/relay)
      - a=rtpmap: dynamic payload type -> codec name
      - a=ice-ufrag / a=ice-pwd
      - a=sendrecv / a=sendonly / a=recvonly / a=inactive
    """
    sdp_candidates = []
    sdp_media_ip = ""
    sdp_media_port = None
    direction = "sendrecv"
    codecs = []
    ice_ufrag = ""
    ice_pwd = ""

    for sdp_line in body_lines:
        sdp_line = sdp_line.strip()

        if sdp_line.startswith("c=IN IP4 ") or sdp_line.startswith("c=IN IP6 "):
            sdp_media_ip = sdp_line.split(" ")[-1].strip()

        elif sdp_line.startswith("m=audio ") or sdp_line.startswith("m=video "):
            m_parts = sdp_line.split(" ")
            if len(m_parts) >= 2:
                try:
                    sdp_media_port = int(m_parts[1])
                except ValueError:
                    pass

        elif sdp_line.startswith("a=candidate:"):
            candidate = _parse_sdp_candidate(sdp_line)
            if candidate:
                sdp_candidates.append(candidate)

        elif sdp_line in ("a=sendonly", "a=recvonly", "a=sendrecv", "a=inactive"):
            direction = sdp_line.replace("a=", "")

        elif sdp_line.startswith("a=rtpmap:"):
            # e.g. a=rtpmap:111 opus/48000/2
            m = re.match(r"a=rtpmap:\d+\s+([\w\-\/]+)", sdp_line)
            if m:
                codecs.append(m.group(1))

        elif sdp_line.startswith("a=ice-ufrag:"):
            ice_ufrag = sdp_line.split(":", 1)[1].strip()

        elif sdp_line.startswith("a=ice-pwd:"):
            ice_pwd = sdp_line.split(":", 1)[1].strip()

    return {
        "sdp_media_ip": sdp_media_ip,
        "sdp_media_port": sdp_media_port,
        "sdp_candidates": sdp_candidates,
        "direction": direction,
        "codecs": codecs,
        "ice_ufrag": ice_ufrag,
        "ice_pwd": ice_pwd,
    }


def _parse_sdp_candidate(line: str) -> dict | None:
    """Parse SDP a=candidate line to extract candidate type (host/srflx/relay).

    Example: a=candidate:842232490 1 udp 1686052607 192.168.1.14 51234 typ host

    The 'typ' field is the ONLY place candidate type appears on the wire —
    STUN packets do not carry this label. This parser is critical for
    correct ICE attribution (avoiding misattribution of TURN relay IPs
    as real endpoints).
    """
    line = line.replace("a=candidate:", "").strip()
    parts = line.split()
    if len(parts) < 8:
        return None

    try:
        foundation = parts[0]
        component_id = int(parts[1])
        transport = parts[2]
        priority = int(parts[3])
        connection_address = parts[4]
        port = int(parts[5])
        # parts[6] should be 'typ'
        candidate_type = parts[7]  # host | srflx | relay | prflx

        candidate = {
            "foundation": foundation,
            "component_id": component_id,
            "transport": transport,
            "priority": priority,
            "ip": connection_address,
            "port": port,
            "candidate_type": candidate_type,
        }

        # Check for related addresses (raddr/rport)
        for i in range(8, len(parts) - 1):
            if parts[i] == "raddr":
                candidate["rel_address"] = parts[i + 1]
            elif parts[i] == "rport":
                try:
                    candidate["rel_port"] = int(parts[i + 1])
                except ValueError:
                    pass

        return candidate
    except Exception:
        return None
