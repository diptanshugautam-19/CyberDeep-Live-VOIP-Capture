from collections import Counter
import gzip
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from app.parsers.base import ConnectionRecord, EvidenceParser, ParserError


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8080, 8081, 8888, 8443}


class PcapParser(EvidenceParser):
    supported_extensions = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".cap.gz")

    def parse(self, path: Path) -> Iterable[ConnectionRecord]:
        try:
            from scapy.all import ARP, DNS, Ether, IP, Raw, TCP, UDP, rdpcap
        except Exception as exc:  # pragma: no cover - depends on optional capture stack
            raise ParserError("Scapy is required for PCAP parsing. Install requirements.txt.") from exc

        try:
            packets = rdpcap(str(path)) if not path.name.lower().endswith(".gz") else rdpcap(gzip.open(path, "rb"))
        except Exception as exc:  # pragma: no cover
            raise ParserError(f"Unable to read PCAP evidence: {exc}") from exc

        flows: Counter[tuple] = Counter()
        bytes_by_flow: Counter[tuple] = Counter()
        first_seen: dict[tuple, str] = {}
        first_mac_seen: dict[tuple, tuple[str | None, str | None]] = {}
        tcp_flag_samples: dict[tuple, set[str]] = {}
        dns_queries: dict[tuple, set[str]] = {}
        payload_samples: dict[tuple, dict] = {}
        packet_details: dict[tuple, list[dict]] = {}

        for packet in packets:
            src_ip = None
            dst_ip = None
            src_mac, dst_mac = _ethernet_macs(packet)

            try:
                from scapy.all import IP, IPv6, ARP, TCP, UDP
            except:
                pass

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            elif ARP in packet:
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
            elif src_mac:
                src_ip = src_mac
                dst_ip = dst_mac or "L2 Broadcast"

            if not src_ip or not dst_ip:
                continue

            src_port = dst_port = None
            base_proto = "IP"
            if TCP in packet:
                src_port, dst_port, base_proto = int(packet[TCP].sport), int(packet[TCP].dport), "TCP"
            elif UDP in packet:
                src_port, dst_port, base_proto = int(packet[UDP].sport), int(packet[UDP].dport), "UDP"
            elif ARP in packet:
                base_proto = "ARP"

            payload_present, payload_bytes = _packet_payload_bytes(packet)
            protocol = _detect_protocol(packet, base_proto, src_port, dst_port, payload_bytes)

            IGNORE_PROTOCOLS = {
                "HTTP",
                "FTP",
                "SMTP",
                "POP3",
                "IMAP",
                "SMB",
                "NFS",
                "RDP",
                "TELNET",
                "MYSQL",
                "POSTGRESQL",
                "BITTORRENT"
            }
            if protocol in IGNORE_PROTOCOLS:
                continue

            key = (src_ip, dst_ip, src_port, dst_port, protocol)
            tcp_flags = _tcp_flags(packet)
            if tcp_flags:
                tcp_flag_samples.setdefault(key, set()).add(tcp_flags)

            flows[key] += 1
            bytes_by_flow[key] += len(packet)
            first_seen.setdefault(key, _packet_timestamp(packet))
            first_mac_seen.setdefault(key, (src_mac, dst_mac))
            packet_dns = _dns_preview(packet)
            if packet_dns:
                dns_queries.setdefault(key, set()).update(packet_dns["queries"])
            sample = _payload_sample(packet, packet_dns, base_proto, src_port, dst_port, payload_present, payload_bytes)
            decoded = _decode_packet(packet, base_proto, src_port, dst_port, packet_dns, payload_bytes, sample, app_protocol=protocol)
            sample["decoded_type"] = decoded.get("type")
            sample["decoded_summary"] = decoded.get("summary")
            sample["decoded_detail"] = decoded.get("detail")
            if sample.get("payload_kind") == "plaintext" and decoded.get("type", "").startswith("HTTP"):
                sample["payload_preview"] = decoded.get("summary") or sample.get("payload_preview")
            existing_sample = payload_samples.get(key)
            if existing_sample is None or _sample_priority(sample) > _sample_priority(existing_sample):
                payload_samples[key] = sample
            packet_entries = packet_details.setdefault(key, [])
            packet_entries.append(
                {
                    "packet_index": len(packet_entries) + 1,
                    "timestamp": _packet_timestamp(packet),
                    "length": len(packet),
                    "protocol": protocol,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "source_port": src_port,
                    "destination_port": dst_port,
                    "source_mac": src_mac,
                    "destination_mac": dst_mac,
                    "tcp_flags": tcp_flags,
                    "flow_label": _flow_label(src_ip, dst_ip, src_port, dst_port, protocol),
                    "summary": _packet_summary(packet),
                    "decoded_type": decoded.get("type"),
                    "decoded_summary": decoded.get("summary"),
                    "decoded_detail": decoded.get("detail"),
                    "decoded_fields": decoded.get("fields"),
                    "payload_kind": sample.get("payload_kind"),
                    "payload_preview": sample.get("payload_preview"),
                    "payload_hex": sample.get("payload_hex"),
                }
            )

        for (src, dst, sport, dport, protocol), count in flows.items():
            sample = payload_samples.get((src, dst, sport, dport, protocol), {})
            macs = first_mac_seen.get((src, dst, sport, dport, protocol), (None, None))
            yield ConnectionRecord(
                source_ip=src,
                destination_ip=dst,
                source_port=sport,
                destination_port=dport,
                protocol=protocol,
                timestamp=first_seen.get((src, dst, sport, dport, protocol)),
                packet_count=count,
                bytes_transferred=bytes_by_flow[(src, dst, sport, dport, protocol)],
                source_mac=macs[0],
                destination_mac=macs[1],
                tcp_flags=", ".join(sorted(tcp_flag_samples.get((src, dst, sport, dport, protocol), set()))) or None,
                dns_query=", ".join(sorted(dns_queries.get((src, dst, sport, dport, protocol), set()))) or None,
                payload_preview=sample.get("payload_preview"),
                payload_hex=sample.get("payload_hex"),
                payload_kind=sample.get("payload_kind"),
                packet_details=packet_details.get((src, dst, sport, dport, protocol), []),
            )


def _packet_timestamp(packet) -> str | None:
    try:
        timestamp = float(packet.time)
    except (TypeError, ValueError):
        return None
    if timestamp <= 0:
        return None
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _packet_payload_bytes(packet) -> tuple[bool, bytes | None]:
    from scapy.all import Raw

    if not packet.haslayer(Raw):
        return False, None
    try:
        return True, bytes(packet["Raw"].load)
    except Exception:
        return True, None


def _ethernet_macs(packet) -> tuple[str | None, str | None]:
    try:
        from scapy.all import Ether

        if packet.haslayer(Ether):
            layer = packet.getlayer(Ether)
            return getattr(layer, "src", None), getattr(layer, "dst", None)
    except Exception:
        pass
    return None, None


def _tcp_flags(packet) -> str | None:
    try:
        from scapy.all import TCP

        if packet.haslayer(TCP):
            flags = packet.getlayer(TCP).flags
            return str(flags)
    except Exception:
        return None
    return None


def _payload_sample(
    packet,
    dns_preview: dict | None,
    protocol: str,
    src_port: int | None,
    dst_port: int | None,
    payload_present: bool,
    payload_bytes: bytes | None,
) -> dict:
    if dns_preview and dns_preview.get("preview"):
        return {
            "payload_kind": "dns",
            "payload_preview": dns_preview["preview"],
            "payload_hex": None,
        }

    if payload_bytes is None:
        if payload_present:
            return {
                "payload_kind": "opaque",
                "payload_preview": "Packet payload present but could not be decoded",
                "payload_hex": None,
            }
        return {
            "payload_kind": "metadata_only",
            "payload_preview": "No packet payload extracted",
            "payload_hex": None,
        }

    if not payload_bytes:
        return {
            "payload_kind": "empty",
            "payload_preview": "Empty packet payload",
            "payload_hex": None,
        }

    ascii_preview = _ascii_preview(payload_bytes)
    if ascii_preview:
        return {
            "payload_kind": "plaintext",
            "payload_preview": ascii_preview,
            "payload_hex": payload_bytes[:32].hex(" "),
        }

    if _looks_encrypted(payload_bytes, protocol, src_port, dst_port):
        return {
            "payload_kind": "encrypted",
            "payload_preview": "Encrypted payload detected; ciphertext preview shown below",
            "payload_hex": payload_bytes[:64].hex(" "),
        }

    return {
        "payload_kind": "binary",
        "payload_preview": "Binary payload detected",
        "payload_hex": payload_bytes[:64].hex(" "),
    }


def _sample_priority(sample: dict) -> int:
    decoded_type = str(sample.get("decoded_type") or "").upper()
    if decoded_type.startswith("HTTP"):
        return 6
    order = {
        "dns": 5,
        "plaintext": 4,
        "encrypted": 3,
        "binary": 2,
        "opaque": 1,
        "empty": 0,
        "metadata_only": 0,
    }
    return order.get(sample.get("payload_kind"), 0)


def _packet_summary(packet) -> str:
    try:
        return packet.summary()
    except Exception:
        return "Packet summary unavailable"


def _flow_label(src: str, dst: str, src_port: int | None, dst_port: int | None, protocol: str) -> str:
    return f"{src}:{src_port or 'n/a'} -> {dst}:{dst_port or 'n/a'} ({protocol})"


def _decode_packet(
    packet,
    protocol: str,
    src_port: int | None,
    dst_port: int | None,
    dns_preview: dict | None,
    payload_bytes: bytes | None,
    sample: dict,
    app_protocol: str = "",
) -> dict:
    from scapy.all import DNS

    if packet.haslayer(DNS):
        return _decode_dns_packet(packet)

    if app_protocol in ("SIP", "SDP"):
        sip = _decode_sip_packet(payload_bytes, app_protocol)
        if sip:
            return sip

    if app_protocol in ("RTP", "SRTP"):
        rtp = _decode_rtp_packet(payload_bytes, app_protocol)
        if rtp:
            return rtp

    if app_protocol in ("RTCP", "SRTCP"):
        rtcp = _decode_rtcp_packet(payload_bytes, app_protocol)
        if rtcp:
            return rtcp

    stun = _decode_stun_packet(payload_bytes, protocol)
    if stun:
        return stun

    http = _decode_http_packet(payload_bytes, protocol, src_port, dst_port)
    if http:
        return http

    payload_kind = sample.get("payload_kind")
    if payload_kind == "encrypted":
        return {
            "type": "Encrypted Payload",
            "summary": "Ciphertext or TLS-encrypted data detected",
            "detail": "Plaintext cannot be recovered without decryption material. Hex preview is shown in the payload panel.",
            "fields": {
                "ciphertext_preview": sample.get("payload_hex") or "",
            },
        }

    if payload_kind == "plaintext":
        preview = sample.get("payload_preview") or "Readable payload detected"
        return {
            "type": "Plaintext Payload",
            "summary": preview,
            "detail": preview,
            "fields": {
                "preview": preview,
            },
        }

    if payload_kind == "binary":
        return {
            "type": "Binary Payload",
            "summary": "Non-text payload detected",
            "detail": "The packet contains data that does not decode cleanly as text.",
            "fields": {
                "binary_preview": sample.get("payload_hex") or "",
            },
        }

    if payload_kind in {"metadata_only", "empty"}:
        return {
            "type": "No Payload",
            "summary": "No application payload extracted",
            "detail": sample.get("payload_preview") or "No application payload extracted",
            "fields": {},
        }

    if payload_kind == "opaque":
        return {
            "type": "Opaque Payload",
            "summary": sample.get("payload_preview") or "Packet payload present but could not be decoded",
            "detail": sample.get("payload_preview") or "Packet payload present but could not be decoded",
            "fields": {},
        }

    return {
        "type": "Unknown",
        "summary": sample.get("payload_preview") or "Packet payload present but could not be decoded",
        "detail": sample.get("payload_preview") or "Packet payload present but could not be decoded",
        "fields": {},
    }


def _parse_sip(payload_bytes: bytes | None) -> dict | None:
    if not payload_bytes:
        return None
    try:
        text = payload_bytes.decode("utf-8", errors="ignore")
    except Exception:
        try:
            text = payload_bytes.decode("iso-8859-1", errors="ignore")
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
    contact = ""
    from_uri = ""
    to_uri = ""
    user_agent = ""
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
            elif name in ("contact", "m"):
                contact = val
            elif name in ("from", "f"):
                from_uri = val
            elif name in ("to", "t"):
                to_uri = val
            elif name in ("user-agent", "server"):
                user_agent = val
    
    sdp_media_ip = ""
    sdp_media_port = None
    if body_lines:
        for sdp_line in body_lines:
            sdp_line = sdp_line.strip()
            if sdp_line.startswith("c=IN IP4 "):
                sdp_media_ip = sdp_line.replace("c=IN IP4 ", "").strip()
            elif sdp_line.startswith("m=audio "):
                m_parts = sdp_line.split(" ")
                if len(m_parts) >= 2:
                    try:
                        sdp_media_port = int(m_parts[1])
                    except ValueError:
                        pass

    call_id = headers.get("call-id", headers.get("i", "")).strip()
    if not call_id:
        return None

    return {
        "is_request": is_request,
        "is_response": is_response,
        "method": method,
        "status_code": status_code,
        "reason": reason,
        "call_id": call_id,
        "vias": vias,
        "record_routes": record_routes,
        "contact": contact,
        "from_uri": from_uri,
        "to_uri": to_uri,
        "user_agent": user_agent,
        "sdp_media_ip": sdp_media_ip,
        "sdp_media_port": sdp_media_port,
        "first_line": first_line,
        "headers": headers,
    }


def _decode_sip_packet(payload_bytes: bytes | None, app_protocol: str) -> dict | None:
    if not payload_bytes:
        return None
    from app.protocols.sip import parse_sip_message
    parsed = parse_sip_message(payload_bytes)
    if not parsed:
        return None

    call_id = parsed["call_id"]
    msg_type = "SIP Request" if parsed["is_request"] else "SIP Response"
    if parsed["is_request"]:
        summary = f"SIP {parsed['method']} | Call-ID: {call_id[:12]}..."
    else:
        summary = f"SIP {parsed['status_code']} {parsed['reason']} | Call-ID: {call_id[:12]}..."

    detail = f"Call-ID: {call_id}\nFrom: {parsed['from_uri']}\nTo: {parsed['to_uri']}\nUser-Agent: {parsed['user_agent']}"
    if parsed["sdp_media_ip"] or parsed["sdp_media_port"]:
        detail += f"\nSDP Media: {parsed['sdp_media_ip'] or 'n/a'}:{parsed['sdp_media_port'] or 'n/a'}"

    return {
        "type": msg_type,
        "summary": summary,
        "detail": detail,
        "fields": parsed
    }


def _decode_rtp_packet(payload_bytes: bytes | None, protocol: str) -> dict | None:
    if not payload_bytes:
        return None
    from app.protocols.rtp import parse_rtp_header
    parsed = parse_rtp_header(payload_bytes)
    if not parsed:
        return None

    pt = parsed["payload_type"]
    from app.protocols.rtp import PAYLOAD_SAMPLE_RATES
    pt_names = {
        0: "PCMU (G.711 mu-law)",
        3: "GSM",
        4: "G723",
        8: "PCMA (G.711 a-law)",
        9: "G722",
        18: "G729",
        96: "Dynamic (dynamic)",
        97: "Dynamic (dynamic)",
        101: "Dynamic (telephone-event)",
    }
    pt_name = pt_names.get(pt, f"Dynamic/Reserved ({pt})")

    return {
        "type": f"{protocol} Media",
        "summary": f"{protocol} | Payload: {pt_name} | Seq: {parsed['sequence_number']} | SSRC: {parsed['ssrc']}",
        "detail": f"RTP Version: {parsed['version']}\nPayload Type: {pt} ({pt_name})\nSequence: {parsed['sequence_number']}\nTimestamp: {parsed['timestamp']}\nSSRC: {parsed['ssrc']}",
        "fields": parsed
    }


def _decode_rtcp_packet(payload_bytes: bytes | None, protocol: str) -> dict | None:
    if not payload_bytes or len(payload_bytes) < 8:
        return None
    version = (payload_bytes[0] & 0xC0) >> 6
    if version != 2:
        return None
    packet_type = payload_bytes[1]
    length = int.from_bytes(payload_bytes[2:4], "big")
    ssrc = int.from_bytes(payload_bytes[4:8], "big")

    rtcp_types = {
        200: "Sender Report (SR)",
        201: "Receiver Report (RR)",
        202: "Source Description (SDES)",
        203: "Goodbye (BYE)",
        204: "Application-defined (APP)",
    }
    type_name = rtcp_types.get(packet_type, f"Unknown ({packet_type})")

    return {
        "type": f"{protocol} Control",
        "summary": f"{protocol} {type_name} | SSRC: {ssrc}",
        "detail": f"RTCP Version: {version}\nType: {packet_type} ({type_name})\nSSRC: {ssrc}\nLength: {length} words",
        "fields": {
            "rtcp_version": version,
            "packet_type": packet_type,
            "packet_type_name": type_name,
            "ssrc": ssrc,
            "length_words": length,
        }
    }


def _decode_stun_packet(payload_bytes: bytes | None, protocol: str) -> dict | None:
    if protocol.upper() != "UDP" or not payload_bytes:
        return None
    from app.protocols.stun import parse_stun_packet
    parsed = parse_stun_packet(payload_bytes)
    if not parsed:
        return None

    msg_name = parsed["message_name"]
    return {
        "type": f"STUN {msg_name}",
        "summary": f"STUN {msg_name}",
        "detail": f"Message length: {parsed['message_length']} bytes | Transaction ID: {parsed['transaction_id']}",
        "fields": parsed,
    }


def _decode_dns_packet(packet) -> dict:
    from scapy.all import DNS

    dns = packet[DNS]
    mode = "Response" if int(getattr(dns, "qr", 0) or 0) else "Request"
    questions = _dns_questions(dns)
    answers = _dns_answers(dns)
    transaction_id = int(getattr(dns, "id", 0) or 0)
    rcode = _dns_rcode_name(getattr(dns, "rcode", 0))
    summary_bits = [f"DNS {mode}"]
    if questions:
        summary_bits.append(questions[0])
    if answers:
        summary_bits.append(answers[0])
    detail_bits = [
        f"Transaction ID: {transaction_id}",
        f"RCode: {rcode}",
    ]
    if questions:
        detail_bits.append("Questions: " + "; ".join(questions[:4]))
    if answers:
        detail_bits.append("Answers: " + "; ".join(answers[:4]))
    return {
        "type": f"DNS {mode}",
        "summary": " | ".join(summary_bits),
        "detail": " | ".join(detail_bits),
        "fields": {
            "transaction_id": transaction_id,
            "mode": mode,
            "rcode": rcode,
            "questions": questions,
            "answers": answers,
        },
    }


def _decode_http_packet(payload_bytes: bytes | None, protocol: str, src_port: int | None, dst_port: int | None) -> dict | None:
    if not payload_bytes:
        return None

    text = payload_bytes.decode("iso-8859-1", errors="ignore")
    if not text.strip():
        return None

    first_line, headers, body = _split_http_message(text)
    if not first_line:
        return None

    if first_line.startswith("HTTP/1."):
        parts = first_line.split(" ", 2)
        status_code = parts[1] if len(parts) > 1 else ""
        reason = parts[2] if len(parts) > 2 else ""
        body_preview = _text_preview(body)
        summary = f"HTTP Response {status_code}".strip()
        if reason:
            summary = f"{summary} {reason}".strip()
        detail_bits = []
        if headers.get("content-type"):
            detail_bits.append(f"Content-Type: {headers['content-type']}")
        if headers.get("content-length"):
            detail_bits.append(f"Content-Length: {headers['content-length']}")
        if body_preview:
            detail_bits.append(f"Body Preview: {body_preview}")
        return {
            "type": "HTTP Response",
            "summary": summary,
            "detail": " | ".join(detail_bits) or first_line,
            "fields": {
                "version": "HTTP/1.x",
                "status_code": status_code,
                "reason": reason,
                "headers": headers,
                "body_preview": body_preview,
            },
        }

    http_method = None
    for method in HTTP_METHODS:
        if first_line.startswith(f"{method} "):
            http_method = method
            break

    if not http_method and protocol.upper() == "TCP" and {src_port, dst_port} & HTTP_PORTS and ("HTTP/" in text or "Host:" in text):
        candidate = first_line.split(" ", 1)[0]
        if candidate in HTTP_METHODS:
            http_method = candidate

    if not http_method:
        return None

    parts = first_line.split(" ", 2)
    path = parts[1] if len(parts) > 1 else "/"
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    host = headers.get("host", "")
    body_preview = _text_preview(body)
    summary = f"HTTP Request {http_method} {path}".strip()
    if host:
        summary = f"{summary} | Host: {host}"
    detail_bits = [
        f"Method: {http_method}",
        f"Path: {path}",
        f"Version: {version}",
    ]
    if host:
        detail_bits.append(f"Host: {host}")
    if headers.get("user-agent"):
        detail_bits.append(f"User-Agent: {headers['user-agent']}")
    if headers.get("content-type"):
        detail_bits.append(f"Content-Type: {headers['content-type']}")
    if body_preview:
        detail_bits.append(f"Body Preview: {body_preview}")
    return {
        "type": "HTTP Request",
        "summary": summary,
        "detail": " | ".join(detail_bits),
        "fields": {
            "method": http_method,
            "path": path,
            "version": version,
            "host": host,
            "headers": headers,
            "body_preview": body_preview,
        },
    }


def _split_http_message(text: str) -> tuple[str, dict, str]:
    head, separator, body = text.partition("\r\n\r\n")
    if not separator:
        head, separator, body = text.partition("\n\n")
    lines = [line for line in head.splitlines() if line.strip()]
    if not lines:
        return "", {}, body
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return lines[0].strip(), headers, body


def _text_preview(value: str) -> str:
    if not value:
        return ""
    cleaned = "".join(char for char in value if char in "\t\r\n" or 32 <= ord(char) <= 126).strip()
    if not cleaned:
        return ""
    return cleaned[:240]


def _dns_questions(dns) -> list[str]:
    questions = []
    current = getattr(dns, "qd", None)
    seen = 0
    while current is not None and seen < 8:
        try:
            name_bytes = current.qname
        except Exception:
            break
        if not name_bytes:
            break
        name = name_bytes.decode("utf-8", errors="ignore").rstrip(".")
        qtype = _dns_type_name(getattr(current, "qtype", None))
        questions.append(f"{name} ({qtype})")
        seen += 1
        try:
            current = current.payload
        except Exception:
            break
        if current is None:
            break
    return questions


def _dns_answers(dns) -> list[str]:
    answers = []
    current = getattr(dns, "an", None)
    seen = 0
    while current is not None and seen < 8:
        try:
            rrname = current.rrname
        except Exception:
            break
        if not rrname:
            break
        name = rrname.decode("utf-8", errors="ignore").rstrip(".")
        rtype = _dns_type_name(getattr(current, "type", None))
        rdata = getattr(current, "rdata", "")
        answers.append(f"{name} -> {rdata} ({rtype})")
        seen += 1
        try:
            current = current.payload
        except Exception:
            break
        if current is None:
            break
    return answers


def _dns_type_name(value) -> str:
    mapping = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        41: "OPT",
    }
    try:
        return mapping.get(int(value), str(value) if value is not None else "UNKNOWN")
    except (TypeError, ValueError):
        return str(value) if value is not None else "UNKNOWN"


def _dns_rcode_name(value) -> str:
    mapping = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }
    try:
        return mapping.get(int(value), str(value) if value is not None else "UNKNOWN")
    except (TypeError, ValueError):
        return str(value) if value is not None else "UNKNOWN"


def _looks_encrypted(payload_bytes: bytes, protocol: str, src_port: int | None, dst_port: int | None) -> bool:
    secure_ports = {
        443,
        465,
        563,
        636,
        853,
        993,
        995,
        1433,
        2083,
        2087,
        2096,
        5061,
        5223,
        7844,
        8443,
        9443,
    }
    port_set = {port for port in (src_port, dst_port) if port is not None}

    if protocol.upper() == "TCP" and port_set & secure_ports:
        return True

    if protocol.upper() == "UDP" and port_set & {443, 853, 7844}:
        return True

    if len(payload_bytes) >= 5:
        first, major, minor = payload_bytes[0], payload_bytes[1], payload_bytes[2]
        if first in {0x14, 0x15, 0x16, 0x17, 0x18} and major == 0x03 and minor in {0x00, 0x01, 0x02, 0x03, 0x04}:
            return True

    return False


def _ascii_preview(payload_bytes: bytes) -> str:
    printable = bytes(byte for byte in payload_bytes[:160] if byte in b"\t\r\n" or 32 <= byte <= 126)
    if not printable:
        return ""
    decoded = printable.decode("utf-8", errors="ignore").strip()
    if len(decoded) < 4:
        return ""
    return decoded[:160]


def _dns_preview(packet) -> dict | None:
    from scapy.all import DNS

    if not packet.haslayer(DNS):
        return None

    queries = []
    answers = []
    try:
        dns_layer = packet[DNS]
        if getattr(dns_layer, "qd", None) is not None and hasattr(dns_layer.qd, "qname"):
            queries.append(dns_layer.qd.qname.decode("utf-8", errors="ignore").rstrip("."))
    except Exception:
        pass

    for section_name in ("an", "ns", "ar"):
        try:
            section = getattr(packet[DNS], section_name)
            if section is not None and hasattr(section, "rrname"):
                rrname = getattr(section, "rrname", b"")
                rdata = getattr(section, "rdata", "")
                if rrname:
                    name = rrname.decode("utf-8", errors="ignore").rstrip(".")
                    answers.append(f"{name} -> {rdata}")
        except Exception:
            continue

    preview_parts = []
    if queries:
        preview_parts.append("DNS query: " + ", ".join(queries[:4]))
    if answers:
        preview_parts.append("DNS answer: " + "; ".join(str(item) for item in answers[:3]))
    if not preview_parts:
        preview_parts.append("DNS/mDNS packet detected")
    return {"queries": set(queries), "preview": " | ".join(preview_parts)}


def _detect_protocol(packet, base_protocol: str, src_port: int | None, dst_port: int | None, payload_bytes: bytes | None) -> str:
    # 1. Layer 2 / Network layer specific structures
    try:
        from scapy.all import ARP, ICMP, DNS
    except:
        pass

    if packet.haslayer("ARP"):
        return "ARP"
    if packet.haslayer("ICMP"):
        return "ICMP"
    if packet.haslayer("ICMPv6ND_NS") or packet.haslayer("ICMPv6ND_NA") or packet.haslayer("ICMPv6DestUnreach") or "ICMPv6" in packet.summary():
        return "ICMPv6"
    if packet.haslayer("DNS"):
        if src_port == 5353 or dst_port == 5353:
            return "mDNS"
        if src_port == 5355 or dst_port == 5355:
            return "LLMNR"
        return "DNS"

    # DHCP checks
    if packet.haslayer("DHCP") or packet.haslayer("BOOTP"):
        return "DHCP"
    if packet.haslayer("DHCP6") or src_port in {546, 547} or dst_port in {546, 547}:
        return "DHCPv6"

    # EAPOL / 802.11 / Radiotap
    if packet.haslayer("EAPOL") or (hasattr(packet, "type") and packet.type == 0x888e):
        return "EAPOL"
    if packet.haslayer("Dot11"):
        return "802.11"
    if packet.haslayer("Radiotap"):
        return "Radiotap"

    # IP protocol level checks
    # RSVP is protocol 46
    if hasattr(packet, "proto") and packet.proto == 46:
        return "RSVP"
    # GRE is protocol 47
    if packet.haslayer("GRE") or (hasattr(packet, "proto") and packet.proto == 47):
        return "GRE"
    # ESP is protocol 50
    if packet.haslayer("ESP") or (hasattr(packet, "proto") and packet.proto == 50):
        return "ESP"
    # AH is protocol 51
    if packet.haslayer("AH") or (hasattr(packet, "proto") and packet.proto == 51):
        return "AH"

    # Application layer checks (over UDP or TCP)
    ports = {src_port, dst_port}

    # Ignored protocols detection (FTP, TELNET, SMTP, POP3, IMAP, SMB, NFS, RDP, MYSQL, POSTGRESQL, BITTORRENT, HTTP)
    if 21 in ports or 20 in ports:
        return "FTP"
    if 23 in ports:
        return "TELNET"
    if 25 in ports or 465 in ports or 587 in ports:
        return "SMTP"
    if 110 in ports or 995 in ports:
        return "POP3"
    if 143 in ports or 993 in ports:
        return "IMAP"
    if 445 in ports:
        return "SMB"
    if 2049 in ports:
        return "NFS"
    if 3389 in ports:
        return "RDP"
    if 3306 in ports:
        return "MYSQL"
    if 5432 in ports:
        return "POSTGRESQL"
    if ports & {6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969}:
        return "BITTORRENT"
    if ports & {80, 8080, 8081, 8888, 3000, 5000}:
        return "HTTP"
    if payload_bytes:
        http_methods = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ", b"CONNECT ", b"TRACE "]
        if any(payload_bytes.startswith(m) for m in http_methods) or b"HTTP/1." in payload_bytes:
            return "HTTP"


    # NBNS (NetBIOS Name Service)
    if 137 in ports:
        return "NBNS"

    # LLMNR / mDNS fallback
    if 5353 in ports:
        return "mDNS"
    if 5355 in ports:
        return "LLMNR"

    # SIP / SDP
    if 5060 in ports:
        if payload_bytes and (b"\r\nv=0\r\n" in payload_bytes or b"\r\no=" in payload_bytes):
            return "SDP"
        return "SIP"
    if 5061 in ports:
        return "SIP"
    if payload_bytes:
        if payload_bytes.startswith(b"SIP/2.0") or b"\r\nVIA " in payload_bytes.upper() or b"\r\nFROM " in payload_bytes.upper() or b"INVITE sip:" in payload_bytes or b"REGISTER sip:" in payload_bytes:
            if b"\r\nv=0\r\n" in payload_bytes or b"\r\no=" in payload_bytes:
                return "SDP"
            return "SIP"

    # STUN / TURN / ICE
    if payload_bytes and len(payload_bytes) >= 20 and payload_bytes[4:8] == b"\x21\x12\xa4\x42" and not (payload_bytes[0] & 0xC0):
        message_type = int.from_bytes(payload_bytes[:2], "big")
        if message_type in {0x0001, 0x0101, 0x0111}:
            return "ICE"
        if message_type in {0x0003, 0x0103, 0x0113, 0x0004, 0x0104, 0x0006, 0x0007}:
            return "TURN"
        return "STUN"
    if 3478 in ports or 3479 in ports or 5349 in ports:
        return "STUN"

    # ZRTP
    if payload_bytes and payload_bytes.startswith(b"ZRTP"):
        return "ZRTP"

    # RTCP / SRTCP
    if base_protocol == "UDP" and payload_bytes and len(payload_bytes) >= 8:
        version = (payload_bytes[0] & 0xC0) >> 6
        packet_type = payload_bytes[1]
        if version == 2 and 200 <= packet_type <= 204:
            return "RTCP"

    # RTP / SRTP
    if base_protocol == "UDP" and payload_bytes and len(payload_bytes) >= 12:
        version = (payload_bytes[0] & 0xC0) >> 6
        payload_type = payload_bytes[1] & 0x7F
        if version == 2 and (0 <= payload_type <= 34 or 96 <= payload_type <= 127):
            return "SRTP" if (5061 in ports or 443 in ports) else "RTP"

    # TLS / DTLS
    if payload_bytes and len(payload_bytes) > 5:
        first, major, minor = payload_bytes[0], payload_bytes[1], payload_bytes[2]
        if first in {20, 21, 22, 23, 24} and major == 0x03 and minor in {0x00, 0x01, 0x02, 0x03, 0x04}:
            if base_protocol == "UDP":
                return "DTLS"
            return "TLS"

    # QUIC
    if base_protocol == "UDP" and 443 in ports:
        return "QUIC"

    # H.323 / H.225 / H.245 / RAS / ISUP / M3UA / SIGTRAN / TPKT
    if 1720 in ports:
        return "H225"
    if 1719 in ports:
        return "RAS"
    if 2944 in ports or 2945 in ports:
        return "MEGACO"
    if 2427 in ports or 2727 in ports:
        return "MGCP"
    if 2000 in ports:
        return "SCCP"
    if 4569 in ports:
        return "IAX2"
    if 5069 in ports:
        return "MIKEY"
    if 606 in ports:
        return "T38"
    if 2855 in ports:
        return "MSRP"
    if 5070 in ports:
        return "BFCP"
    if 102 in ports:
        return "TPKT"
    if 2905 in ports:
        return "M3UA"

    return base_protocol

