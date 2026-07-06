from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from statistics import mean, pstdev

from dateutil import parser as date_parser

from app.enrichment.ports import PORT_MAP, VOIP_PORT_RANGES, port_intelligence
from app.enrichment.telecom import enrich_telecom
from app.parsers.base import ConnectionRecord
from app.threat_intel.manager import ThreatIntelManager
from app.protocols.models import VoipSession, QosMetrics
from app.analysis.attribution import build_call_attribution
from app.protocols.rtp import compute_qos_metrics
from app.analysis.graph_hooks import voip_session_to_graph



COMMON_SERVER_PORTS = {
    20,
    21,
    22,
    25,
    53,
    80,
    110,
    123,
    143,
    443,
    465,
    587,
    993,
    995,
    1194,
    1433,
    1723,
    1883,
    2049,
    2375,
    2376,
    3128,
    3306,
    3389,
    3478,
    3479,
    3480,
    3481,
    5060,
    5061,
    5432,
    554,
    636,
    8080,
    8081,
    8443,
    8888,
    9000,
    9200,
    10000,
    1194,
    19302,
    19305,
    5004,
    5005,
    5349,
    5222,
    5223,
}

WEB_PORTS = {80, 81, 3000, 5000, 8000, 8080, 8081, 8443, 8888}
MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
DNS_PORTS = {53, 853}
PROXY_PORTS = {3128, 8080, 8081, 8888}
VPN_PORTS = {500, 1194, 1701, 4500, 51820}
VOIP_SIGNAL_PORTS = {5060, 5061, 19302, 3478, 3479, 3480, 3481, 5349}
MEDIA_PORTS = {5004, 5005}


@dataclass
class RoleDecision:
    role: str
    confidence: int
    reasons: list[str]
    evidence_packets: list[dict]
    secondary_roles: list[str]


def build_network_intelligence(records: list[ConnectionRecord], rows: list[dict]) -> dict:
    raw_records = [record.to_dict() if hasattr(record, "to_dict") else dict(record) for record in records]
    threat_manager = ThreatIntelManager()
    rows_by_ip = {row.get("destination_ip"): row for row in rows if row.get("destination_ip")}

    host_stats = _collect_host_stats(raw_records)
    sessions = _build_sessions(raw_records)
    host_decisions = _classify_hosts(host_stats, sessions, rows_by_ip, threat_manager)
    hosts = list(host_decisions.values())
    hosts.sort(key=lambda item: (-item.get("role_confidence", 0), item.get("ip", "")))

    host_lookup = {host["ip"]: host for host in hosts}
    for row in rows:
        host = host_lookup.get(row.get("destination_ip"))
        if not host:
            continue
        row.update(
            {
                "role": host["role"],
                "role_confidence": host["role_confidence"],
                "role_reasoning": host["role_reasons"],
                "role_secondary": host["secondary_roles"],
                "mac_address": host.get("mac_address") or row.get("mac_address") or "",
                "host_sessions": host.get("session_ids", []),
                "host_peers": host.get("peer_ips", []),
                "evidence_packets": host.get("evidence_packets", []),
            }
        )

    communication_matrix = _communication_matrix(sessions)
    timeline = _build_timeline(raw_records, sessions)
    protocol_summary = _protocol_summary(raw_records)
    flow_diagram = _flow_diagram(hosts, communication_matrix)
    voip_analysis = _voip_analysis(sessions, rows_by_ip)
    host_overview = _host_overview(hosts)
    session_summary = _session_summary(sessions)
    anomalies = _detect_anomalies(raw_records, hosts, sessions)

    return {
        "hosts": hosts,
        "host_lookup": host_lookup,
        "host_overview": host_overview,
        "sessions": sessions,
        "session_summary": session_summary,
        "communication_matrix": communication_matrix,
        "timeline": timeline,
        "protocol_summary": protocol_summary,
        "flow_diagram": flow_diagram,
        "voip_analysis": voip_analysis,
        "anomalies": anomalies,
        "role_counts": Counter(host["role"] for host in hosts),
        "host_roles": Counter(role for host in hosts for role in [host["role"], *host.get("secondary_roles", [])] if role),
    }


def _detect_anomalies(records: list[dict], hosts: list[dict], sessions: list[dict]) -> list[dict]:
    anomalies = []

    # 1. Port scanning
    src_dst_ports = defaultdict(set)
    for r in records:
        src = r.get("source_ip")
        dport = r.get("destination_port")
        if src and dport:
            try:
                src_dst_ports[src].add(int(dport))
            except (ValueError, TypeError):
                pass
    for src, ports in src_dst_ports.items():
        if len(ports) >= 10:
            anomalies.append({
                "title": "Potential Port Scanning Detected",
                "description": f"Host {src} scanned {len(ports)} unique destination ports in this traffic batch.",
                "severity": "medium",
                "ip": src
            })

    # 2. Potential Data Exfiltration
    for session in sessions:
        client = session.get("client_ip")
        server = session.get("server_ip")
        sent = session.get("bytes_sent") or 0
        rcvd = session.get("bytes_received") or 0
        total = session.get("bytes_transferred") or 0
        if total >= 5_000_000 and sent >= rcvd * 10:
            is_pub = True
            try:
                is_pub = not ip_address(server).is_private
            except ValueError:
                pass
            if is_pub:
                anomalies.append({
                    "title": "High-Volume Data Exfiltration",
                    "description": f"Abnormally high upload ratio to public server {server} ({sent / 1000000:.2f} MB uploaded).",
                    "severity": "high",
                    "ip": server
                })

    # 3. Plaintext Credentials Leak
    for r in records:
        preview = str(r.get("payload_preview") or "").lower()
        hex_preview = str(r.get("payload_hex") or "").lower()
        text_to_check = preview + " " + hex_preview
        triggers = ["password=", "passwd=", "basic ", "bearer ", "token=", "api_key"]
        matched = [t for t in triggers if t in text_to_check]
        if matched:
            src = r.get("source_ip")
            dst = r.get("destination_ip")
            anomalies.append({
                "title": "Cleartext Credentials Exposed",
                "description": f"Unencrypted authentication pattern ({', '.join(matched)}) detected in connection from {src} to {dst}.",
                "severity": "high",
                "ip": dst
            })
            break

    # 4. DNS Tunneling Heuristics
    long_queries = []
    dns_queries_by_src = defaultdict(int)
    for r in records:
        query = str(r.get("dns_query") or "")
        src = r.get("source_ip")
        if query and src:
            dns_queries_by_src[src] += 1
            for part in query.split(","):
                part = part.strip()
                if len(part) > 60:
                    long_queries.append((src, part))

    for src, part in long_queries[:3]:
        anomalies.append({
            "title": "Suspicious DNS Tunneling Attempt",
            "description": f"Host {src} sent abnormally long DNS query ({part[:40]}...), indicating possible payload tunneling.",
            "severity": "medium",
            "ip": src
        })

    for src, count in dns_queries_by_src.items():
        if count > 50:
            anomalies.append({
                "title": "High-Frequency DNS Requests",
                "description": f"Host {src} generated {count} DNS queries in a short timeframe, potential C2 signaling.",
                "severity": "medium",
                "ip": src
            })

    # 5. Threat Indicator Alerts
    for h in hosts:
        if h.get("malicious") or h.get("reputation_score", 0) >= 80:
            anomalies.append({
                "title": "High Threat Reputation Indicator",
                "description": f"Destination {h['ip']} ({h.get('asn_org', '')}) flagged on active threat feeds (Score: {h.get('reputation_score')}/100).",
                "severity": "high",
                "ip": h["ip"]
            })

    # Deduplicate anomalies
    unique_anomalies = []
    seen = set()
    for item in anomalies:
        key = (item["title"], item["description"])
        if key not in seen:
            seen.add(key)
            unique_anomalies.append(item)

    return unique_anomalies



def _collect_host_stats(records: list[dict]) -> dict[str, dict]:
    stats: dict[str, dict] = defaultdict(
        lambda: {
            "ip": "",
            "source_records": 0,
            "destination_records": 0,
            "source_bytes": 0,
            "destination_bytes": 0,
            "source_packets": 0,
            "destination_packets": 0,
            "source_ports": Counter(),
            "destination_ports": Counter(),
            "protocols": Counter(),
            "peer_ips": Counter(),
            "timestamps": [],
            "source_macs": Counter(),
            "destination_macs": Counter(),
            "tcp_flags": Counter(),
            "packet_evidence": [],
            "session_ids": set(),
        }
    )

    for index, record in enumerate(records, start=1):
        src = record.get("source_ip")
        dst = record.get("destination_ip")
        if src:
            entry = stats[src]
            entry["ip"] = src
            entry["source_records"] += 1
            entry["source_bytes"] += int(record.get("bytes_transferred") or 0)
            entry["source_packets"] += int(record.get("packet_count") or 0)
            _count_if_present(entry["source_ports"], record.get("source_port"))
            _count_if_present(entry["protocols"], record.get("protocol"))
            _count_if_present(entry["peer_ips"], dst)
            _count_if_present(entry["source_macs"], record.get("source_mac"))
            _count_if_present(entry["tcp_flags"], record.get("tcp_flags"))
            timestamp = _parse_time(record.get("timestamp"))
            if timestamp:
                entry["timestamps"].append(timestamp)
            entry["packet_evidence"].extend(_packet_evidence(record, index))
        if dst:
            entry = stats[dst]
            entry["ip"] = dst
            entry["destination_records"] += 1
            entry["destination_bytes"] += int(record.get("bytes_transferred") or 0)
            entry["destination_packets"] += int(record.get("packet_count") or 0)
            _count_if_present(entry["destination_ports"], record.get("destination_port"))
            _count_if_present(entry["protocols"], record.get("protocol"))
            _count_if_present(entry["peer_ips"], src)
            _count_if_present(entry["destination_macs"], record.get("destination_mac"))
            timestamp = _parse_time(record.get("timestamp"))
            if timestamp:
                entry["timestamps"].append(timestamp)
            entry["packet_evidence"].extend(_packet_evidence(record, index))

    return stats


def _build_sessions(records: list[dict]) -> list[dict]:
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for record in records:
        key = _session_key(record)
        grouped[key].append(record)

    sessions = []
    for key, items in grouped.items():
        items.sort(key=lambda item: _sort_key(item.get("timestamp")))
        ips, ports, protocol = key
        start = _parse_time(items[0].get("timestamp"))
        end = _parse_time(items[-1].get("timestamp")) or start
        ports_observed = sorted({port for port in ports if port is not None})
        service_port = _service_port(ports_observed)
        service_name = _service_name(service_port, protocol)
        client_ip, server_ip, confidence, reasons = _infer_client_server(items, ips, ports_observed, protocol)
        bytes_sent = sum(int(item.get("bytes_transferred") or 0) for item in items if item.get("source_ip") == client_ip)
        bytes_received = sum(int(item.get("bytes_transferred") or 0) for item in items if item.get("source_ip") == server_ip)
        packets_sent = sum(int(item.get("packet_count") or 0) for item in items if item.get("source_ip") == client_ip)
        packets_received = sum(int(item.get("packet_count") or 0) for item in items if item.get("source_ip") == server_ip)
        path = f"{client_ip}:{_preferred_port(items, client_ip)} -> {server_ip}:{_preferred_port(items, server_ip)}"
        packets = [packet for item in items for packet in (item.get("packet_details") or [])]
        sessions.append(
            {
                "session_id": "|".join([ips[0], ips[1], protocol, ",".join(str(port) for port in ports_observed)]),
                "participants": list(ips),
                "client_ip": client_ip,
                "server_ip": server_ip,
                "source_ip": client_ip,
                "destination_ip": server_ip,
                "source_port": _preferred_port(items, client_ip),
                "destination_port": _preferred_port(items, server_ip),
                "ports": ports_observed,
                "protocol": protocol,
                "service": service_name,
                "start_time": start.isoformat() if start else "",
                "end_time": end.isoformat() if end else "",
                "duration_seconds": _duration_seconds(start, end),
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "bytes_transferred": bytes_sent + bytes_received,
                "packets_sent": packets_sent,
                "packets_received": packets_received,
                "packet_count": packets_sent + packets_received,
                "direction": path,
                "confidence": confidence,
                "reasoning": reasons,
                "packet_details": packets[:20],
                "bidirectional": len({item.get("source_ip") for item in items if item.get("source_ip")}) > 1,
                "evidence_packets": _session_evidence(items),
            }
        )

    sessions.sort(key=lambda item: (item.get("start_time") or "", item.get("session_id") or ""))
    return sessions


def _classify_hosts(
    host_stats: dict[str, dict],
    sessions: list[dict],
    rows_by_ip: dict[str, dict],
    threat_manager: ThreatIntelManager,
) -> dict[str, dict]:
    session_by_host: dict[str, list[dict]] = defaultdict(list)
    for session in sessions:
        for participant in session.get("participants", []):
            session_by_host[participant].append(session)

    decision_map: dict[str, RoleDecision] = {}
    enriched_cache: dict[str, dict] = {}
    threat_cache: dict[str, dict] = {}

    for ip, stats in host_stats.items():
        telemetry = rows_by_ip.get(ip) or enriched_cache.setdefault(ip, enrich_telecom(ip))
        threat = threat_cache.setdefault(ip, threat_manager.lookup(ip))
        role_decision = _decide_role(ip, stats, session_by_host.get(ip, []), telemetry)
        session_ids = [session["session_id"] for session in session_by_host.get(ip, [])]
        packet_evidence = _dedupe_packets(stats.get("packet_evidence", []))
        peer_ips = [peer for peer, _ in stats["peer_ips"].most_common(10) if peer]
        mac_address = _choose_mac(stats)
        decision_map[ip] = RoleDecision(
            role=role_decision.role,
            confidence=role_decision.confidence,
            reasons=role_decision.reasons,
            evidence_packets=packet_evidence,
            secondary_roles=role_decision.secondary_roles,
        )
        stats["session_ids"] = set(session_ids)
        stats["peer_ips"] = peer_ips
        stats["telemetry"] = telemetry
        stats["threat"] = threat
        stats["role"] = role_decision.role
        stats["role_confidence"] = role_decision.confidence
        stats["role_reasons"] = role_decision.reasons
        stats["role_secondary"] = role_decision.secondary_roles
        stats["mac_address"] = mac_address

    host_rows = []
    for ip, stats in host_stats.items():
        telemetry = stats.get("telemetry") or enrich_telecom(ip)
        threat = stats.get("threat") or threat_manager.lookup(ip)
        packet_evidence = stats.get("packet_evidence", [])
        host_rows.append(
            {
                "ip": ip,
                "hostname": telemetry.get("hostname") or "",
                "mac_address": stats.get("mac_address") or telemetry.get("mac_address") or "",
                "asn": telemetry.get("asn", "AS0"),
                "asn_number": telemetry.get("asn_number", 0),
                "asn_org": telemetry.get("asn_org", "Unknown Organization"),
                "isp": telemetry.get("isp", "Unknown Provider"),
                "network_prefix": telemetry.get("network_prefix", "Unknown"),
                "country": telemetry.get("country", "Unknown"),
                "region": telemetry.get("region", "Unknown"),
                "city": telemetry.get("city", "Unknown"),
                "latitude": telemetry.get("latitude"),
                "longitude": telemetry.get("longitude"),
                "ip_source": telemetry.get("ip_source", "Local GeoIP"),
                "role": stats.get("role", "client device"),
                "role_confidence": stats.get("role_confidence", 0),
                "role_reasons": stats.get("role_reasons", []),
                "secondary_roles": stats.get("role_secondary", []),
                "packet_evidence": packet_evidence,
                "evidence_packets": packet_evidence,
                "peer_ips": stats.get("peer_ips", []),
                "session_ids": sorted(stats.get("session_ids", [])),
                "source_records": stats.get("source_records", 0),
                "destination_records": stats.get("destination_records", 0),
                "source_packets": stats.get("source_packets", 0),
                "destination_packets": stats.get("destination_packets", 0),
                "source_bytes": stats.get("source_bytes", 0),
                "destination_bytes": stats.get("destination_bytes", 0),
                "source_ports": [port for port, _ in stats["source_ports"].most_common(8) if port is not None],
                "destination_ports": [port for port, _ in stats["destination_ports"].most_common(8) if port is not None],
                "protocols": [protocol for protocol, _ in stats["protocols"].most_common(8) if protocol],
                "total_packets": stats.get("source_packets", 0) + stats.get("destination_packets", 0),
                "total_bytes": stats.get("source_bytes", 0) + stats.get("destination_bytes", 0),
                **threat,
            }
        )

    return {host["ip"]: host for host in host_rows}


def _decide_role(ip: str, stats: dict, sessions: list[dict], telemetry: dict) -> RoleDecision:
    address = ip_address(ip)
    secondary_roles: list[str] = []
    reasons: list[str] = []
    scores: dict[str, int] = defaultdict(int)

    if address.is_multicast or address.is_unspecified or ip == "255.255.255.255":
        return RoleDecision("broadcast device", 98, ["Address is multicast, unspecified, or broadcast"], _packets_from_sessions(sessions), [])

    if address.is_loopback:
        return RoleDecision("local host", 98, ["Loopback address observed"], _packets_from_sessions(sessions), [])

    source_records = stats.get("source_records", 0)
    destination_records = stats.get("destination_records", 0)
    peer_count = len([peer for peer in stats.get("peer_ips", []) if peer])
    total_records = source_records + destination_records
    total_packets = stats.get("source_packets", 0) + stats.get("destination_packets", 0)
    is_private = address.is_private or _is_reserved_local(ip)
    inbound_ratio = destination_records / total_records if total_records else 0.0
    outbound_ratio = source_records / total_records if total_records else 0.0

    if is_private:
        scores["local host"] += 10
        scores["client device"] += 15
        reasons.append("Private address space indicates an internal endpoint")

    if source_records >= destination_records * 1.5:
        scores["client device"] += 30
        reasons.append("Host initiates more sessions than it receives")
    if destination_records >= source_records * 1.5:
        scores["server"] += 25
        reasons.append("Host receives more sessions than it initiates")
    if peer_count >= 5:
        scores["gateway"] += 18
        reasons.append("Host communicates with many peers across different sessions")

    well_known_server_hits = _well_known_server_hits(stats)
    if well_known_server_hits:
        scores["server"] += 20 + min(20, well_known_server_hits * 4)
        reasons.append("Repeated traffic targets well-known service ports")

    if _has_protocol_hits(stats, {"DNS"}):
        scores["dns server"] += 35
        reasons.append("DNS protocol observed")

    if _has_port_hits(stats, WEB_PORTS):
        scores["web server"] += 30
        reasons.append("HTTP/HTTPS ports observed")

    if _has_port_hits(stats, MAIL_PORTS):
        scores["mail server"] += 25
        reasons.append("Mail service ports observed")

    if _has_port_hits(stats, VOIP_SIGNAL_PORTS | MEDIA_PORTS):
        scores["voip server"] += 30
        reasons.append("VoIP signaling or media ports observed")

    if _has_port_hits(stats, PROXY_PORTS):
        scores["proxy server"] += 25
        reasons.append("Proxy-style port behavior observed")

    if _has_port_hits(stats, VPN_PORTS):
        scores["vpn server"] += 30
        reasons.append("VPN service ports observed")

    if _has_port_hits(stats, {19302, 3478}) and _has_protocol_hits(stats, {"UDP"}):
        scores["stun server"] += 28
        reasons.append("STUN-related UDP behavior observed")

    if any(session.get("service") == "TURN" or "TURN" in str(session.get("service", "")).upper() for session in sessions):
        scores["relay/TURN server"] += 35
        reasons.append("TURN traffic observed in one or more sessions")

    if _is_balanced(stats) and peer_count >= 2 and not scores:
        scores["peer"] += 35
        reasons.append("Traffic is balanced and no strong client/server bias is present")

    if is_private and peer_count >= 3 and source_records >= 2 and destination_records >= 2 and not scores.get("server"):
        scores["gateway"] += 10
        reasons.append("Private host shows routing-like fan-out across multiple peers")

    if is_private and source_records > destination_records and peer_count >= 3:
        scores["client device"] += 10

    if not scores:
        scores["destination host"] += 20
        reasons.append("No stronger behavioral signature was available")

    if _has_broadcast_activity(stats):
        scores["broadcast device"] += 40
        reasons.append("Broadcast or multicast traffic observed")

    if not scores:
        scores["client device"] = 25

    top_role, top_score = max(scores.items(), key=lambda item: (item[1], item[0]))
    secondary_roles = [role for role, score in sorted(scores.items(), key=lambda item: item[1], reverse=True)[1:4] if score >= max(10, top_score - 20)]
    evidence_packets = _packets_from_sessions(sessions)
    confidence = min(99, max(35, top_score))
    if top_role == "relay/TURN server" and any("TURN" in reason for reason in reasons):
        confidence = min(99, confidence + 10)
    if top_role in {"client device", "server", "web server", "dns server", "mail server", "voip server", "proxy server", "vpn server", "relay/TURN server", "stun server"}:
        confidence = min(99, confidence + 5)
    if is_private and top_role in {"client device", "local host"}:
        confidence = min(99, confidence + 8)
    return RoleDecision(top_role, confidence, reasons, evidence_packets, secondary_roles)


def _communication_matrix(sessions: list[dict]) -> list[dict]:
    matrix = defaultdict(lambda: {"packet_count": 0, "bytes_transferred": 0, "session_count": 0, "protocols": Counter()})
    for session in sessions:
        key = (session["client_ip"], session["server_ip"])
        entry = matrix[key]
        entry["packet_count"] += int(session.get("packet_count") or 0)
        entry["bytes_transferred"] += int(session.get("bytes_transferred") or 0)
        entry["session_count"] += 1
        entry["protocols"][session.get("protocol") or "UNKNOWN"] += 1

    result = []
    for (client_ip, server_ip), entry in matrix.items():
        result.append(
            {
                "source_ip": client_ip,
                "destination_ip": server_ip,
                "protocols": [protocol for protocol, _ in entry["protocols"].most_common()],
                "protocol": entry["protocols"].most_common(1)[0][0] if entry["protocols"] else "UNKNOWN",
                "packet_count": entry["packet_count"],
                "bytes_transferred": entry["bytes_transferred"],
                "session_count": entry["session_count"],
            }
        )
    result.sort(key=lambda item: (-item["bytes_transferred"], -item["session_count"], item["source_ip"], item["destination_ip"]))
    return result


def _build_timeline(records: list[dict], sessions: list[dict]) -> list[dict]:
    events = []
    for record in records:
        timestamp = record.get("timestamp")
        if timestamp:
            events.append(
                {
                    "timestamp": timestamp,
                    "event": f"{record.get('protocol', 'UNKNOWN')} flow",
                    "source_ip": record.get("source_ip", ""),
                    "destination_ip": record.get("destination_ip", ""),
                    "protocol": record.get("protocol", "UNKNOWN"),
                    "details": f"{record.get('packet_count', 0)} packets, {record.get('bytes_transferred', 0)} bytes",
                }
            )

    for session in sessions:
        if session.get("start_time"):
            events.append(
                {
                    "timestamp": session["start_time"],
                    "event": f"{session.get('service', 'Session')} started",
                    "source_ip": session.get("client_ip", ""),
                    "destination_ip": session.get("server_ip", ""),
                    "protocol": session.get("protocol", "UNKNOWN"),
                    "details": session.get("direction", ""),
                }
            )
        if session.get("end_time"):
            events.append(
                {
                    "timestamp": session["end_time"],
                    "event": f"{session.get('service', 'Session')} ended",
                    "source_ip": session.get("client_ip", ""),
                    "destination_ip": session.get("server_ip", ""),
                    "protocol": session.get("protocol", "UNKNOWN"),
                    "details": f"{session.get('duration_seconds', 0)} seconds",
                }
            )

    events.sort(key=lambda item: item.get("timestamp") or "")
    return events[:400]


def _protocol_summary(records: list[dict]) -> list[dict]:
    counts = Counter()
    for record in records:
        counts[str(record.get("protocol") or "UNKNOWN").upper()] += 1
    return [
        {"protocol": protocol, "count": count}
        for protocol, count in counts.most_common(12)
    ]


def _flow_diagram(hosts: list[dict], communication_matrix: list[dict]) -> dict:
    nodes = []
    node_seen = set()
    for host in hosts[:20]:
        node = {
            "id": host["ip"],
            "label": host["ip"],
            "role": host.get("role", ""),
            "confidence": host.get("role_confidence", 0),
            "asn": host.get("asn", ""),
            "country": host.get("country", ""),
        }
        if node["id"] not in node_seen:
            nodes.append(node)
            node_seen.add(node["id"])

    edges = []
    for edge in communication_matrix[:25]:
        edges.append(
            {
                "source": edge["source_ip"],
                "target": edge["destination_ip"],
                "label": f"{edge['session_count']} sessions | {edge['bytes_transferred']} bytes",
                "protocol": edge.get("protocol", "UNKNOWN"),
                "weight": min(100, max(10, int(edge["bytes_transferred"] / 5000) + edge["session_count"] * 8)),
            }
        )

    return {"nodes": nodes, "edges": edges}


def _parse_sip_text(text: str) -> dict | None:
    if not text:
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
    }


def _extract_ip_from_via(via: str) -> str | None:
    parts = via.split(" ")
    if len(parts) < 2:
        return None
    host_port = parts[1].split(";")[0]
    host = host_port.split(":")[0]
    return host


def _is_relay_server(ip: str, telemetry: dict) -> bool:
    if not ip:
        return False
    if telemetry:
        org = str(telemetry.get("asn_org") or telemetry.get("isp") or "").upper()
        server_keywords = [
            "FACEBOOK", "GOOGLE", "MICROSOFT", "AMAZON", "CLOUDFLARE",
            "TELEGRAM", "WHATSAPP", "ZOOM", "SKYPE", "TENCENT", "ALIBABA",
            "HOSTING", "DATA CENTER", "DATACENTER", "CLOUD", "RELAY", "SERVER",
            "NETFLIX", "AKAMAI", "FASTLY", "EDGE", "INFRASTRUCTURE"
        ]
        if any(kw in org for kw in server_keywords):
            return True
    return False


def _voip_analysis(sessions: list[dict], rows_by_ip: dict[str, dict]) -> list[dict]:
    import ipaddress
    sip_packets = []
    stun_packets = []
    rtp_packets = []

    # 1. Collect all packets from the sessions
    for session in sessions:
        for packet in session.get("packet_details", []):
            proto = str(packet.get("protocol")).upper()
            decoded_type = str(packet.get("decoded_type") or "").upper()
            fields = packet.get("decoded_fields") or {}

            # Route to appropriate bucket
            if proto == "SIP" or "SIP" in decoded_type or fields.get("call_id"):
                sip_packets.append(packet)
            elif proto == "STUN" or "STUN" in decoded_type or fields.get("message_name"):
                stun_packets.append(packet)
            elif proto in ("RTP", "SRTP") or "RTP" in decoded_type:
                rtp_packets.append(packet)

    # Group SIP by call_id
    sip_by_call_id = defaultdict(list)
    for pkt in sip_packets:
        fields = pkt.get("decoded_fields") or {}
        call_id = fields.get("call_id")
        if call_id:
            sip_by_call_id[call_id].append(pkt)

    # Group STUN by sorted ufrag_key
    stun_by_ufrag = defaultdict(list)
    for pkt in stun_packets:
        fields = pkt.get("decoded_fields") or {}
        remote = fields.get("remote_ufrag")
        local = fields.get("local_ufrag")
        if remote and local:
            ufrag_key = ":".join(sorted([remote, local]))
            stun_by_ufrag[ufrag_key].append(pkt)

    # List of consolidated VoIP groups
    groups = []

    # First, create groups for each STUN ufrag_key
    for ufrag_key, pkts in stun_by_ufrag.items():
        groups.append({
            "call_id": None,
            "ufrag_key": ufrag_key,
            "sip_packets": [],
            "stun_packets": pkts,
            "rtp_packets": []
        })

    # Now, add SIP groups
    for call_id, pkts in sip_by_call_id.items():
        # Let's see if we can link this call_id to any existing ufrag_key group
        sdp_ips = set()
        sdp_ports = set()
        for p in pkts:
            fields = p.get("decoded_fields") or {}
            if fields.get("sdp_media_ip"):
                sdp_ips.add(fields["sdp_media_ip"])
            if fields.get("sdp_media_port"):
                sdp_ports.add(fields["sdp_media_port"])
            for c in fields.get("sdp_candidates") or []:
                if c.get("ip"):
                    sdp_ips.add(c["ip"])
                if c.get("port"):
                    sdp_ports.add(c["port"])

        # Try to match with STUN packets IPs and ports
        matched_group = None
        for g in groups:
            stun_ips = {p.get("source_ip") for p in g["stun_packets"]} | {p.get("destination_ip") for p in g["stun_packets"]}
            stun_ports = {p.get("source_port") for p in g["stun_packets"]} | {p.get("destination_port") for p in g["stun_packets"]}
            if (sdp_ips & stun_ips) or (sdp_ports & stun_ports):
                matched_group = g
                break

        if matched_group:
            matched_group["call_id"] = call_id
            matched_group["sip_packets"].extend(pkts)
        else:
            groups.append({
                "call_id": call_id,
                "ufrag_key": None,
                "sip_packets": pkts,
                "stun_packets": [],
                "rtp_packets": []
            })

    # Assign RTP packets to groups
    for rtp in rtp_packets:
        matched_group = None
        rtp_ips = {rtp.get("source_ip"), rtp.get("destination_ip")}
        rtp_ports = {rtp.get("source_port"), rtp.get("destination_port")}

        for g in groups:
            sdp_ips = set()
            sdp_ports = set()
            for p in g["sip_packets"]:
                fields = p.get("decoded_fields") or {}
                if fields.get("sdp_media_ip"):
                    sdp_ips.add(fields["sdp_media_ip"])
                if fields.get("sdp_media_port"):
                    sdp_ports.add(fields["sdp_media_port"])

            stun_ips = {p.get("source_ip") for p in g["stun_packets"]} | {p.get("destination_ip") for p in g["stun_packets"]}
            stun_ports = {p.get("source_port") for p in g["stun_packets"]} | {p.get("destination_port") for p in g["stun_packets"]}

            if (rtp_ips & sdp_ips) or (rtp_ports & sdp_ports) or (rtp_ips & stun_ips) or (rtp_ports & stun_ports):
                matched_group = g
                break

        if matched_group:
            matched_group["rtp_packets"].append(rtp)

    calls = []
    for g in groups:
        call_id = g["call_id"]
        ufrag_key = g["ufrag_key"]

        all_pkts = g["sip_packets"] + g["stun_packets"] + g["rtp_packets"]
        if not all_pkts:
            continue
        all_pkts.sort(key=lambda p: _sort_key(p.get("timestamp")))

        session = VoipSession(
            call_id=call_id,
            ufrag_key=ufrag_key,
            start_time=all_pkts[0].get("timestamp"),
            end_time=all_pkts[-1].get("timestamp")
        )

        session = build_call_attribution(session, g["stun_packets"], g["rtp_packets"], g["sip_packets"])

        # Extract RTP metrics if available
        rtp_seqs = []
        rtp_ts = []
        rtp_arrs = []
        rtp_pts = []
        for rtp in g["rtp_packets"]:
            fields = rtp.get("decoded_fields") or {}
            seq = fields.get("sequence_number")
            ts = fields.get("timestamp")
            pt = fields.get("payload_type")
            arr = _parse_time(rtp.get("timestamp"))
            if seq is not None and ts is not None and arr is not None and pt is not None:
                rtp_seqs.append(seq)
                rtp_ts.append(ts)
                rtp_arrs.append(arr.timestamp())
                rtp_pts.append(pt)

        qos = compute_qos_metrics(rtp_seqs, rtp_ts, rtp_arrs, rtp_pts)
        session.qos = QosMetrics(
            jitter_ms=qos["jitter_ms"],
            packet_loss_pct=qos["packet_loss_pct"],
            mos_score=qos["mos_score"],
            mos_label=qos["mos_label"]
        )

        graph_data = voip_session_to_graph(session)

        route = []
        for n in graph_data["nodes"]:
            route.append({
                "ip": n["id"],
                "role": n["role"],
                "name": n["asn"] + " (" + n["country"] + ")" if n["asn"] != "AS0" else n["country"]
            })

        has_turn = len(session.turn_servers) > 0 or session.callee.relay_ip is not None
        call_type = "Server Relayed" if has_turn else "Peer-to-Peer"

        media_ports = set()
        for rtp in g["rtp_packets"]:
            media_ports.add(rtp.get("source_port"))
            media_ports.add(rtp.get("destination_port"))
        media_ports_list = sorted(list(filter(None, media_ports)))

        notes = list(session.warnings)
        if not notes:
            notes.append(f"Call session verified with confidence {session.confidence_score}%")
        for reason in session.confidence_reasons:
            if "Initial session score" not in reason:
                notes.append(reason)

        calls.append({
            "call_type": call_type,
            "caller": session.caller.public_ip or session.caller.private_ip or session.caller.ufrag or "Unknown",
            "remote_peer": session.callee.public_ip or session.callee.private_ip or session.callee.ufrag or "Unknown",
            "media_ports": _media_port_label(media_ports_list),
            "turn_server": session.turn_servers[0] if session.turn_servers else "",
            "stun_usage": any(c.candidate_type == "srflx" for c in session.candidates),
            "turn_usage": has_turn,
            "call_duration_seconds": _duration_seconds(_parse_time(session.start_time), _parse_time(session.end_time)),
            "packet_loss_estimate": session.qos.packet_loss_pct,
            "jitter_ms": session.qos.jitter_ms,
            "mos_estimate": session.qos.mos_score,
            "confidence": int(session.confidence_score),
            "notes": notes,
            "route": route,
            "graph": graph_data,
            "call_id": session.call_id or session.ufrag_key or "N/A",
            "user_agent": next((msg.get("user_agent") for msg in g["sip_packets"] if msg.get("user_agent")), "WebRTC Client"),
            "evidence": all_pkts[:8],
        })

    # 2. Fallback: process remaining sessions that were not part of any reconstructed SIP/STUN call
    claimed_sessions = set()
    for g in groups:
        group_packet_keys = set()
        for p in g["sip_packets"] + g["stun_packets"] + g["rtp_packets"]:
            key = (p.get("timestamp"), p.get("source_ip"), p.get("destination_ip"), p.get("source_port"), p.get("destination_port"))
            group_packet_keys.add(key)

        for session in sessions:
            session_id = session.get("session_id")
            if session_id in claimed_sessions:
                continue
            for p in session.get("packet_details", []):
                key = (p.get("timestamp"), p.get("source_ip"), p.get("destination_ip"), p.get("source_port"), p.get("destination_port"))
                if key in group_packet_keys:
                    claimed_sessions.add(session_id)
                    break

    for session in sessions:
        if session.get("session_id") in claimed_sessions:
            continue

        signature_text = " ".join(
            [
                str(session.get("service", "")),
                str(session.get("protocol", "")),
                " ".join(str(port) for port in session.get("ports", [])),
                str(session.get("direction", "")),
            ]
        ).upper()

        ports = session.get("ports", [])
        if not any(token in signature_text for token in ("SIP", "RTP", "RTCP", "STUN", "TURN", "ICE", "WEBRTC")):
            if not any(port in VOIP_PORT_RANGES[0] or port in VOIP_PORT_RANGES[1] for port in ports):
                continue
            if any(p in (53, 80, 443, 137, 138, 139, 445, 1900, 5353) for p in ports):
                continue

        caller_ip = session.get("client_ip", "")
        receiver_ip = session.get("server_ip", "")

        try:
            c_addr = ipaddress.ip_address(caller_ip)
            r_addr = ipaddress.ip_address(receiver_ip)
            if c_addr.is_multicast or c_addr.is_link_local or c_addr.is_loopback or c_addr.is_unspecified:
                continue
            if r_addr.is_multicast or r_addr.is_link_local or r_addr.is_loopback or r_addr.is_unspecified:
                continue
        except Exception:
            pass

        call_type, confidence, notes = _classify_call(session, rows_by_ip)
        jitter_ms = _estimate_jitter(session)
        loss_percent = _estimate_loss(session)
        mos = _estimate_mos(jitter_ms, loss_percent)

        route = []

        def add_fallback_hop(ip, role, name, port=None):
            if not ip:
                return
            route_name = name
            telemetry = rows_by_ip.get(ip)
            if not telemetry:
                try:
                    telemetry = enrich_telecom(ip)
                except Exception:
                    pass
            if telemetry:
                asn_org = telemetry.get("asn_org")
                isp = telemetry.get("isp")
                country = telemetry.get("country")
                asn_val = str(telemetry.get('asn') or "")
                if asn_val.upper().startswith("AS"):
                    org_info = f"{asn_val} {asn_org or isp or ''}".strip()
                elif asn_val:
                    org_info = f"AS{asn_val} {asn_org or isp or ''}".strip()
                else:
                    org_info = (asn_org or isp or "").strip()
                if org_info:
                    route_name = f"{org_info} ({country})"
                else:
                    route_name = country or name
            
            hop_data = {"ip": ip, "role": role, "name": route_name}
            if port:
                hop_data["port"] = port
            route.append(hop_data)

        receiver_telemetry = rows_by_ip.get(receiver_ip)
        if not receiver_telemetry:
            try:
                receiver_telemetry = enrich_telecom(receiver_ip)
                if receiver_telemetry:
                    rows_by_ip[receiver_ip] = receiver_telemetry
            except Exception:
                pass
                
        is_relay = (
            _has_turn_usage(session)
            or _has_stun_usage(session)
            or _is_relay_server(receiver_ip, receiver_telemetry)
            or call_type == "Server Relayed"
        )
        
        caller_port = session.get("source_port")
        relay_port = session.get("destination_port")

        add_fallback_hop(caller_ip, "caller", "Caller Endpoint", port=caller_port)
        
        if is_relay:
            call_type = "Server Relayed"
            role = "relay"
            fallback_role_name = "VoIP Media Relay"
            if _has_turn_usage(session):
                fallback_role_name = "TURN Relay Server"
            elif _has_stun_usage(session):
                fallback_role_name = "STUN SBC"
                role = "stun"
            
            add_fallback_hop(receiver_ip, role, fallback_role_name, port=relay_port)
        else:
            add_fallback_hop(receiver_ip, "receiver", "Receiver Endpoint", port=relay_port)

        graph_data = {
            "nodes": [
                {
                    "id": caller_ip,
                    "label": caller_ip,
                    "role": "caller",
                    "confidence": int(confidence),
                    "asn": "AS0" if not rows_by_ip.get(caller_ip) else f"AS{rows_by_ip.get(caller_ip).get('asn') or ''} {rows_by_ip.get(caller_ip).get('asn_org') or ''}".strip(),
                    "country": "Unknown" if not rows_by_ip.get(caller_ip) else rows_by_ip.get(caller_ip).get("country", "Unknown")
                },
                {
                    "id": receiver_ip,
                    "label": receiver_ip,
                    "role": "relay" if is_relay else "receiver",
                    "confidence": 100,
                    "asn": "AS0" if not rows_by_ip.get(receiver_ip) else f"AS{rows_by_ip.get(receiver_ip).get('asn') or ''} {rows_by_ip.get(receiver_ip).get('asn_org') or ''}".strip(),
                    "country": "Unknown" if not rows_by_ip.get(receiver_ip) else rows_by_ip.get(receiver_ip).get("country", "Unknown")
                }
            ],
            "edges": [
                {
                    "source": caller_ip,
                    "target": receiver_ip,
                    "label": f"Fallback media flow ({session.get('protocol', 'UDP')})",
                    "protocol": session.get("protocol", "UDP"),
                    "weight": 80
                }
            ]
        }

        calls.append(
            {
                "call_type": call_type,
                "caller": caller_ip,
                "remote_peer": receiver_ip,
                "media_ports": _media_port_label(session.get("ports", [])),
                "turn_server": _turn_server(session),
                "stun_usage": _has_stun_usage(session),
                "turn_usage": _has_turn_usage(session),
                "call_duration_seconds": session.get("duration_seconds", 0),
                "packet_loss_estimate": loss_percent,
                "jitter_ms": jitter_ms,
                "mos_estimate": mos,
                "confidence": confidence,
                "notes": notes,
                "evidence": session.get("evidence_packets", [])[:8],
                "route": route,
                "graph": graph_data,
                "call_id": session.get("session_id", "N/A"),
                "user_agent": "VoIP Client",
            }
        )

    return calls


def _host_overview(hosts: list[dict]) -> dict:
    roles = Counter(host.get("role", "unknown") for host in hosts)
    private = sum(1 for host in hosts if _is_private_host(host.get("ip", "")))
    return {
        "total_hosts": len(hosts),
        "private_hosts": private,
        "public_hosts": max(0, len(hosts) - private),
        "roles": dict(roles),
        "top_role": roles.most_common(1)[0][0] if roles else "Unknown",
        "top_host": hosts[0]["ip"] if hosts else "",
    }


def _session_summary(sessions: list[dict]) -> dict:
    protocols = Counter(session.get("protocol", "UNKNOWN") for session in sessions)
    service_counts = Counter(session.get("service", "UNKNOWN") for session in sessions)
    return {
        "total_sessions": len(sessions),
        "bidirectional_sessions": sum(1 for session in sessions if session.get("bidirectional")),
        "protocols": dict(protocols),
        "services": dict(service_counts),
        "top_protocol": protocols.most_common(1)[0][0] if protocols else "UNKNOWN",
    }


def _infer_client_server(items: list[dict], ips: tuple[str, str], ports: list[int], protocol: str) -> tuple[str, str, int, list[str]]:
    left, right = ips
    reasons: list[str] = []
    confidence = 45
    service_port = _service_port(ports)
    if service_port is not None:
        if any(item.get("destination_port") == service_port for item in items):
            server = right if any(item.get("destination_ip") == right and item.get("destination_port") == service_port for item in items) else left
            client = left if server == right else right
            reasons.append(f"Service port {service_port} suggests the server side")
            confidence += 25
            return client, server, min(99, confidence), reasons
        if any(item.get("source_port") == service_port for item in items):
            server = left if any(item.get("source_ip") == left and item.get("source_port") == service_port for item in items) else right
            client = right if server == left else left
            reasons.append(f"Observed service port {service_port} on the source side")
            confidence += 20
            return client, server, min(99, confidence), reasons

    first = min(items, key=lambda item: _sort_key(item.get("timestamp")))
    initiator = first.get("source_ip") or left
    responder = right if initiator == left else left
    reasons.append(f"Earliest observed packet originated from {initiator}")
    if protocol.upper() == "TCP":
        syn = next((item for item in items if str(item.get("tcp_flags", "")).upper() in {"S", "SYN"} or "S" in str(item.get("tcp_flags", "")).upper()), None)
        if syn and syn.get("source_ip"):
            initiator = syn.get("source_ip")
            responder = right if initiator == left else left
            reasons.append("TCP SYN evidence points to the initiating host")
            confidence += 15

    return initiator, responder, min(99, confidence), reasons


def _service_port(ports: list[int]) -> int | None:
    if not ports:
        return None
    candidates = [port for port in ports if port in COMMON_SERVER_PORTS]
    if candidates:
        return min(candidates)
    for port in ports:
        if port in PORT_MAP or any(port in range_set for range_set in VOIP_PORT_RANGES):
            return port
    return ports[0]


def _service_name(service_port: int | None, protocol: str) -> str:
    if service_port is None:
        return "Unknown"
    if service_port in PORT_MAP:
        return PORT_MAP[service_port]
    if protocol.upper() == "UDP" and any(service_port in ports for ports in VOIP_PORT_RANGES):
        return "VoIP Media"
    return "Custom"


def _preferred_port(items: list[dict], ip: str) -> int | None:
    ports = [item.get("destination_port") for item in items if item.get("destination_ip") == ip and item.get("destination_port") is not None]
    if not ports:
        ports = [item.get("source_port") for item in items if item.get("source_ip") == ip and item.get("source_port") is not None]
    if not ports:
        return None
    return Counter(ports).most_common(1)[0][0]


def _session_key(record: dict) -> tuple:
    ips = tuple(sorted([str(record.get("source_ip") or ""), str(record.get("destination_ip") or "")]))
    ports = tuple(sorted([port for port in [record.get("source_port"), record.get("destination_port")] if port is not None]))
    protocol = str(record.get("protocol") or "UNKNOWN").upper()
    return ips, ports, protocol


def _count_if_present(counter: Counter, value):
    if value in (None, "", "Unknown"):
        return
    counter[str(value)] += 1


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = date_parser.parse(str(value), fuzzy=True)
        return parsed if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _sort_key(value: str | None):
    parsed = _parse_time(value)
    return parsed or datetime.min.replace(tzinfo=timezone.utc)


def _duration_seconds(start: datetime | None, end: datetime | None) -> int:
    if not start or not end:
        return 0
    return max(0, int((end - start).total_seconds()))


def _packet_evidence(record: dict, index: int) -> list[dict]:
    packets = []
    for packet in record.get("packet_details") or []:
        packets.append(
            {
                "record_index": index,
                "packet_index": packet.get("packet_index"),
                "timestamp": packet.get("timestamp"),
                "flow_label": packet.get("flow_label"),
                "summary": packet.get("summary"),
                "decoded_type": packet.get("decoded_type"),
                "source_ip": packet.get("source_ip"),
                "destination_ip": packet.get("destination_ip"),
                "source_port": packet.get("source_port"),
                "destination_port": packet.get("destination_port"),
                "protocol": packet.get("protocol"),
            }
        )
    if not packets:
        packets.append(
            {
                "record_index": index,
                "packet_index": 1,
                "timestamp": record.get("timestamp"),
                "flow_label": f"{record.get('source_ip')}:{record.get('source_port') or 'n/a'} -> {record.get('destination_ip')}:{record.get('destination_port') or 'n/a'}",
                "summary": record.get("payload_preview") or record.get("protocol") or "Flow record",
                "decoded_type": record.get("payload_kind") or "",
                "source_ip": record.get("source_ip"),
                "destination_ip": record.get("destination_ip"),
                "source_port": record.get("source_port"),
                "destination_port": record.get("destination_port"),
                "protocol": record.get("protocol"),
            }
        )
    return packets


def _session_evidence(items: list[dict]) -> list[dict]:
    evidence = []
    for item in items:
        evidence.extend(_packet_evidence(item, 0)[:3])
    return _dedupe_packets(evidence)[:8]


def _packets_from_sessions(sessions: list[dict]) -> list[dict]:
    evidence = []
    for session in sessions:
        evidence.extend((session.get("evidence_packets") or [])[:2])
    return _dedupe_packets(evidence)[:8]


def _dedupe_packets(packets: list[dict]) -> list[dict]:
    seen = set()
    deduped = []
    for packet in packets:
        key = (
            packet.get("timestamp"),
            packet.get("flow_label"),
            packet.get("source_ip"),
            packet.get("destination_ip"),
            packet.get("packet_index"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(packet)
    return deduped


def _choose_mac(stats: dict) -> str:
    for counter in (stats.get("source_macs"), stats.get("destination_macs")):
        if counter and counter.most_common(1):
            return counter.most_common(1)[0][0]
    return ""


def _well_known_server_hits(stats: dict) -> int:
    ports = list(stats.get("destination_ports", Counter()).elements())
    total = 0
    for port in ports:
        try:
            if int(port) in COMMON_SERVER_PORTS:
                total += 1
        except (TypeError, ValueError):
            continue
    return total


def _has_protocol_hits(stats: dict, protocols: set[str]) -> bool:
    return any(protocol.upper() in protocols for protocol, _ in stats.get("protocols", Counter()).items())


def _has_port_hits(stats: dict, ports: set[int]) -> bool:
    source_ports = stats.get("source_ports", Counter())
    destination_ports = stats.get("destination_ports", Counter())
    return any(int(port) in ports for port in list(source_ports.elements()) + list(destination_ports.elements()) if port is not None)


def _has_broadcast_activity(stats: dict) -> bool:
    peers = stats.get("peer_ips", Counter())
    if isinstance(peers, Counter):
        for peer in peers:
            if str(peer) in {"255.255.255.255", "224.0.0.251", "224.0.0.252"}:
                return True
    return False


def _is_balanced(stats: dict) -> bool:
    source = stats.get("source_records", 0)
    destination = stats.get("destination_records", 0)
    total = source + destination
    if total == 0:
        return False
    return abs(source - destination) / total <= 0.2


def _classify_call(session: dict, rows_by_ip: dict[str, dict]) -> tuple[str, int, list[str]]:
    ports = set(session.get("ports", []))
    service = str(session.get("service", "")).upper()
    notes = []
    confidence = 70

    if "TURN" in service or any(port in {3478, 3479, 3480, 3481, 5349} for port in ports):
        notes.append("TURN or relay signaling observed")
        return "Server Relayed", 99, notes

    if "STUN" in service or 19302 in ports:
        notes.append("STUN usage observed")
        confidence += 10

    if any(port in MEDIA_PORTS for port in ports):
        notes.append("RTP/RTCP media ports observed")
        confidence += 5

    if session.get("bidirectional") and not any(port in {3478, 3479, 3480, 3481, 5349} for port in ports):
        notes.append("Traffic is directly exchanged between peers")
        return "Peer-to-Peer", min(99, confidence + 10), notes

    if any("SIP" in port_intelligence(port, session.get("protocol", "")).get("name", "").upper() for port in ports):
        notes.append("SIP-style signaling observed")

    return "Server Relayed" if any(port in VOIP_SIGNAL_PORTS for port in ports) else "Peer-to-Peer", min(95, confidence), notes


def _has_stun_usage(session: dict) -> bool:
    service = str(session.get("service", "")).upper()
    ports = set(session.get("ports", []))
    return "STUN" in service or 19302 in ports or any(port in {3478, 3479, 3480, 3481} for port in ports)


def _has_turn_usage(session: dict) -> bool:
    service = str(session.get("service", "")).upper()
    ports = set(session.get("ports", []))
    return "TURN" in service or any(port in {3479, 3480, 3481, 5349} for port in ports)


def _turn_server(session: dict) -> str:
    if _has_turn_usage(session):
        return session.get("server_ip", "")
    return ""


def _media_port_label(ports: list[int]) -> str:
    if not ports:
        return "n/a"
    if len(ports) == 1:
        return str(ports[0])
    return f"{min(ports)} \u2194 {max(ports)}"


def _estimate_jitter(session: dict) -> float | None:
    packets = session.get("packet_details") or []
    times = []
    for packet in packets:
        timestamp = _parse_time(packet.get("timestamp"))
        if timestamp:
            times.append(timestamp.timestamp())
    if len(times) < 4:
        return None
    deltas = [b - a for a, b in zip(times, times[1:]) if b >= a]
    if len(deltas) < 2:
        return None
    return round(pstdev(deltas) * 1000.0, 2)


def _estimate_loss(session: dict) -> float | None:
    packets = session.get("packet_details") or []
    if len(packets) < 4:
        return None
    times = [_parse_time(packet.get("timestamp")) for packet in packets]
    times = [stamp for stamp in times if stamp]
    if len(times) < 4:
        return None
    deltas = [max(0.0, (b - a).total_seconds()) for a, b in zip(times, times[1:])]
    if not deltas:
        return None
    average = mean(deltas) or 0.0
    if average <= 0:
        return None
    outliers = sum(1 for delta in deltas if delta > average * 3)
    return round(min(35.0, (outliers / len(deltas)) * 100.0), 2)


def _estimate_mos(jitter_ms: float | None, loss_percent: float | None) -> float | None:
    if jitter_ms is None and loss_percent is None:
        return None
    jitter = jitter_ms or 0.0
    loss = loss_percent or 0.0
    mos = 4.5 - (jitter / 120.0) - (loss / 25.0)
    return round(max(1.0, min(4.5, mos)), 2)


def _is_private_host(ip: str) -> bool:
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False


def _is_reserved_local(ip: str) -> bool:
    return ip.startswith("169.254.") or ip.startswith("127.")
