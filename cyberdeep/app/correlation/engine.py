from collections import Counter
from datetime import datetime, timezone

from dateutil import parser as date_parser


def correlate_evidence(analysis: dict, telecom_records: list[dict], evidence_files: list[dict]) -> dict:
    events = []
    telecom_by_source = {record.get("assigned_ip") for record in telecom_records if record.get("assigned_ip")}

    for row in analysis.get("rows", []):
        for packet in row.get("raw_connections", []):
            for record in telecom_records:
                event = _score_event(row, packet, record)
                if event["score"] >= 60:
                    events.append(event)

    events.sort(key=lambda item: item.get("time") or "")
    matched_sessions = {event.get("match_session_id") for event in events if event.get("score", 0) >= 60}
    subscribers = sorted({event["subscriber"] for event in events if event.get("subscriber")})
    devices = sorted({event["imei"] for event in events if event.get("imei")})
    services = Counter(event["service"] for event in events if event.get("service"))
    confidence = round(sum(event["score"] for event in events) / len(events), 1) if events else 0
    attribution = build_attribution_report(events, analysis, evidence_files)

    return {
        "events": events,
        "services": build_service_correlation(events),
        "attribution_report": attribution,
        "case_summary": {
            "uploaded_files": [item["filename"] for item in evidence_files],
            "correlated_events": len(events),
            "matched_sessions": len(matched_sessions),
            "confidence": confidence,
            "confidence_label": confidence_label(confidence),
            "likely_services": [service for service, _ in services.most_common(5)],
            "associated_subscribers": subscribers,
            "associated_devices": devices,
            "assigned_ips": sorted(telecom_by_source),
            "countries_contacted": sorted({row["country"] for row in analysis.get("rows", []) if row.get("country") != "Unknown"}),
            "threats": _threat_summary(analysis.get("rows", [])),
            "assessment": attribution["assessment"],
        },
    }


def _score_event(row: dict, packet: dict, record: dict) -> dict:
    if record.get("called_ip") and record.get("called_ip") != packet.get("destination_ip"):
        return _empty_event(row, packet, record)

    score = 0
    factors = []
    breakdown = []
    packet_time = _parse_time(packet.get("timestamp"))
    start_time = _parse_time(record.get("session_start") or record.get("timestamp"))
    end_time = _parse_time(record.get("session_end"))

    if record.get("assigned_ip") and record.get("assigned_ip") == packet.get("source_ip"):
        score += 30
        factors.append("Exact IP match")
        breakdown.append({"label": "IP Match", "points": 30})

    if record.get("called_ip") and record.get("called_ip") == packet.get("destination_ip"):
        score += 20
        factors.append("Service/IP destination match")
        breakdown.append({"label": "Service Match", "points": 20})

    if packet_time and start_time:
        delta = abs((packet_time - start_time).total_seconds())
        if delta <= 5:
            score += 20
            factors.append("Exact timestamp match")
            breakdown.append({"label": "Timestamp Match", "points": 20})
        elif delta <= 60:
            score += 10
            factors.append("Near timestamp match")
            breakdown.append({"label": "Timestamp Match", "points": 10})

    if packet_time and start_time and (not end_time or start_time <= packet_time <= end_time):
        score += 5
        factors.append("Session overlap")
        breakdown.append({"label": "Session Overlap", "points": 5})

    if row.get("matched_asn"):
        score += 15
        factors.append("ASN match")
        breakdown.append({"label": "ASN Match", "points": 15})

    if record.get("cell_tower"):
        score += 10
        factors.append("Cell tower context")
        breakdown.append({"label": "Cell Tower Context", "points": 10})

    if packet.get("dns_query"):
        score += 10
        factors.append("DNS evidence")
        breakdown.append({"label": "DNS Evidence", "points": 10})

    score = min(score, 99)
    return {
        "time": packet.get("timestamp") or record.get("timestamp") or record.get("session_start"),
        "pcap_evidence": f"{packet.get('source_ip')} -> {packet.get('destination_ip')} {packet.get('protocol')}/{packet.get('destination_port') or 'unknown'}",
        "txt_evidence": _txt_label(record),
        "match_score": f"{score}%",
        "score": score,
        "confidence_label": confidence_label(score),
        "subscriber": record.get("subscriber", ""),
        "imsi": record.get("imsi", ""),
        "imei": record.get("imei", ""),
        "assigned_ip": record.get("assigned_ip", ""),
        "destination_ip": packet.get("destination_ip", ""),
        "provider": row.get("isp", ""),
        "service": row.get("category", ""),
        "asn": row.get("asn", ""),
        "factors": factors,
        "breakdown": breakdown,
        "pcap_raw": packet,
        "txt_raw": record.get("raw_text", ""),
        "txt_evidence_id": f"{record.get('source_file')}|{record.get('subscriber')}|{record.get('session_start')}|{record.get('assigned_ip')}",
        "match_session_id": _match_session_id(record, packet),
    }


def _empty_event(row: dict, packet: dict, record: dict) -> dict:
    return {
        "time": packet.get("timestamp") or record.get("timestamp") or record.get("session_start"),
        "pcap_evidence": f"{packet.get('source_ip')} -> {packet.get('destination_ip')}",
        "txt_evidence": _txt_label(record),
        "match_score": "0%",
        "score": 0,
        "confidence_label": confidence_label(0),
        "subscriber": record.get("subscriber", ""),
        "imsi": record.get("imsi", ""),
        "imei": record.get("imei", ""),
        "assigned_ip": record.get("assigned_ip", ""),
        "destination_ip": packet.get("destination_ip", ""),
        "provider": row.get("isp", ""),
        "service": row.get("category", ""),
        "asn": row.get("asn", ""),
        "factors": [],
        "breakdown": [],
        "pcap_raw": packet,
        "txt_raw": record.get("raw_text", ""),
        "txt_evidence_id": f"{record.get('source_file')}|{record.get('subscriber')}|{record.get('session_start')}|{record.get('assigned_ip')}",
        "match_session_id": _match_session_id(record, packet),
    }


def confidence_label(score: float) -> str:
    if score >= 95:
        return "Very High Confidence"
    if score >= 80:
        return "High Confidence"
    if score >= 60:
        return "Medium Confidence"
    return "Low Confidence"


def _txt_label(record: dict) -> str:
    label = record.get("subscriber") or record.get("imsi") or "Subscriber Session"
    assigned = record.get("assigned_ip")
    return f"{label} ({assigned})" if assigned else label


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = date_parser.parse(str(value), fuzzy=True)
        if parsed.tzinfo:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except Exception:
        return None


def _threat_summary(rows: list[dict]) -> str:
    threats = [row for row in rows if row.get("malicious") or row.get("reputation_score", 0) >= 50]
    if not threats:
        return "None"
    return ", ".join(sorted({row.get("threat_category", "Unknown") for row in threats}))


def _match_session_id(record: dict, packet: dict) -> str:
    return "|".join(
        [
            record.get("source_file", ""),
            record.get("subscriber", ""),
            record.get("session_start", ""),
            record.get("assigned_ip", ""),
            record.get("called_ip", ""),
            packet.get("destination_ip", ""),
        ]
    )


def build_service_correlation(events: list[dict]) -> list[dict]:
    grouped = {}
    for event in events:
        key = event.get("service") or event.get("destination_ip")
        grouped.setdefault(
            key,
            {
                "session": key,
                "pcap_match": "Yes",
                "txt_match": "Yes",
                "confidence": 0.0,
                "events": 0,
            },
        )
        grouped[key]["events"] += 1
        grouped[key]["confidence"] = max(grouped[key]["confidence"], float(event.get("score", 0)))

    return [
        {
            "session": item["session"],
            "pcap_match": item["pcap_match"],
            "txt_match": item["txt_match"],
            "confidence": f"{round(item['confidence'])}%",
            "events": item["events"],
        }
        for item in grouped.values()
    ]


def build_attribution_report(events: list[dict], analysis: dict, evidence_files: list[dict]) -> dict:
    subscribers = sorted({event["subscriber"] for event in events if event.get("subscriber")})
    assigned_ips = sorted({event["assigned_ip"] for event in events if event.get("assigned_ip")})
    devices = sorted({event["imei"] for event in events if event.get("imei")})
    services = sorted({event["service"] for event in events if event.get("service")})
    confidence = round(sum(event["score"] for event in events) / len(events), 1) if events else 0
    summary = {
        "subscriber": subscribers[0] if subscribers else "Unknown",
        "assigned_ip": assigned_ips[0] if assigned_ips else "Unknown",
        "correlated_services": services,
        "supporting_evidence": [item["filename"] for item in evidence_files],
        "confidence": confidence,
        "confidence_label": confidence_label(confidence),
        "assessment": (
            "Network activity observed in the packet capture is highly consistent with the subscriber session records."
            if confidence >= 95
            else "Observed packet-capture activity is partially consistent with the subscriber/session records and should be reviewed with supporting context."
        ),
        "device": devices[0] if devices else "Unknown",
    }
    return summary
