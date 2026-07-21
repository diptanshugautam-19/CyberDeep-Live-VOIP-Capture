from app.protocols.models import VoipSession
from app.analysis.attribution_engine import AttributionEngine
from app.analysis.vpn_classifier import ClassificationEngine, EndpointRole, ROLE_TIERS
from pathlib import Path
import uuid
import datetime

STANDARD_STUN_PORTS = {3478, 3479, 3480, 3481, 5349, 19302, 19305}


def build_call_attribution(session: VoipSession, stun_packets: list[dict], rtp_packets: list[dict], sip_messages: list[dict]) -> VoipSession:
    """Takes grouped candidate events + SIP/SDP signaling, and attributes the VoipSession.
    
    Delegates to the forensic-grade AttributionEngine.
    """
    engine = AttributionEngine()
    engine.ingest_parsed_logs(stun_packets, rtp_packets, sip_messages)
    summary = engine.analyze()

    # Collect all unique IPs in the group for classification
    all_ips = set()
    all_records = []
    
    for p in stun_packets:
        r = p if isinstance(p, dict) else p.to_dict()
        all_records.append(r)
        if r.get("source_ip"): all_ips.add(r["source_ip"])
        if r.get("destination_ip"): all_ips.add(r["destination_ip"])
        
    for p in rtp_packets:
        r = p if isinstance(p, dict) else p.to_dict()
        all_records.append(r)
        if r.get("source_ip"): all_ips.add(r["source_ip"])
        if r.get("destination_ip"): all_ips.add(r["destination_ip"])
        
    for p in sip_messages:
        r = p if isinstance(p, dict) else p.to_dict()
        all_records.append(r)
        if r.get("source_ip"): all_ips.add(r["source_ip"])
        if r.get("destination_ip"): all_ips.add(r["destination_ip"])
        if r.get("sdp_media_ip"): all_ips.add(r["sdp_media_ip"])
        for c in r.get("sdp_candidates") or []:
            if c.get("ip"): all_ips.add(c["ip"])

    # Load classification engine
    classifier = ClassificationEngine(Path("registry/interfaces"))
    session_endpoints = []
    excluded_ips = set() # Always empty - never exclude any IP address per user requirement
    
    for ip in sorted(all_ips):
        role, confidence, matched_sig, paired_addr, evidence = classifier.classify(ip, all_records, filename=session.call_id or "")
        tier = ROLE_TIERS[role]
        excluded_from = []
            
        endpoint_id = f"ep_{uuid.uuid4().hex[:6]}"
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        endpoint_data = {
            "endpoint_id": endpoint_id,
            "address": ip,
            "port": None,
            "transport": None,
            "role": role.value,
            "confidence": float(confidence),
            "tier": tier,
            "matched_signature": matched_sig or None,
            "paired_address": paired_addr,
            "evidence": evidence,
            "capture_source": "PCAPdroid" if "vpn" in (matched_sig or "") else "Local GeoIP",
            "excluded_from": excluded_from,
            "first_seen": session.start_time or now_str,
            "last_seen": session.end_time or now_str,
            "role_history": [
                {
                    "role": role.value,
                    "confidence": float(confidence),
                    "assigned_by": matched_sig or "default_classifier",
                    "timestamp": now_str,
                    "evidence_snapshot": evidence
                }
            ]
        }
        session_endpoints.append(endpoint_data)
        
    session.endpoints = session_endpoints
    
    # Store engine results in session model (filtering out excluded/internal vpn endpoints)
    session.participant_public_ip = summary.remote_ip if (summary.remote_ip and summary.remote_ip not in excluded_ips) else "Not Observable"
    session.remote_participant_ip = summary.remote_ip if (summary.remote_ip and summary.remote_ip not in excluded_ips) else "Not Observable"
    session.participant_private_ip = summary.private_ip if (summary.private_ip and summary.private_ip not in excluded_ips) else "Not Observable"
    
    # Apply fallback logic ONLY for participant private IP
    if session.participant_private_ip == "Not Observable":
        from app.analysis.attribution_engine import _is_valid_private_ip
        fallback_ips = set()
        for p in stun_packets + rtp_packets + sip_messages:
            src = p.get("source_ip")
            dst = p.get("destination_ip")
            if src: fallback_ips.add(src)
            if dst: fallback_ips.add(dst)
        pvt_ips = [ip for ip in fallback_ips if _is_valid_private_ip(ip) and ip not in excluded_ips]
        if pvt_ips:
            pvt_ips.sort()
            session.participant_private_ip = pvt_ips[0]
    
    session.media_path = summary.media_path
    session.attribution_reason = summary.reason
    session.attribution_confidence = summary.confidence
    
    # Perform dynamic GeoIP enrichment for participant IP
    if session.participant_public_ip and session.participant_public_ip != "Not Observable":
        try:
            from app.enrichment.telecom import enrich_telecom
            geo = enrich_telecom(session.participant_public_ip)
            session.participant_isp = geo.get("isp") or geo.get("asn_org") or "Unknown ISP"
            session.participant_city = geo.get("city") or "Unknown"
            session.participant_country = geo.get("country") or "Unknown"
        except Exception:
            session.participant_isp = "Unknown"
            session.participant_city = "Unknown"
            session.participant_country = "Unknown"
    else:
        session.participant_isp = "Not Observable"
        session.participant_city = ""
        session.participant_country = ""
    
    # Map back to caller/callee IP details for existing layout/dashboard compatibility
    pvt_ip = summary.private_ip or (session.participant_private_ip if session.participant_private_ip != "Not Observable" else None)
    if pvt_ip and pvt_ip not in excluded_ips:
        session.caller.private_ip = pvt_ip
        session.caller.ip = pvt_ip
    else:
        session.caller.private_ip = None
        session.caller.ip = None

    if summary.public_nat and summary.public_nat not in excluded_ips:
        session.caller.public_ip = summary.public_nat
        session.caller.ip = summary.public_nat
        
    if summary.remote_ip and summary.remote_ip not in excluded_ips:
        session.callee.public_ip = summary.remote_ip
        session.callee.ip = summary.remote_ip
        session.callee.attribution_confidence = "direct"
    elif summary.relay_ip and summary.relay_ip not in excluded_ips:
        session.callee.relay_ip = summary.relay_ip
        session.callee.ip = summary.relay_ip
        session.callee.attribution_confidence = "relay_only"
        
    session.confidence_score = float(summary.confidence)
    session.confidence_reasons = [summary.reason] if summary.reason else []
    
    # Re-group candidates
    from app.protocols.ice import IceCandidate
    session.candidates.clear()
    for c in engine.sdp_parser.candidates:
        if c.ip not in excluded_ips:
            session.candidates.append(IceCandidate(
                ufrag=session.caller.ufrag or "caller",
                candidate_type=c.candidate_type,
                ip=c.ip,
                port=c.port,
                priority=c.priority,
                foundation=c.foundation,
                source_packet_ts=0.0
            ))
        
    # Relays
    session.turn_servers = [srv for srv in engine.correlation.get_turn_relays() if srv.split(":")[0] not in excluded_ips]

    return session
