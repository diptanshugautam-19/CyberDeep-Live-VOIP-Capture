from app.protocols.models import VoipSession
from app.protocols.ice import resolve_endpoint_identity

STANDARD_STUN_PORTS = {3478, 3479, 3480, 3481, 5349, 19302, 19305}


def build_call_attribution(session: VoipSession, stun_packets: list[dict], rtp_packets: list[dict], sip_messages: list[dict]) -> VoipSession:
    """Takes grouped candidate events + SIP/SDP signaling, and attributes the VoipSession."""
    
    # 1. Group candidates by local/remote ufrag
    # From ICE USERNAME format: remoteUfrag:localUfrag (remote = callee, local = caller)
    caller_candidates = []
    callee_candidates = []
    
    caller_ufrag = None
    callee_ufrag = None

    # Get ufrags from USERNAME attributes of STUN packets
    for p in stun_packets:
        remote = p.get("remote_ufrag")
        local = p.get("local_ufrag")
        if remote and local:
            callee_ufrag = remote
            caller_ufrag = local
            break

    # If not found, try from SIP SDP candidates
    if not caller_ufrag or not callee_ufrag:
        for msg in sip_messages:
            candidates = msg.get("sdp_candidates") or []
            for c in candidates:
                # Guess ufrag from message info or default
                if c.get("ufrag"):
                    # We can use this as a fallback
                    pass

    # Extract all candidates from the STUN packets
    from app.protocols.ice import IceCandidate
    seen_candidates = set()

    for p in stun_packets:
        msg_name = p.get("message_name", "")
        # Candidate endpoints from XOR-MAPPED-ADDRESS
        mapped = p.get("xor_mapped_address")
        if mapped:
            c_type = "srflx"
            # If the source port is standard stun ports, it is a server, not client host candidate
            ip = mapped["ip"]
            port = mapped["port"]
            
            # Identify candidate type
            if p.get("is_turn") or "Allocate" in msg_name:
                c_type = "relay"
            
            # Group candidate
            key = (ip, port, c_type)
            if key not in seen_candidates:
                seen_candidates.add(key)
                cand = IceCandidate(
                    ufrag=caller_ufrag or "caller",
                    candidate_type=c_type,
                    ip=ip,
                    port=port,
                    priority=p.get("priority", 0),
                    foundation=p.get("foundation", "1"),
                    source_packet_ts=0.0
                )
                # Map to caller / callee depending on context
                # STUN Binding Request source is caller, Binding Response destination is caller
                if p.get("is_request") or "Request" in msg_name:
                    caller_candidates.append(cand)
                else:
                    callee_candidates.append(cand)

        # TURN relayed/peer candidates
        relayed = p.get("xor_relayed_address")
        if relayed:
            key = (relayed["ip"], relayed["port"], "relay")
            if key not in seen_candidates:
                seen_candidates.add(key)
                cand = IceCandidate(
                    ufrag=callee_ufrag or "callee",
                    candidate_type="relay",
                    ip=relayed["ip"],
                    port=relayed["port"],
                    priority=p.get("priority", 0),
                    foundation=p.get("foundation", "1"),
                    source_packet_ts=0.0
                )
                callee_candidates.append(cand)
                # Add to unique relay servers for VoipSession overview
                srv = f"{relayed['ip']}:{relayed['port']}"
                if srv not in session.turn_servers:
                    session.turn_servers.append(srv)

        peer = p.get("xor_peer_address")
        if peer:
            key = (peer["ip"], peer["port"], "prflx")
            if key not in seen_candidates:
                seen_candidates.add(key)
                cand = IceCandidate(
                    ufrag=callee_ufrag or "callee",
                    candidate_type="prflx",
                    ip=peer["ip"],
                    port=peer["port"],
                    priority=p.get("priority", 0),
                    foundation=p.get("foundation", "1"),
                    source_packet_ts=0.0
                )
                callee_candidates.append(cand)

    # Incorporate candidates from SDP
    for msg in sip_messages:
        candidates = msg.get("sdp_candidates") or []
        for c in candidates:
            c_type = c.get("candidate_type", "host")
            ip = c.get("ip")
            port = c.get("port")
            if not ip or not port:
                continue
            key = (ip, port, c_type)
            if key not in seen_candidates:
                seen_candidates.add(key)
                cand = IceCandidate(
                    ufrag=caller_ufrag or "caller",
                    candidate_type=c_type,
                    ip=ip,
                    port=port,
                    priority=c.get("priority", 0),
                    foundation=c.get("foundation", "1"),
                    source_packet_ts=0.0
                )
                # SDP attributes matching: INVITE is caller side, 200 OK is callee side
                if msg.get("method") == "INVITE" or msg.get("is_request"):
                    caller_candidates.append(cand)
                else:
                    callee_candidates.append(cand)

    # 2. Resolve Endpoint Identities
    session.caller = resolve_endpoint_identity(caller_ufrag or "caller", caller_candidates)
    session.callee = resolve_endpoint_identity(callee_ufrag or "callee", callee_candidates)
    session.candidates = caller_candidates + callee_candidates

    # 3. Anomaly Detection & Scoring
    reasons = ["Initial session score set to 100%"]
    
    # Track USE-CANDIDATE bindings
    use_candidate_ips = set()
    for p in stun_packets:
        if p.get("use_candidate"):
            use_candidate_ips.add(p.get("source_ip"))
            use_candidate_ips.add(p.get("destination_ip"))

    # Anomaly A: Non-standard STUN/TURN port bindings
    non_std_ports = set()
    for p in stun_packets:
        for port in (p.get("source_port"), p.get("destination_port")):
            if port and port < 1024:  # standard well known ranges
                continue
            # STUN signatures on non-standard ports
            if port and port not in STANDARD_STUN_PORTS:
                non_std_ports.add(port)
    if non_std_ports:
        session.confidence_score -= 10
        session.warnings.append(f"Non-standard STUN port usage: {sorted(non_std_ports)}")
        reasons.append("Deducted 10% for using non-standard STUN/TURN ports (evasion risk)")

    # Anomaly B: Session Hijack (multiple USE-CANDIDATE sources)
    if len(use_candidate_ips) > 4:  # More than Caller, Callee, and their NAT/Relay endpoints
        session.confidence_score -= 30
        session.warnings.append("Session hijack warning: Repeated USE-CANDIDATE from multiple distinct IP addresses")
        reasons.append("Deducted 30% for multiple conflicting ICE candidate activations (hijack indicator)")

    # Anomaly C: SSRC collision in RTP stream
    ssrcs = set()
    for p in rtp_packets:
        ssrc = p.get("ssrc")
        if ssrc:
            ssrcs.add(ssrc)
    if len(ssrcs) > 4:  # Normally max 2 streams (audio/video in each direction)
        session.confidence_score -= 15
        session.warnings.append("SSRC collision: Unusual number of media streams observed on the same ports")
        reasons.append("Deducted 15% for SSRC stream count anomalies (media injection threat)")

    # Anomaly D: Symmetric NAT warning
    if session.callee.attribution_confidence == "relay_only":
        session.warnings.append("Callee endpoint behind symmetric NAT (real public IP hidden by TURN relay)")

    # Finalize reasons list
    session.confidence_score = max(0.0, session.confidence_score)
    session.confidence_reasons = reasons

    return session
