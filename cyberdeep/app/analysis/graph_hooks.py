from app.protocols.models import VoipSession
from app.enrichment.telecom import enrich_telecom


def voip_session_to_graph(session: VoipSession) -> dict:
    """Export a VoipSession to nodes and edges matching the NCRP graph schema."""
    nodes = []
    edges = []
    seen_nodes = set()

    def add_node(ip: str, role: str, confidence: int):
        if not ip or ip in seen_nodes:
            return
        seen_nodes.add(ip)

        # Lookup telecom info
        asn = "AS0"
        country = "Unknown"
        try:
            telemetry = enrich_telecom(ip)
            if telemetry:
                asn_num = telemetry.get("asn") or telemetry.get("asn_number") or ""
                asn_org = telemetry.get("asn_org") or telemetry.get("isp") or ""
                asn = f"AS{asn_num} {asn_org}".strip() if asn_num else asn_org or "AS0"
                country = telemetry.get("country") or "Unknown"
        except Exception:
            pass

        nodes.append(
            {
                "id": ip,
                "label": ip,
                "role": role,
                "confidence": confidence,
                "asn": asn,
                "country": country,
            }
        )

    # 1. Add Endpoint Nodes
    caller_conf = 99 if session.caller.attribution_confidence == "direct" else 70
    callee_conf = int(session.confidence_score)

    if session.caller.private_ip:
        add_node(session.caller.private_ip, "caller private IP", 99)
    if session.caller.public_ip:
        add_node(session.caller.public_ip, "caller public IP", caller_conf)

    if session.callee.private_ip:
        add_node(session.callee.private_ip, "callee private IP", callee_conf)
    if session.callee.public_ip:
        add_node(session.callee.public_ip, "callee public IP", callee_conf)
    if session.callee.relay_ip:
        add_node(session.callee.relay_ip, "VoIP media relay", 100)

    # Add stun/turn servers
    for srv in session.turn_servers:
        ip = srv.split(":")[0]
        add_node(ip, "TURN server", 100)

    # 2. Add Communication Edges
    def add_edge(source: str, target: str, label: str, protocol: str):
        if not source or not target:
            return
        edges.append(
            {
                "source": source,
                "target": target,
                "label": label,
                "protocol": protocol,
                "weight": 80,
            }
        )

    # Edge: Caller Private -> Caller Public
    if session.caller.private_ip and session.caller.public_ip and session.caller.private_ip != session.caller.public_ip:
        add_edge(
            session.caller.private_ip,
            session.caller.public_ip,
            "ICE STUN Binding (NAT Mapping)",
            "STUN"
        )

    # Edge: Caller Public -> Relay Server
    relay_ip = None
    if session.turn_servers:
        relay_ip = session.turn_servers[0].split(":")[0]
    elif session.callee.relay_ip:
        relay_ip = session.callee.relay_ip

    if relay_ip:
        src = session.caller.public_ip or session.caller.private_ip
        if src:
            add_edge(src, relay_ip, "TURN Allocation & Channel Bind", "TURN")

        # Edge: Relay Server -> Callee Public/Private
        dst = session.callee.public_ip or session.callee.private_ip
        if dst:
            add_edge(relay_ip, dst, "Relayed media channel", "RTP")
    else:
        # Peer-to-Peer
        src = session.caller.public_ip or session.caller.private_ip
        dst = session.callee.public_ip or session.callee.private_ip
        if src and dst:
            add_edge(src, dst, "Direct media stream", "RTP")

    return {"nodes": nodes, "edges": edges}
