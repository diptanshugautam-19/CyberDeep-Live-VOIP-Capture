import time
import hashlib
import logging
import asyncio
from typing import Dict, List, Any, Tuple, Optional
from app.protocols.models import VoipSession, RtpStream, QosMetrics
from app.protocols.ice import (
    EndpointIdentity, IceCandidate, ICECandidate, ICECheck,
    IceStateMachine, IPExtractionStore, find_candidate_by_priority
)
from app.protocols.stun import parse_stun_packet, parse_stun_binding_for_ice
from app.protocols.turn import (
    parse_turn_packet,
    parse_turn_allocate_request,
    parse_turn_allocate_response,
    parse_turn_channel_bind,
)
from app.protocols.tcp_media import analyze_tcp_stream, make_tcp_stream
from app.protocols.sip import parse_sip_message, parse_sip_ips
from app.protocols.rtp import parse_rtp_header
from app.protocols.tls_parser import extract_sni
from app.protocols.dns import parse_dns_payload
from app.analysis.attribution import build_call_attribution
from app.analysis.graph_hooks import voip_session_to_graph
from app.storage.database import router
from app.core.bridge import broadcast_manager

logger = logging.getLogger(__name__)

# Session timeout: expire inactive sessions after 300 seconds
SESSION_TIMEOUT_SECONDS = 300


class LiveVoipManager:
    def __init__(self):
        # Primary lookup: SIP Call-ID -> VoipSession
        self.active_calls: Dict[str, VoipSession] = {}

        # Secondary lookup: SSRC -> call_id
        self.ssrc_to_call: Dict[int, str] = {}

        # Ufrag -> call_id mapping (populated from SDP a=ice-ufrag and STUN USERNAME)
        self.ufrag_to_call: Dict[str, str] = {}

        # Raw packet logs for attribution (grouped by call_id)
        self.stun_logs: Dict[str, List[dict]] = {}
        self.rtp_logs: Dict[str, List[dict]] = {}
        self.sip_logs: Dict[str, List[dict]] = {}

        # DNS resolution cache: IP -> hostname (from DNS A/AAAA answers)
        self.dns_cache: Dict[str, str] = {}

        # TLS SNI cache: IP:port -> hostname (from ClientHello SNI)
        self.sni_cache: Dict[str, str] = {}

        # Session last-activity timestamps for timeout cleanup
        self.last_activity: Dict[str, float] = {}

        # ---- Production WebRTC Capture Engine v3 additions ----

        # Per-session ICE state machines (keyed by ufrag / call_id)
        self.ice_state_machines: Dict[str, IceStateMachine] = {}

        # In-flight TURN Allocate transactions: txn_id_hex -> {client, requested_at, transport}
        self.turn_sessions: Dict[str, dict] = {}

        # Confirmed TURN allocations: "relay_ip:port" -> TURNAllocation
        self.turn_allocations: Dict[str, Any] = {}

        # TCP stream reassembly buffers: stream_key -> stream_state_dict
        self.tcp_stream_buffers: Dict[str, dict] = {}

        # De-duplicated IP extraction store (mirrors _add_ip / seen_ips in engine v3)
        self.ip_store = IPExtractionStore(filter_private=False)

        self.lock = asyncio.Lock()
        self._cleanup_task = None

    def start_cleanup_loop(self):
        """Start the periodic session timeout cleanup loop."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def _cleanup_loop(self):
        """Expire inactive sessions every 60 seconds to prevent memory leakage."""
        while True:
            try:
                await asyncio.sleep(60)
                await self._expire_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")

    async def _expire_sessions(self):
        """Remove sessions that have been inactive for more than SESSION_TIMEOUT_SECONDS."""
        now = time.time()
        async with self.lock:
            expired = [
                cid for cid, ts in self.last_activity.items()
                if now - ts > SESSION_TIMEOUT_SECONDS
            ]
            for cid in expired:
                self.active_calls.pop(cid, None)
                self.stun_logs.pop(cid, None)
                self.rtp_logs.pop(cid, None)
                self.sip_logs.pop(cid, None)
                self.last_activity.pop(cid, None)
                # Clean up ssrc and ufrag reverse maps
                self.ssrc_to_call = {
                    k: v for k, v in self.ssrc_to_call.items() if v != cid
                }
                self.ufrag_to_call = {
                    k: v for k, v in self.ufrag_to_call.items() if v != cid
                }
            if expired:
                logger.info(f"Expired {len(expired)} inactive VoIP sessions")

    async def process_packet(self, parsed_pkt: dict):
        """Processes a packet from the live stream for VoIP session tracking."""
        protocol = parsed_pkt.get("protocol")
        raw_bytes = parsed_pkt.get("payload") or b""
        timestamp = parsed_pkt.get("timestamp", time.time())
        src_ip = parsed_pkt.get("source_ip")
        dst_ip = parsed_pkt.get("destination_ip")
        src_port = parsed_pkt.get("source_port")
        dst_port = parsed_pkt.get("destination_port")

        if not raw_bytes:
            return

        # ---- TCP stream reassembly (RFC 4571 / WebSocket / SIP-over-TCP) ----
        # Handles all media-bearing TCP flows from ProductionWebRTCCaptureEngine v3
        if protocol == "TCP" and src_ip and dst_ip:
            self._process_tcp_packet(raw_bytes, src_ip, src_port, dst_ip, dst_port)

        call_id = None
        voip_type = None  # "SIP" or "STUN" or "RTP" or "TURN"
        decoded = None

        # --- 1. Protocol-specific parsing and call_id resolution ---

        if protocol == "SIP" or src_port == 5060 or dst_port == 5060:
            decoded = parse_sip_message(raw_bytes)
            if decoded:
                voip_type = "SIP"
                # SIP Call-ID is the primary, canonical session key
                call_id = decoded.get("call_id")
                # Register SDP ice-ufrag -> call_id mapping for STUN correlation
                sdp_ufrag = decoded.get("ice_ufrag")
                if sdp_ufrag and call_id:
                    self.ufrag_to_call[sdp_ufrag] = call_id

                # ---- parse_sip_message() IP extraction (engine v3 equivalent) ----
                # Uses _parse_addr_advanced() for Via/Contact, registers all IPs
                # including sdp_c_line, sdp_origin, and all ice_candidate_* types
                for ip_entry in parse_sip_ips(raw_bytes):
                    self.ip_store.add_ip(
                        ip_entry['source'],
                        ip_entry['ip'],
                        ip_entry['port'],
                        ip_entry['ip_version'],
                        ip_entry['context'],
                        ip_entry['confidence'],
                        session_id=call_id or ip_entry.get('ice_ufrag'),
                    )

        elif protocol == "STUN" or src_port == 3478 or dst_port == 3478:
            decoded = parse_stun_packet(raw_bytes)
            if decoded:
                voip_type = "STUN"
                # Correlate via ufrag -> call_id (populated by SDP)
                remote = decoded.get("remote_ufrag")
                local = decoded.get("local_ufrag")
                if remote and remote in self.ufrag_to_call:
                    call_id = self.ufrag_to_call[remote]
                elif local and local in self.ufrag_to_call:
                    call_id = self.ufrag_to_call[local]
                else:
                    if remote and local:
                        call_id = f"stun_{remote}_{local}"
                    else:
                        call_id = f"stun_txn_{decoded.get('transaction_id', '')}"

                # ---- ICE nomination tracking (engine v3) ----
                self._handle_stun_ice(
                    raw_bytes, decoded, call_id, src_ip, src_port, dst_ip, dst_port
                )

        elif protocol == "TURN" or src_port in (3478, 5349, 19302) or dst_port in (3478, 5349, 19302):
            # ---- TURN allocation tracking (engine v3) ----
            # Try request first (records client addr), then response (builds allocation)
            if parse_turn_allocate_request(raw_bytes, (src_ip, src_port), self.turn_sessions):
                decoded = parse_turn_packet(raw_bytes)
                voip_type = "TURN"
            else:
                alloc = parse_turn_allocate_response(
                    raw_bytes, (src_ip, src_port), self.turn_sessions
                )
                if alloc:
                    key = f"{alloc.relay_addr}:{alloc.relay_port}"
                    self.turn_allocations[key] = alloc
                    # Record client real IP (turn_client_real source)
                    self.ip_store.add_ip(
                        'turn_client_real', alloc.client_addr, alloc.client_port,
                        6 if ':' in alloc.client_addr else 4,
                        f"TURN allocation client for relay {key}", 'high'
                    )
                    # Record XOR-MAPPED-ADDRESS (turn_xor_mapped_client source)
                    # Mirrors ProductionWebRTCCaptureEngine.parse_turn_message() Allocate response branch
                    xm = getattr(alloc, '_xor_mapped_client', None)
                    if xm:
                        xm_ip, xm_port = xm
                        self.ip_store.add_ip(
                            'turn_xor_mapped_client', xm_ip, xm_port,
                            6 if ':' in xm_ip else 4,
                            f"TURN XOR-MAPPED-ADDRESS (real client)", 'high'
                        )
                elif parse_turn_channel_bind(raw_bytes, (src_ip, src_port), self.turn_allocations):
                    pass  # Channel binding updated in-place

            if not decoded:
                decoded = parse_turn_packet(raw_bytes)
            if decoded:
                voip_type = "TURN"
                remote = decoded.get("remote_ufrag")
                local = decoded.get("local_ufrag")
                if remote and remote in self.ufrag_to_call:
                    call_id = self.ufrag_to_call[remote]
                elif local and local in self.ufrag_to_call:
                    call_id = self.ufrag_to_call[local]
                else:
                    if remote and local:
                        call_id = f"stun_{remote}_{local}"
                    else:
                        call_id = f"stun_txn_{decoded.get('transaction_id', '')}"

        elif protocol == "RTP":
            decoded = parse_rtp_header(raw_bytes)
            if decoded:
                voip_type = "RTP"
                ssrc = decoded.get("ssrc")
                pt   = decoded.get("payload_type", 0)
                # Map SSRC to call if we already mapped it
                if ssrc in self.ssrc_to_call:
                    call_id = self.ssrc_to_call[ssrc]
                else:
                    # Try matching by endpoints
                    call_id = self._match_call_by_endpoints(src_ip, dst_ip, src_port, dst_port)
                    if not call_id:
                        # Create a new partial call for mid-session join
                        call_id = f"rtp_call_{ssrc}"
                    self.ssrc_to_call[ssrc] = call_id

                # ---- rtp_udp source (from ProductionWebRTCCaptureEngine.process_packet UDP/RTP branch) ----
                self.ip_store.add_ip(
                    'rtp_udp', src_ip, src_port,
                    6 if src_ip and ':' in src_ip else 4,
                    f"RTP/UDP PT={pt} SSRC={ssrc:08X}",
                    'high',
                    session_id=call_id
                )

        elif protocol == "DNS":
            # DNS correlation: tie IPs to hostnames for forensic attribution
            dns_result = parse_dns_payload(raw_bytes)
            if dns_result:
                for answer in dns_result.get("answers", []):
                    ip = answer.get("data", "")
                    name = answer.get("name", "")
                    if ip and name:
                        self.dns_cache[ip] = name
            return  # DNS packets are not VoIP sessions, just enrich the cache

        elif protocol == "TLS":
            # TLS SNI correlation: tie server IPs to hostnames
            sni = extract_sni(raw_bytes)
            if sni and dst_ip:
                key = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
                self.sni_cache[key] = sni
            return  # TLS packets are not VoIP sessions, just enrich the cache

        if not call_id:
            return

        async with self.lock:
            # Update last-activity timestamp
            self.last_activity[call_id] = time.time()

            # Initialize lists
            if call_id not in self.stun_logs:
                self.stun_logs[call_id] = []
            if call_id not in self.rtp_logs:
                self.rtp_logs[call_id] = []
            if call_id not in self.sip_logs:
                self.sip_logs[call_id] = []

            # --- 2. Get/Create VoIP Session ---
            if call_id not in self.active_calls:
                self.active_calls[call_id] = VoipSession(
                    call_id=call_id,
                    start_time=datetime_iso(timestamp),
                    end_time=datetime_iso(timestamp),
                    protocol="VoIP"
                )

            session = self.active_calls[call_id]
            session.end_time = datetime_iso(timestamp)

            # --- 3. Handle specific protocol packets ---
            if decoded:
                decoded["source_ip"] = src_ip
                decoded["destination_ip"] = dst_ip
                decoded["source_port"] = src_port
                decoded["destination_port"] = dst_port
                decoded["protocol"] = voip_type
                decoded["timestamp"] = timestamp
                decoded["length"] = parsed_pkt.get("length", 0)

            if voip_type == "SIP" and decoded:
                self.sip_logs[call_id].append(decoded)
                # Parse caller/callee from SIP headers
                if not session.caller.ufrag or session.caller.ufrag == "caller":
                    session.caller = EndpointIdentity(ufrag="caller", ip=src_ip, port=src_port)
                if not session.callee.ufrag or session.callee.ufrag == "callee":
                    session.callee = EndpointIdentity(ufrag="callee", ip=dst_ip, port=dst_port)

            elif voip_type in ("STUN", "TURN") and decoded:
                self.stun_logs[call_id].append(decoded)

            elif voip_type == "RTP" and decoded:
                self.rtp_logs[call_id].append(decoded)
                # Update RTP Streams in the session
                ssrc = decoded.get("ssrc")
                payload_type = decoded.get("payload_type")

                # Check if stream exists
                rtp_stream = None
                for stream in session.media_streams:
                    if stream.ssrc == ssrc:
                        rtp_stream = stream
                        break

                if not rtp_stream:
                    rtp_stream = RtpStream(ssrc=ssrc, payload_type=payload_type)
                    session.media_streams.append(rtp_stream)

                rtp_stream.packets_count += 1
                rtp_stream.bytes_count += parsed_pkt.get("length", 0)

            # --- 4. Perform VoIP Attribution ---
            # Candidate type (host/srflx/relay) comes from SDP a=candidate lines,
            # NOT from STUN wire format. build_call_attribution correlates them.
            joined_mid = len(self.stun_logs[call_id]) == 0

            session = build_call_attribution(
                session,
                self.stun_logs[call_id],
                self.rtp_logs[call_id],
                self.sip_logs[call_id]
            )

            # Apply mid-session constraints
            if joined_mid:
                session.confidence_score = 40.0
                if "Call joined mid-session: ICE/STUN negotiation missing." not in session.confidence_reasons:
                    session.confidence_reasons.append("Call joined mid-session: ICE/STUN negotiation missing.")
                if "Partial session capture" not in session.warnings:
                    session.warnings.append("Partial session capture")
                confidence_tier = "relay_only" if session.turn_servers else "unresolved"
            else:
                confidence_tier = "direct"

            # --- 5. Persist to SQLite ---
            self._persist_voip_session(session, joined_mid, confidence_tier)

            # --- 6. Broadcast VoIP status to WebSockets (Priority 1) ---
            graph_data = voip_session_to_graph(session)

            # Enrich with DNS/SNI hostnames
            caller_hostname = self._resolve_hostname(session.caller.ip, session.caller.port)
            callee_hostname = self._resolve_hostname(session.callee.ip, session.callee.port)

            await broadcast_manager.broadcast({
                "type": "voip_update",
                "session": {
                    "call_id": session.call_id,
                    "start_time": session.start_time,
                    "end_time": session.end_time,
                    "caller_ip": session.caller.ip,
                    "callee_ip": session.callee.ip,
                    "caller_hostname": caller_hostname,
                    "callee_hostname": callee_hostname,
                    "turn_servers": session.turn_servers,
                    "confidence_score": session.confidence_score,
                    "confidence_tier": confidence_tier,
                    "joined_mid_session": joined_mid,
                    "warnings": session.warnings,
                    "media_streams": [
                        {
                            "ssrc": s.ssrc,
                            "payload_type": s.payload_type,
                            "packets_count": s.packets_count,
                            "bytes_count": s.bytes_count
                        } for s in session.media_streams
                    ],
                    "jitter": session.qos.jitter_ms,
                    "loss": session.qos.packet_loss_pct,
                    "mos": session.qos.mos_score,
                    "mos_label": session.qos.mos_label,
                    "graph": graph_data,
                    "participant_public_ip": session.participant_public_ip or "Not Observable",
                    "remote_participant_ip": session.remote_participant_ip or "Not Observable",
                    "participant_private_ip": session.participant_private_ip or "Not Observable",
                    "media_path": session.media_path or "Unknown",
                    "attribution_reason": session.attribution_reason or "",
                    "attribution_confidence": session.attribution_confidence,
                    "participant_isp": session.participant_isp or "Not Observable",
                    "participant_city": session.participant_city or "",
                    "participant_country": session.participant_country or "",
                    "endpoints": session.endpoints,
                    # ---- Production WebRTC Capture Engine v3 additions ----
                    "ice_state": self._get_ice_state(call_id),
                    "nominated_pair": self._get_nominated_pair(call_id),
                    "turn_allocations": [
                        {
                            "relay": f"{a.relay_addr}:{a.relay_port}",
                            "client": f"{a.client_addr}:{a.client_port}",
                            "lifetime": a.lifetime,
                            "channels": {
                                str(ch): f"{peer[0]}:{peer[1]}"
                                for ch, peer in a.channels.items()
                            }
                        }
                        for a in self.turn_allocations.values()
                    ],
                    "extracted_ips": self.ip_store.get_by_category(),
                }
            }, priority=1)

    def _resolve_hostname(self, ip: str | None, port: int | None) -> str:
        """Resolve an IP to a hostname using TLS SNI cache first, then DNS cache."""
        if not ip:
            return ""
        # Try SNI cache first (more specific: IP:port)
        if port:
            key = f"{ip}:{port}"
            if key in self.sni_cache:
                return self.sni_cache[key]
        # Fall back to DNS cache (IP only)
        return self.dns_cache.get(ip, "")

    def _match_call_by_endpoints(self, src: str, dst: str, sport: int, dport: int) -> str | None:
        """Finds an active call matching endpoints (IPs and ports)."""
        for cid, call in self.active_calls.items():
            if (call.caller.ip == src and call.caller.port == sport) or \
               (call.caller.ip == dst and call.caller.port == dport):
                return cid
            if (call.callee.ip == src and call.callee.port == sport) or \
               (call.callee.ip == dst and call.callee.port == dport):
                return cid
        return None

    def _persist_voip_session(self, session: VoipSession, joined_mid: bool, confidence_tier: str):
        """Writes VoIP metadata into flows.sqlite3 tables."""
        try:
            # 1. Update sip_dialogs
            router.execute(
                "sip_dialogs",
                """INSERT OR REPLACE INTO sip_dialogs 
                (id, call_id, from_uri, to_uri, method, status_code, user_agent, sdp_media_ip, sdp_media_port, joined_mid_session, confidence_tier)
                VALUES (
                    (SELECT id FROM sip_dialogs WHERE call_id = ?), 
                    ?, ?, ?, 'INVITE', '200 OK', 'Live Agent', ?, ?, ?, ?
                )""",
                (
                    session.call_id,
                    session.call_id,
                    session.caller.ufrag or "caller",
                    session.callee.ufrag or "callee",
                    session.callee.ip or "",
                    session.callee.port or 0,
                    1 if joined_mid else 0,
                    confidence_tier
                )
            )

            # 2. Update rtp_streams
            for stream in session.media_streams:
                router.execute(
                    "rtp_streams",
                    """INSERT OR REPLACE INTO rtp_streams 
                    (id, session_flow_id, ssrc, payload_type, packet_count, jitter, loss, mos)
                    VALUES (
                        (SELECT id FROM rtp_streams WHERE session_flow_id = ? AND ssrc = ?),
                        ?, ?, ?, ?, ?, ?, ?
                    )""",
                    (
                        session.call_id,
                        stream.ssrc,
                        session.call_id,
                        stream.ssrc,
                        stream.payload_type,
                        stream.packets_count,
                        session.qos.jitter_ms,
                        session.qos.packet_loss_pct,
                        session.qos.mos_score
                    )
                )

            # 3. Update ice_sessions
            for srv in session.turn_servers:
                router.execute(
                    "ice_sessions",
                    """INSERT OR REPLACE INTO ice_sessions 
                    (id, session_flow_id, ufrag, state, candidate_type, relay_server, nat_type_guess, joined_mid_session, confidence_tier)
                    VALUES (
                        (SELECT id FROM ice_sessions WHERE session_flow_id = ? AND relay_server = ?),
                        ?, ?, ?, ?, ?, 'unknown', ?, ?
                    )""",
                    (
                        session.call_id,
                        srv,
                        session.call_id,
                        session.caller.ufrag or "caller",
                        "CONNECTED",
                        "relay",
                        srv,
                        1 if joined_mid else 0,
                        confidence_tier
                    )
                )
        except Exception as e:
            logger.error(f"Failed to persist VoIP session in SQLite: {e}")

    # =========================================================================
    # Private helpers — Production WebRTC Capture Engine v3 integration
    # =========================================================================

    def _get_or_create_ice_machine(self, session_key: str) -> IceStateMachine:
        """Return the IceStateMachine for session_key, creating it if absent."""
        if session_key not in self.ice_state_machines:
            self.ice_state_machines[session_key] = IceStateMachine()
        return self.ice_state_machines[session_key]

    def _handle_stun_ice(
        self,
        raw_bytes: bytes,
        decoded: dict,
        call_id: str,
        src_ip: str, src_port: int,
        dst_ip: str, dst_port: int,
    ):
        """
        Drive the ICE state machine on each STUN Binding Request/Response.
        Mirrors ProductionWebRTCCaptureEngine.parse_stun_binding().
        """
        ice_fields = parse_stun_binding_for_ice(raw_bytes)
        if not ice_fields:
            return

        ufrag = ice_fields.get('ufrag') or call_id
        machine = self._get_or_create_ice_machine(ufrag)

        if ice_fields.get('is_controlling'):
            machine.is_controlling = True

        if ice_fields['is_request']:
            # Build a minimal ICECheck from what we know on the wire
            remote_cand = ICECandidate(
                foundation='remote',
                component=1,
                transport='UDP',
                priority=ice_fields.get('priority') or 0,
                ip=src_ip,
                port=src_port,
                candidate_type='prflx',
            )
            check = ICECheck(
                local_candidate=remote_cand,
                remote_candidate=remote_cand,
                use_candidate_seen=ice_fields['use_candidate'],
                nominated=ice_fields['use_candidate'],
            )
            machine.on_binding_request(check)

            if ice_fields['use_candidate']:
                logger.info(f"[ICE] USE-CANDIDATE seen in session {ufrag}")

            # Extract XOR-MAPPED-ADDRESS if present in request (unusual but valid)
            xm = ice_fields.get('xor_mapped')
            if xm:
                self.ip_store.add_ip(
                    'ice_binding_response', xm['ip'], xm['port'],
                    6 if ':' in xm['ip'] else 4,
                    f"STUN request XOR-MAPPED from {ufrag}", 'medium', ufrag
                )
        else:
            # Binding Response: confirm the most recent unconfirmed nominated check
            xm = ice_fields.get('xor_mapped')
            pending = [c for c in machine.checks if not c.succeeded]
            check = pending[-1] if pending else None
            if check:
                machine.on_binding_response(check)

            if xm:
                is_nom = machine.nomination_confirmed
                self.ip_store.add_ip(
                    'ice_binding_response', xm['ip'], xm['port'],
                    6 if ':' in xm['ip'] else 4,
                    f"STUN response XOR-MAPPED (session {ufrag})", 'high',
                    ufrag, is_nominated=is_nom
                )
                if machine.nomination_confirmed:
                    logger.info(
                        f"[ICE] Nominated pair confirmed for {ufrag}: "
                        f"{xm['ip']}:{xm['port']}"
                    )

    def _process_tcp_packet(
        self,
        raw_bytes: bytes,
        src_ip: str, src_port: int,
        dst_ip: str, dst_port: int,
    ):
        """
        Route a TCP payload through the stream reassembler.
        Mirrors ProductionWebRTCCaptureEngine.process_packet() TCP branch.
        """
        stream_key_fwd = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        stream_key_rev = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        # Canonical key: alphabetically larger string
        stream_key = stream_key_fwd if stream_key_fwd > stream_key_rev else stream_key_rev

        if stream_key not in self.tcp_stream_buffers:
            self.tcp_stream_buffers[stream_key] = make_tcp_stream()

        stream = self.tcp_stream_buffers[stream_key]

        def on_rtp(ip, port, pt, ssrc, seq, sk):
            self.ip_store.add_ip(
                'rtp_over_tcp', ip, port,
                6 if ':' in ip else 4,
                f"RTP/TCP PT={pt} SSRC={ssrc:08X} (RFC 4571)", 'high', sk[:8]
            )

        def on_sip_bytes(payload, s_ip, s_port):
            # Parse SIP and record ICE candidates in ip_store
            result = parse_sip_message(payload)
            if not result:
                return
            candidates = result.get('sdp_candidates', [])
            ufrag = result.get('ice_ufrag', '')
            for cand in candidates:
                ctype = cand.get('candidate_type', 'host')
                confidence_map = {'srflx': 'high', 'prflx': 'high', 'host': 'medium', 'relay': 'low'}
                self.ip_store.add_ip(
                    f'ice_candidate_{ctype}',
                    cand['ip'], cand['port'],
                    6 if ':' in cand['ip'] else 4,
                    f"a=candidate typ {ctype} [via TCP stream]",
                    confidence_map.get(ctype, 'low'),
                    ufrag or stream_key[:8]
                )

        analyze_tcp_stream(
            raw_bytes, stream,
            (src_ip, src_port), (dst_ip, dst_port),
            stream_key, on_rtp, on_sip_bytes
        )

    def _get_ice_state(self, call_id: str) -> str:
        """Return ICE state string for broadcast payload."""
        ufrag = None
        # Try to resolve ufrag from call_id via reverse map
        for u, cid in self.ufrag_to_call.items():
            if cid == call_id:
                ufrag = u
                break
        key = ufrag or call_id
        machine = self.ice_state_machines.get(key)
        if not machine:
            return "NEW"
        return machine.ice_state.name

    def _get_nominated_pair(self, call_id: str) -> Optional[dict]:
        """Return nominated ICE pair info for broadcast payload."""
        ufrag = None
        for u, cid in self.ufrag_to_call.items():
            if cid == call_id:
                ufrag = u
                break
        key = ufrag or call_id
        machine = self.ice_state_machines.get(key)
        if not machine or not machine.nominated_pair:
            return None
        pair = machine.nominated_pair
        return {
            "local_ip":  pair.local_candidate.ip,
            "local_port": pair.local_candidate.port,
            "remote_ip": pair.remote_candidate.ip,
            "remote_port": pair.remote_candidate.port,
            "succeeded":  pair.succeeded,
        }


# Singleton
voip_manager = LiveVoipManager()


def datetime_iso(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()
