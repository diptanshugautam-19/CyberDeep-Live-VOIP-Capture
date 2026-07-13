import time
import logging
import asyncio
from typing import Dict, List, Any
from app.protocols.models import VoipSession, RtpStream, QosMetrics
from app.protocols.ice import EndpointIdentity, IceCandidate
from app.protocols.stun import parse_stun_packet
from app.protocols.turn import parse_turn_packet
from app.protocols.sip import parse_sip_message
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
        # Call-ID is the canonical session key; it survives re-INVITEs,
        # port changes, and ICE restarts, unlike IP:port.
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
                    # Fallback: generate a temporary call_id from ufrag pair
                    if remote and local:
                        call_id = f"stun_{remote}_{local}"
                    else:
                        call_id = f"stun_txn_{decoded.get('transaction_id', '')}"

        elif protocol == "TURN":
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
                    "endpoints": session.endpoints
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


def datetime_iso(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()

# Singleton
voip_manager = LiveVoipManager()
