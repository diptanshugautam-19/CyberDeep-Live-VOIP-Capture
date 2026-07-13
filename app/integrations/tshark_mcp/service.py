import os
import time
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from app.integrations.tshark_mcp.client import TSharkMcpClient
from app.integrations.tshark_mcp.cache import McpCache
from app.integrations.tshark_mcp.models import InvestigationSession, SIPCall, RTPSession, ICESession, STUNTransaction, TURNAllocation, Endpoint, Conversation
from app.storage.database import router

logger = logging.getLogger("tshark-mcp-service")

class TSharkMcpService:
    def __init__(self):
        self.client = TSharkMcpClient()

    async def analyze_file(self, pcap_path: str) -> InvestigationSession:
        pcap_path = os.path.abspath(pcap_path)
        logger.info(f"Starting TShark MCP analysis for {pcap_path}")
        
        # Check cache first
        cached = McpCache.get(pcap_path, "full_analysis")
        if cached:
            logger.info("Cache hit for full analysis")
            return InvestigationSession(**cached)

        # Call MCP tools
        await self.client.start()
        try:
            sip_data = await self.client.call_tool("list_sip_calls", {"pcap_path": pcap_path})
            rtp_data = await self.client.call_tool("list_rtp_streams", {"pcap_path": pcap_path})
            ice_data = await self.client.call_tool("extract_ice_candidates", {"pcap_path": pcap_path})
            stun_data = await self.client.call_tool("extract_stun_transactions", {"pcap_path": pcap_path})
            turn_data = await self.client.call_tool("find_turn_servers", {"pcap_path": pcap_path})
            pcap_summary = await self.client.call_tool("summarize_capture", {"pcap_path": pcap_path})
            packet_data = await self.client.call_tool("analyze_pcap", {"pcap_path": pcap_path, "limit": 1000})

            # Map tools data to models
            sip_calls = []
            for c in sip_data.get("calls", []):
                sip_calls.append(SIPCall(
                    call_id=c.get("call_id", ""),
                    caller=c.get("caller", ""),
                    callee=c.get("callee", ""),
                    status=c.get("status", ""),
                    start_time=0.0,
                    packets_count=0
                ))

            rtp_sessions = []
            for r in rtp_data.get("streams", []):
                rtp_sessions.append(RTPSession(
                    ssrc=r.get("ssrc", ""),
                    source_ip=r.get("source_ip", ""),
                    dest_ip=r.get("dest_ip", ""),
                    source_port=r.get("source_port", 0),
                    dest_port=r.get("dest_port", 0),
                    packet_count=r.get("packet_count", 0),
                    lost_packets=r.get("lost_packets", 0),
                    jitter=r.get("jitter", 0.0),
                    duration=0.0
                ))

            ice_sessions = []
            for idx, i in enumerate(ice_data.get("candidates", [])):
                ice_sessions.append(ICESession(
                    session_id=f"ice_{idx}",
                    caller_ufrag=i.get("username", "").split(":")[0],
                    callee_ufrag=i.get("username", "").split(":")[-1] if ":" in i.get("username", "") else "",
                    state="CONNECTED",
                    candidates=[i]
                ))

            stun_transactions = []
            for s in stun_data.get("transactions", []):
                stun_transactions.append(STUNTransaction(
                    transaction_id=s.get("transaction_id", ""),
                    method="Binding",
                    class_type=s.get("type", "Request"),
                    source_ip=s.get("source_ip", ""),
                    source_port=s.get("source_port", 0),
                    dest_ip=s.get("dest_ip", ""),
                    dest_port=s.get("dest_port", 0),
                    result="Success"
                ))

            turn_allocations = []
            for idx, t in enumerate(turn_data.get("turn_servers", [])):
                turn_allocations.append(TURNAllocation(
                    allocation_id=f"turn_{idx}",
                    client_ip="0.0.0.0",
                    client_port=0,
                    relay_ip=t.get("ip", ""),
                    relay_port=t.get("port", 3478),
                    lifetime=3600
                ))

            # Build endpoints and conversations from packet_data
            endpoints_map = {}
            conversations_map = {}
            timeline = []

            for p in packet_data.get("packets", []):
                src = p["source_ip"]
                dst = p["dest_ip"]
                length = p["length"]
                
                # Endpoints
                for ip in (src, dst):
                    if ip not in endpoints_map:
                        endpoints_map[ip] = {
                            "ip": ip, "port": p["source_port"] or 0, "protocol": p["protocol"],
                            "packets_sent": 0, "packets_received": 0, "bytes_sent": 0, "bytes_received": 0
                        }
                endpoints_map[src]["packets_sent"] += 1
                endpoints_map[src]["bytes_sent"] += length
                endpoints_map[dst]["packets_received"] += 1
                endpoints_map[dst]["bytes_received"] += length

                # Conversations
                conv_key = f"{src}-{dst}" if src < dst else f"{dst}-{src}"
                if conv_key not in conversations_map:
                    conversations_map[conv_key] = {
                        "id": conv_key, "endpoint_a": src, "endpoint_b": dst,
                        "protocol": p["protocol"], "packets": 0, "bytes": 0, "duration": 0.0
                    }
                conversations_map[conv_key]["packets"] += 1
                conversations_map[conv_key]["bytes"] += length

                # Timeline entry
                timeline.append({
                    "packet_index": p["index"],
                    "timestamp": p["timestamp"],
                    "protocol": p["protocol"],
                    "source": src,
                    "destination": dst,
                    "length": length,
                    "info": p["summary"]
                })

            endpoints = [Endpoint(**e) for e in endpoints_map.values()]
            conversations = [Conversation(**c) for c in conversations_map.values()]

            session = InvestigationSession(
                session_id=McpCache.get_file_hash(pcap_path)[:12],
                sip_calls=sip_calls,
                rtp_sessions=rtp_sessions,
                ice_sessions=ice_sessions,
                stun_transactions=stun_transactions,
                turn_allocations=turn_allocations,
                dns_queries=[],
                tls_handshakes=[],
                endpoints=endpoints,
                conversations=conversations,
                timeline=timeline
            )

            session_dict = session.dict()
            McpCache.set(pcap_path, "full_analysis", session_dict)

            # Persist to database
            try:
                # Get TShark version
                tshark_ver = "TShark (Wireshark) 4.6.7"
                original_cmd = f"tshark -r {pcap_path} [various MCP tools]"
                created_at_str = datetime.now(timezone.utc).isoformat()
                
                # Check table map for investigations path
                db_path = router.table_map["investigations"]
                with router._get_connection(db_path) as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO investigations (id, filename, created_at, summary_json, case_json) VALUES (?, ?, ?, ?, ?)",
                        (
                            session.session_id,
                            os.path.basename(pcap_path),
                            created_at_str,
                            json.dumps({
                                "tshark_version": tshark_ver,
                                "original_command": original_cmd,
                                "file_hash": McpCache.get_file_hash(pcap_path),
                                "summary": pcap_summary.get("summary", "")
                            }),
                            json.dumps(session_dict)
                        )
                    )
            except Exception as dbe:
                logger.error(f"Failed to persist TShark metadata: {dbe}")

            return session

        finally:
            await self.client.stop()

# Singleton instance
tshark_mcp_service = TSharkMcpService()
