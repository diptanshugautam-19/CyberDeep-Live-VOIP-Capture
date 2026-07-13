from typing import Dict, Any, List
from app.integrations.tshark_mcp.models import SIPCall, RTPSession, ICESession, TURNAllocation, STUNTransaction, Endpoint, Conversation, Packet

def parse_sip_calls(raw_calls: List[Dict[str, Any]]) -> List[SIPCall]:
    parsed = []
    for call in raw_calls:
        parsed.append(SIPCall(
            call_id=call.get("call_id", ""),
            caller=call.get("caller", ""),
            callee=call.get("callee", ""),
            status=call.get("status", ""),
            start_time=0.0,  # We can parse start time if needed
            end_time=None,
            packets_count=0
        ))
    return parsed

def parse_rtp_streams(raw_streams: List[Dict[str, Any]]) -> List[RTPSession]:
    parsed = []
    for stream in raw_streams:
        parsed.append(RTPSession(
            ssrc=stream.get("ssrc", ""),
            source_ip=stream.get("source_ip", ""),
            dest_ip=stream.get("dest_ip", ""),
            source_port=stream.get("source_port", 0),
            dest_port=stream.get("dest_port", 0),
            packet_count=stream.get("packet_count", 0),
            lost_packets=stream.get("lost_packets", 0),
            jitter=stream.get("jitter", 0.0),
            duration=0.0
        ))
    return parsed
