import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis.attribution_engine import AttributionEngine

engine = AttributionEngine()
engine.ingest_sdp(
    "v=0\r\n"
    "c=IN IP4 192.168.1.50\r\n"
    "m=audio 1234 RTP/AVP 0\r\n"
    "a=candidate:1 1 udp 2130706431 192.168.1.50 1234 typ host\r\n"
    "a=candidate:2 1 udp 1694498815 198.51.100.20 3478 typ relay\r\n"
)
engine.ingest_parsed_logs(
    stun_packets=[{
        "message_name": "Allocate Success Response",
        "source_ip": "198.51.100.20",
        "source_port": 3478,
        "destination_ip": "192.168.1.50",
        "destination_port": 1234,
        "xor_relayed_address": {"ip": "198.51.100.20", "port": 50000},
        "use_candidate": True
    }],
    rtp_packets=[],
    sip_messages=[]
)

summary = engine.analyze()
print("ICE State:", engine.correlation.ice_state)
print("Turn Relays:", engine.correlation.turn_relays)
print("NAT Mappings:", engine.correlation.nat_mappings)
print("Selected Pairs:", engine.correlation.selected_pairs)
print("Media Path:", summary.media_path)
