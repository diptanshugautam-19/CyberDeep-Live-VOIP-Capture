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
    "a=candidate:2 1 udp 1694498815 203.0.113.10 5678 typ srflx\r\n"
)
engine.ingest_parsed_logs(
    stun_packets=[],
    rtp_packets=[{
        "ssrc": 12345,
        "payload_type": 0,
        "source_ip": "203.0.113.10",
        "source_port": 5678,
        "destination_ip": "192.168.1.50",
        "destination_port": 1234,
        "timestamp": 1.0
    }],
    sip_messages=[]
)
summary = engine.analyze()
print("Local IPs:", engine.local_ips)
print("RTP Streams:", engine.rtp_parser.streams)
if engine.rtp_parser.streams:
    stream = engine.rtp_parser.streams[12345]
    print("Stream SSRC:", stream.ssrc)
    print("Stream Source IPs:", stream.source_ips)
    print("Stream Dest IPs:", stream.dest_ips)
    
print("Stream Attributions:")
for ssrc, attr in engine._stream_attributions.items():
    print(f"  SSRC {ssrc}: remote_ip={attr.remote_ip}, remote_observable={attr.remote_observable}, media_path={attr.media_path}")

print("Summary Remote IP:", summary.remote_ip)
print("Summary Confidence:", summary.confidence)
print("Summary Media Path:", summary.media_path)
print("Summary Reason:", summary.reason)
