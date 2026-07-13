import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis.attribution_engine import AttributionEngine, IpClassification, _is_private_ip

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

stream = engine.rtp_parser.streams[12345]

nat_ips = set()
for local_ip, (public_ip, _) in engine.correlation.nat_mappings.items():
    nat_ips.add(public_ip)

print("nat_ips:", nat_ips)

remote_candidates = []
for ip in stream.source_ips:
    if ip in nat_ips:
        print(f"IP {ip} is in nat_ips")
        continue
    cls = engine.infra_classifier.classify(ip)
    print(f"IP {ip} classification: {cls}")
    if cls in (IpClassification.UNKNOWN, IpClassification.REMOTE_PARTICIPANT):
        is_priv = _is_private_ip(ip)
        print(f"IP {ip} is_private: {is_priv}")
        if not is_priv:
            remote_candidates.append(ip)

print("remote_candidates:", remote_candidates)
