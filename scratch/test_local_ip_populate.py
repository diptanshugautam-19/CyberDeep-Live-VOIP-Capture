import sys
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence
from app.analysis.attribution_engine import AttributionEngine, _is_private_ip

pcap_path = Path("data/uploads/2771379d-3a49-4b0b-ac66-998d4f78553f_whatapp2.pcap")
records = [r.to_dict() for r in parse_evidence(pcap_path)]

sip_messages = [r for r in records if r.get("protocol") == "SIP"]
rtp_packets = [r for r in records if r.get("protocol") == "RTP"]
stun_packets = [r for r in records if r.get("protocol") == "STUN"]

engine = AttributionEngine()

# Populate local_ips with private IPs from packets
for p in stun_packets + rtp_packets:
    src = p.get("source_ip")
    dst = p.get("destination_ip")
    if src and _is_private_ip(src):
        engine.local_ips.add(src)
    if dst and _is_private_ip(dst):
        engine.local_ips.add(dst)

print("Local IPs populated:", engine.local_ips)

# Ingest packets
engine.ingest_parsed_logs(stun_packets, rtp_packets, sip_messages)
summary = engine.analyze()

print("\nAttribution results after populating local_ips:")
print("private_ip:", summary.private_ip)
print("public_nat:", summary.public_nat)
print("remote_ip:", summary.remote_ip)
print("media_path:", summary.media_path)
print("confidence:", summary.confidence)
print("reason:", summary.reason)
