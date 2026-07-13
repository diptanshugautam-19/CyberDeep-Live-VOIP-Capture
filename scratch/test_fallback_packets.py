import sys
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence
from app.analysis.attribution_engine import _is_private_ip

pcap_path = Path("data/uploads/2771379d-3a49-4b0b-ac66-998d4f78553f_whatapp2.pcap")
records = [r.to_dict() for r in parse_evidence(pcap_path)]

sip_messages = [r for r in records if r.get("protocol") == "SIP"]
rtp_packets = [r for r in records if r.get("protocol") == "RTP"]
stun_packets = [r for r in records if r.get("protocol") == "STUN"]

# Collect all IPs
all_ips = set()
for p in stun_packets + rtp_packets + sip_messages:
    src = p.get("source_ip")
    dst = p.get("destination_ip")
    if src: all_ips.add(src)
    if dst: all_ips.add(dst)

pvt_ips = [ip for ip in all_ips if _is_private_ip(ip)]
print("All IPs:", all_ips)
print("Private IPs:", pvt_ips)
