import sys
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence

pcap_path = Path("data/uploads/0b011a5c-3b41-4ba1-b9fb-dd089efc6d3b_83f93bca-2555-4716-b674-1f8fe04ccf7f_cyberdeep_live_1783513881.pcap")
records = [r.to_dict() for r in parse_evidence(pcap_path)]

ips = set()
for r in records:
    if r.get("source_ip"): ips.add(r["source_ip"])
    if r.get("destination_ip"): ips.add(r["destination_ip"])

print("IPs present in PCAP:", ips)
print("Is 203.0.113.10 in PCAP?", "203.0.113.10" in ips)
