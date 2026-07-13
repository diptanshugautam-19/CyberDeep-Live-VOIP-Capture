import sys
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence

pcap_path = Path("data/uploads/7fcd3d59-ac3c-45d0-8cf1-bf8263802463_cyberdeep_live_1783513881.pcap")
records = [r.to_dict() for r in parse_evidence(pcap_path)]

print("Total parsed records:", len(records))
protocols = {}
for r in records:
    proto = r.get("protocol")
    protocols[proto] = protocols.get(proto, 0) + 1

print("Protocols in PCAP:", protocols)

print("\nSample records:")
for r in records[:5]:
    print(r)
