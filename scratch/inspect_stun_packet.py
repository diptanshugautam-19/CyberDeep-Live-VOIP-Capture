import sys
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence

pcap_path = Path("data/uploads/2771379d-3a49-4b0b-ac66-998d4f78553f_whatapp2.pcap")
records = [r.to_dict() for r in parse_evidence(pcap_path)]

stun_packets = [r for r in records if r.get("protocol") == "STUN"]
print("STUN packets count:", len(stun_packets))
if stun_packets:
    print("STUN keys:", list(stun_packets[0].keys()))
    print("First STUN packet details:")
    import pprint
    pprint.pprint(stun_packets[0])
