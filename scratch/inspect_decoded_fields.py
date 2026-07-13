import sys
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence

pcap_path = Path("data/uploads/2771379d-3a49-4b0b-ac66-998d4f78553f_whatapp2.pcap")
records = [r.to_dict() for r in parse_evidence(pcap_path)]

stun_packets = []
for r in records:
    for p in r.get("packet_details", []):
        if p.get("protocol") == "STUN":
            stun_packets.append(p)

print("Total STUN packets in packet_details:", len(stun_packets))
if stun_packets:
    for idx, p in enumerate(stun_packets):
        fields = p.get("decoded_fields") or {}
        print(f"STUN {idx}: message_name='{fields.get('message_name')}'")
        print(f"  Keys in fields: {list(fields.keys())}")
        for k, v in fields.items():
            if 'address' in k or 'ufrag' in k:
                print(f"  {k}: {v}")
