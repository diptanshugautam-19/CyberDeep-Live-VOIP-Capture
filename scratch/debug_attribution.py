import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence
from app.analysis.attribution_engine import AttributionEngine

pcap_path = Path("data/uploads/2771379d-3a49-4b0b-ac66-998d4f78553f_whatapp2.pcap")
records = [r.to_dict() for r in parse_evidence(pcap_path)]

# Let's filter packets
stun_packets = []
rtp_packets = []
sip_messages = []

for r in records:
    proto = r.get("protocol", "").upper()
    # Check if there is payload_kind or raw_connections/packet_details
    # Wait, parse_evidence returns a list of ConnectionRecords or PacketRecords?
    # Let's see what attributes it has
    if proto == "SIP":
        sip_messages.append(r)
    elif proto == "RTP":
        rtp_packets.append(r)
    elif proto == "STUN":
        stun_packets.append(r)

print(f"STUN count: {len(stun_packets)}, RTP count: {len(rtp_packets)}, SIP count: {len(sip_messages)}")

# Let's check the fields of STUN/RTP packets
if stun_packets:
    print("STUN keys:", stun_packets[0].keys())
    # print some stun records
    for idx, s in enumerate(stun_packets[:3]):
        print(f"STUN {idx}: src={s.get('source_ip')}:{s.get('source_port')}, dst={s.get('destination_ip')}:{s.get('destination_port')}, preview={s.get('payload_preview')}")

# Instantiate AttributionEngine
engine = AttributionEngine()
# Wait, what arguments does ingest_parsed_logs expect?
# Let's check attribution_engine.py
# Let's read lines 500-550 in app/analysis/attribution_engine.py
