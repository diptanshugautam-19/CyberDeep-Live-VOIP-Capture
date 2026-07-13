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

# Populate local_ips
for p in stun_packets + rtp_packets:
    src = p.get("source_ip")
    dst = p.get("destination_ip")
    if src and _is_private_ip(src):
        engine.local_ips.add(src)
    if dst and _is_private_ip(dst):
        engine.local_ips.add(dst)

# Ingest
engine.ingest_parsed_logs(stun_packets, rtp_packets, sip_messages)
engine.correlation.finalize_ice_state()

print("NAT mappings:", engine.correlation.nat_mappings)
print("Selected pairs:", engine.correlation.selected_pairs)
print("TURN relays:", engine.correlation.turn_relays)
print("ICE state:", engine.correlation.ice_state)
print("Signaling servers:", engine.correlation.signaling_servers)
print("RTP streams:", len(engine.rtp_parser.get_all_streams()))
for s in engine.rtp_parser.get_all_streams():
    print(f"  SSRC {s.ssrc_hex}: PT={s.payload_type}, Src={s.source_ips}, Dst={s.dest_ips}")
