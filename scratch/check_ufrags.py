import sys
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence

pcap_path = Path("data/uploads/0b011a5c-3b41-4ba1-b9fb-dd089efc6d3b_83f93bca-2555-4716-b674-1f8fe04ccf7f_cyberdeep_live_1783513881.pcap")
records = [r.to_dict() for r in parse_evidence(pcap_path)]

stun_ufrags = set()
sip_ufrags = set()

for r in records:
    fields = r.get("decoded_fields") or {}
    if r.get("protocol") == "STUN":
        remote = fields.get("remote_ufrag")
        local = fields.get("local_ufrag")
        if remote: stun_ufrags.add(remote)
        if local: stun_ufrags.add(local)
    elif r.get("protocol") == "SIP":
        ufrag = fields.get("ice_ufrag")
        if ufrag: sip_ufrags.add(ufrag)
        for c in fields.get("sdp_candidates") or []:
            if c.get("ufrag"):
                sip_ufrags.add(c["ufrag"])

print("STUN ufrags:", stun_ufrags)
print("SIP ufrags:", sip_ufrags)
print("Intersection:", stun_ufrags & sip_ufrags)
