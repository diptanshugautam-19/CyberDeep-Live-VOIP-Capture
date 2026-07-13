import sys
from pathlib import Path
import ipaddress

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence
from app.analysis.attribution_engine import _is_private_ip

pcap_path = Path("data/uploads/2771379d-3a49-4b0b-ac66-998d4f78553f_whatapp2.pcap")
records = [r.to_dict() for r in parse_evidence(pcap_path)]

# Group sessions by caller/callee
sessions = []
seen = set()
for r in records:
    if r.get("protocol") in ("RTP", "SRTP", "STUN", "TURN"):
        src = r.get("source_ip")
        dst = r.get("destination_ip")
        if src and dst:
            key = tuple(sorted([src, dst]))
            if key not in seen:
                seen.add(key)
                sessions.append({"caller": src, "callee": dst})

print(f"Unique IP pairs: {len(sessions)}")
for s in sessions:
    caller = s["caller"]
    callee = s["callee"]
    
    # Apply fallback logic
    pvt_ip = "Not Observable"
    pub_ip = "Not Observable"
    
    caller_private = _is_private_ip(caller)
    callee_private = _is_private_ip(callee)
    
    if not caller_private and callee_private:
        pub_ip = caller
        pvt_ip = callee
    elif caller_private and not callee_private:
        pub_ip = callee
        pvt_ip = caller
        
    print(f"Pair: {caller} <-> {callee}")
    print(f"  Fallback -> Public: {pub_ip} | Private: {pvt_ip}")
