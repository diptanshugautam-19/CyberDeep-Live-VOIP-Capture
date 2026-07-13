import sys
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence
from app.analysis.attribution import build_call_attribution
from app.protocols.models import VoipSession

pcap_path = Path("data/uploads/7fcd3d59-ac3c-45d0-8cf1-bf8263802463_cyberdeep_live_1783513881.pcap")
if not pcap_path.exists():
    print("PCAP does not exist")
    sys.exit(1)

records = [r.to_dict() for r in parse_evidence(pcap_path)]
print("Parsed records:", len(records))

# Filter sip, rtp, stun
sip_messages = [r for r in records if r.get("protocol") == "SIP" or (r.get("payload_kind") and "sip" in r.get("payload_kind").lower())]
rtp_packets = [r for r in records if r.get("protocol") == "RTP" or (r.get("payload_kind") and "rtp" in r.get("payload_kind").lower())]
stun_packets = [r for r in records if r.get("protocol") == "STUN" or (r.get("payload_kind") and "stun" in r.get("payload_kind").lower())]

print(f"SIP: {len(sip_messages)}, RTP: {len(rtp_packets)}, STUN: {len(stun_packets)}")

# Group by Call-ID and build session
sessions = {}
for msg in sip_messages:
    # simple extract call id
    payload = msg.get("payload_raw", "")
    if not payload:
        # maybe try payload_hex or preview
        payload = msg.get("payload_preview", "")
    call_id = None
    for line in payload.split("\n"):
        if line.lower().startswith("call-id:"):
            call_id = line.split(":", 1)[1].strip()
            break
    if call_id:
        if call_id not in sessions:
            sessions[call_id] = VoipSession(call_id=call_id)
        # Add details
        sessions[call_id].caller_ip = msg.get("source_ip")
        sessions[call_id].callee_ip = msg.get("destination_ip")

print("VoIP Sessions found:", list(sessions.keys()))

for cid, sess in sessions.items():
    res = build_call_attribution(sess, stun_packets, rtp_packets, sip_messages)
    print(f"\n--- Call {cid} Attribution ---")
    print("participant_public_ip:", res.participant_public_ip)
    print("remote_participant_ip:", res.remote_participant_ip)
    print("participant_private_ip:", res.participant_private_ip)
    print("caller.private_ip:", getattr(res.caller, "private_ip", None))
    print("caller.public_ip:", getattr(res.caller, "public_ip", None))
    print("callee.public_ip:", getattr(res.callee, "public_ip", None))
    print("callee.relay_ip:", getattr(res.callee, "relay_ip", None))
