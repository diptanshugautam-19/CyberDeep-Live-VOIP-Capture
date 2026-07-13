import sys
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence
from app.analysis.attribution import build_call_attribution
from app.protocols.models import VoipSession

pcap_path = Path("data/uploads/2771379d-3a49-4b0b-ac66-998d4f78553f_whatapp2.pcap")
records = [r.to_dict() for r in parse_evidence(pcap_path)]

sip_messages = [r for r in records if r.get("protocol") == "SIP"]
rtp_packets = [r for r in records if r.get("protocol") == "RTP"]
stun_packets = [r for r in records if r.get("protocol") == "STUN"]

# Create a mock VoipSession for testing
sess = VoipSession(call_id="test-session-1")
res = build_call_attribution(sess, stun_packets, rtp_packets, sip_messages)

print("Attribution results:")
print("participant_public_ip:", res.participant_public_ip)
print("remote_participant_ip:", res.remote_participant_ip)
print("participant_private_ip:", res.participant_private_ip)
print("caller.private_ip:", getattr(res.caller, "private_ip", None))
print("caller.public_ip:", getattr(res.caller, "public_ip", None))
print("callee.public_ip:", getattr(res.callee, "public_ip", None))
print("callee.relay_ip:", getattr(res.callee, "relay_ip", None))
