import sys
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers.manager import parse_evidence

uploads_dir = Path("data/uploads")
for f in uploads_dir.iterdir():
    if f.suffix.lower() in [".pcap", ".pcapng"]:
        try:
            records = [r.to_dict() for r in parse_evidence(f)]
            sip_count = sum(1 for r in records if r.get("protocol") == "SIP")
            stun_count = sum(1 for r in records if r.get("protocol") == "STUN")
            rtp_count = sum(1 for r in records if r.get("protocol") == "RTP")
            print(f"File: {f.name} (size: {f.stat().st_size} bytes)")
            print(f"  SIP: {sip_count}, STUN: {stun_count}, RTP: {rtp_count}, Total: {len(records)}")
        except Exception as e:
            print(f"File: {f.name} - Error: {e}")
