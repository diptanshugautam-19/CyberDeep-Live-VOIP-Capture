import sys
import os
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

pcap_path = Path("d:/cyberdeep/data/uploads/cyberdeep_live_1783513881.pcap")
if not pcap_path.exists():
    print(f"Error: PCAP file {pcap_path} does not exist.")
    sys.exit(1)

print(f"Uploading {pcap_path} (size: {pcap_path.stat().st_size} bytes) to /api/upload...")

with pcap_path.open("rb") as f:
    files = {"files": (pcap_path.name, f, "application/octet-stream")}
    response = client.post("/api/upload", files=files)

print("Status Code:", response.status_code)
if response.status_code != 200:
    print("Error:", response.text)
    sys.exit(1)

res_data = response.json()
print("Upload result keys:", list(res_data.keys()))

# Check VoIP analysis results
voip_analysis = res_data.get("voip_analysis", [])
print(f"VoIP sessions found: {len(voip_analysis)}")

for idx, call in enumerate(voip_analysis):
    print(f"\n--- VoIP Session {idx+1} ({call.get('session_id')}) ---")
    print("Caller IP:", call.get("caller"))
    print("Callee IP:", call.get("remote_peer"))
    print("Participant Public IP:", call.get("participant_public_ip"))
    print("Remote Participant IP:", call.get("remote_participant_ip"))
    print("Media Path:", call.get("media_path"))
    print("Attribution Reason:", call.get("attribution_reason"))
    print("Attribution Confidence:", call.get("attribution_confidence"))
    print("Notes:", call.get("notes"))
    
# Check correlation voip_sessions
correlation = res_data.get("correlation", {})
corr_sessions = correlation.get("voip_sessions", [])
print(f"\nCorrelated VoIP sessions: {len(corr_sessions)}")
for idx, call in enumerate(corr_sessions):
    print(f"\n--- Correlated Session {idx+1} ---")
    print("Caller IP:", call.get("caller"))
    print("Callee IP:", call.get("callee"))
    print("Participant Public IP:", call.get("participant_public_ip"))
    print("Remote Participant IP:", call.get("remote_participant_ip"))
    print("Media Path:", call.get("media_path"))
    print("Attribution Reason:", call.get("attribution_reason"))
    print("Attribution Confidence:", call.get("attribution_confidence"))
