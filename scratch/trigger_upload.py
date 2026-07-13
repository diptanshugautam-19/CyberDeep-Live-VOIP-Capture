import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import app

client = TestClient(app)

pcap_path = Path("data/uploads/2771379d-3a49-4b0b-ac66-998d4f78553f_whatapp2.pcap")
if not pcap_path.exists():
    print(f"Error: {pcap_path} does not exist")
    sys.exit(1)

print(f"Uploading {pcap_path.name}...")
with pcap_path.open("rb") as f:
    files = {"files": (pcap_path.name, f, "application/octet-stream")}
    response = client.post("/api/upload", files=files)

print("Status Code:", response.status_code)
if response.status_code == 200:
    res_data = response.json()
    print("participant_public_ip:", res_data.get("participant_public_ip"))
    print("participant_private_ip:", res_data.get("participant_private_ip"))
    print("remote_participant_ip:", res_data.get("remote_participant_ip"))
    print("VoIP Sessions found:", len(res_data.get("correlation", {}).get("voip_sessions", [])))
    for s in res_data.get("correlation", {}).get("voip_sessions", []):
        print(f"  Session: caller={s.get('caller')}, callee={s.get('callee')}, participant_pvt={s.get('participant_private_ip')}, participant_pub={s.get('participant_public_ip')}")
else:
    print("Response:", response.text)
