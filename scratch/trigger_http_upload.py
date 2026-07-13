import sys
from pathlib import Path
import requests

pcap_path = Path("data/uploads/1ca17dc2-99df-4e8b-a0b3-9606a541f3c5_2771379d-3a49-4b0b-ac66-998d4f78553f_whatapp2.pcap")
if not pcap_path.exists():
    print(f"Error: {pcap_path} does not exist")
    sys.exit(1)

url = "http://127.0.0.1:8000/api/upload"
print(f"Uploading {pcap_path.name} to {url}...")
with pcap_path.open("rb") as f:
    files = {"files": (pcap_path.name, f, "application/octet-stream")}
    response = requests.post(url, files=files)

print("Status Code:", response.status_code)
if response.status_code == 200:
    res_data = response.json()
    print("participant_public_ip:", res_data.get("participant_public_ip"))
    print("participant_private_ip:", res_data.get("participant_private_ip"))
    print("remote_participant_ip:", res_data.get("remote_participant_ip"))
    print("VoIP Sessions found:", len(res_data.get("correlation", {}).get("voip_sessions", [])))
    for s in res_data.get("correlation", {}).get("voip_sessions", []):
        if s.get("participant_private_ip") != "Not Observable":
            print(f"  Session: caller={s.get('caller')}, callee={s.get('callee')}, participant_pvt={s.get('participant_private_ip')}, participant_pub={s.get('participant_pub')}")
else:
    print("Response:", response.text)
