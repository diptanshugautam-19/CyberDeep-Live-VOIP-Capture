import requests
from pathlib import Path

path = Path("data/uploads/0b011a5c-3b41-4ba1-b9fb-dd089efc6d3b_83f93bca-2555-4716-b674-1f8fe04ccf7f_cyberdeep_live_1783513881.pcap")
print("Path exists:", path.exists())

files = {'files': open(path, 'rb')}
r = requests.post("http://127.0.0.1:8000/api/upload", files=files)
data = r.json()

print("Root participant_public_ip:", data.get("participant_public_ip"))
print("Root participant_isp:", data.get("participant_isp"))
print("Root participant_city:", data.get("participant_city"))
print("Root participant_country:", data.get("participant_country"))

print("\nAll voip sessions:")
for s in data.get("correlation", {}).get("voip_sessions", []):
    print(f"Session {s.get('session_id')}:")
    print(f"  Caller: {s.get('caller')}")
    print(f"  Callee: {s.get('callee')}")
    print(f"  Participant IP: {s.get('participant_public_ip')}")
    print(f"  ISP: {s.get('participant_isp')}")
    print(f"  City: {s.get('participant_city')}")
    print(f"  Country: {s.get('participant_country')}")
