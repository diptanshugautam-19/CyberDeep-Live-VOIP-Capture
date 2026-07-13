import sqlite3
import json

con = sqlite3.connect("data/investigations.sqlite3")
con.row_factory = sqlite3.Row

row = con.execute("SELECT id, case_json FROM investigations WHERE id = 'cdfadd48-8b02-4b0d-956b-1141b7a0d7a9'").fetchone()
if row:
    case_data = json.loads(row["case_json"])
    print("participant_private_ip:", case_data.get("participant_private_ip"))
    voip_sessions = case_data.get("correlation", {}).get("voip_sessions", [])
    print("VoIP Sessions count:", len(voip_sessions))
    for idx, s in enumerate(voip_sessions[:5]):
        print(f"  Session {idx}: caller={s.get('caller')}, callee={s.get('callee')}, participant_pvt={s.get('participant_private_ip')}, participant_pub={s.get('participant_public_ip')}")
con.close()
