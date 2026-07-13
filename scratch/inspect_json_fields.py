import sqlite3
import json

db_path = "data/investigations.sqlite3"
con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row

row = con.execute("SELECT * FROM investigations ORDER BY created_at DESC LIMIT 1").fetchone()
if row:
    print("=== Summary JSON keys ===")
    try:
        summary = json.loads(row["summary_json"])
        print(list(summary.keys()))
        for k in ["participant_public_ip", "remote_participant_ip", "participant_private_ip"]:
            print(f"  {k}: {summary.get(k)}")
    except Exception as e:
        print("Error:", e)

    print("\n=== Case JSON keys ===")
    try:
        case_data = json.loads(row["case_json"])
        print(list(case_data.keys()))
        for k in ["participant_public_ip", "remote_participant_ip", "participant_private_ip", "participant_isp", "participant_city", "participant_country"]:
            print(f"  {k}: {case_data.get(k)}")
        
        print("\nVoIP Sessions in Case JSON:")
        for s in case_data.get("correlation", {}).get("voip_sessions", []):
            print("  Session details:")
            for k in ["caller", "callee", "participant_public_ip", "remote_participant_ip", "participant_private_ip", "participant_isp", "participant_city", "participant_country"]:
                print(f"    {k}: {s.get(k)}")
        
        print("\nTop 4 Rows in Case JSON:")
        for r in case_data.get("rows", [])[:4]:
            print(f"  Destination IP: {r.get('destination_ip')} | Service: {r.get('service')} | Threat: {r.get('threat_level')}")
    except Exception as e:
        print("Error:", e)

con.close()
