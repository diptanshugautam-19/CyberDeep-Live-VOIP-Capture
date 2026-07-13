import sqlite3
import json

con = sqlite3.connect("data/investigations.sqlite3")
con.row_factory = sqlite3.Row

# Get the latest investigation
row = con.execute("SELECT id, created_at, case_json FROM investigations ORDER BY created_at DESC LIMIT 1").fetchone()
if row:
    print("Latest Investigation ID:", row["id"])
    print("Created At:", row["created_at"])
    case_data = json.loads(row["case_json"])
    print("participant_private_ip:", case_data.get("participant_private_ip"))
    print("Top 4 Hosts:")
    for h in case_data.get("hosts", [])[:4]:
        print(f"  {h.get('ip')}")
else:
    print("No investigations found.")
con.close()
