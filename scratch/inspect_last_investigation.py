import sqlite3
import json

db_path = "data/investigations.sqlite3"
con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row

# Get last investigation
row = con.execute("SELECT * FROM investigations ORDER BY created_at DESC LIMIT 1").fetchone()
if row:
    print("=== Last Investigation ===")
    print("ID:", row["id"])
    print("Filename:", row["filename"])
    print("Created At:", row["created_at"])
    
    # The data is probably stored as JSON in analysis_result or similar column
    # Let's inspect the columns
    print("\nColumns:", row.keys())
    for col in ["participant_public_ip", "remote_participant_ip", "participant_private_ip", "participant_isp", "participant_city", "participant_country"]:
        if col in row.keys():
            print(f"{col}: {row[col]}")
            
    # If there is a results or data column, let's print keys
    for col in ["analysis_result", "data", "results", "result"]:
        if col in row.keys() and row[col]:
            try:
                data = json.loads(row[col])
                print(f"\n{col} keys:", list(data.keys()))
                print(f"participant_public_ip in {col}:", data.get("participant_public_ip"))
                print(f"participant_private_ip in {col}:", data.get("participant_private_ip"))
                print(f"remote_participant_ip in {col}:", data.get("remote_participant_ip"))
                print("VoIP Sessions:")
                for s in data.get("correlation", {}).get("voip_sessions", []):
                    print("  Session caller/callee/pvt:", s.get("caller"), s.get("callee"), s.get("participant_private_ip"), s.get("participant_public_ip"))
                print("Top 4 Hosts:")
                for h in data.get("rows", [])[:4]:
                    print("  Host destination_ip:", h.get("destination_ip"))
            except Exception as e:
                print(f"Error parsing {col}: {e}")
else:
    print("No investigations found")

con.close()
