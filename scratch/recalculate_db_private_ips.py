import sys
from pathlib import Path
import sqlite3
import json

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis.attribution_engine import _is_private_ip

db_path = "data/investigations.sqlite3"
if not Path(db_path).exists():
    print("Database does not exist")
    sys.exit(1)

con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row

# Get all investigations
rows = con.execute("SELECT id, summary_json, case_json FROM investigations").fetchall()
print(f"Total investigations in database: {len(rows)}")

updated_count = 0

for row in rows:
    row_id = row["id"]
    try:
        case_json = row["case_json"]
        if not case_json:
            continue
            
        case_data = json.loads(case_json)
        
        # Check if participant_private_ip is "Not Observable"
        curr_pvt = case_data.get("participant_private_ip")
        if curr_pvt == "Not Observable" or not curr_pvt:
            # Let's find a private IP from voip_sessions or hosts
            pvt_ip = None
            
            # Look at voip_sessions
            voip_sessions = case_data.get("correlation", {}).get("voip_sessions", [])
            for s in voip_sessions:
                caller = s.get("caller")
                callee = s.get("callee")
                
                # Extract clean IP (ignoring port or IPv6 brackets)
                for ip in [caller, callee]:
                    if not ip or ip == "Unknown" or ip == "Not Observable":
                        continue
                    clean_ip = ip.split(":", 1)[0].replace("[", "").replace("]", "").strip()
                    if _is_private_ip(clean_ip):
                        pvt_ip = clean_ip
                        break
                if pvt_ip:
                    break
                    
            if not pvt_ip:
                # Look at hosts
                for h in case_data.get("hosts", []):
                    ip = h.get("ip")
                    if ip and _is_private_ip(ip):
                        pvt_ip = ip
                        break
                        
            if pvt_ip:
                print(f"Updating investigation {row_id}: setting private IP to {pvt_ip}")
                
                # Update case_data
                case_data["participant_private_ip"] = pvt_ip
                
                # Update voip_sessions inside case_data
                if "correlation" in case_data and "voip_sessions" in case_data["correlation"]:
                    for s in case_data["correlation"]["voip_sessions"]:
                        if s.get("participant_private_ip") == "Not Observable" or not s.get("participant_private_ip"):
                            s["participant_private_ip"] = pvt_ip
                            
                # Update voip_analysis list
                if "voip_analysis" in case_data:
                    for s in case_data["voip_analysis"]:
                        if s.get("participant_private_ip") == "Not Observable" or not s.get("participant_private_ip"):
                            s["participant_private_ip"] = pvt_ip
                            
                # Save back to DB
                con.execute(
                    "UPDATE investigations SET case_json = ? WHERE id = ?",
                    (json.dumps(case_data), row_id)
                )
                updated_count += 1
    except Exception as e:
        print(f"Error processing row {row_id}: {e}")

con.commit()
con.close()
print(f"Successfully updated {updated_count} investigations in database.")
