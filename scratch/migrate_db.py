import sys
import os
import json
import sqlite3
from pathlib import Path

# Ensure app is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.storage.database import get_db_path, get_connection, SCHEMA_SQL

def migrate():
    source_db = Path("data") / "ip_intel.sqlite3"
    if not source_db.is_file():
        print(f"Source database {source_db} not found. Nothing to migrate.")
        return

    print(f"Starting database split migration from: {source_db}")
    print(f"Source file size: {os.path.getsize(source_db) / 1024 / 1024:.1f} MB")
    
    # 1. Connect to source
    src_conn = sqlite3.connect(source_db)
    src_conn.row_factory = sqlite3.Row
    
    # Fetch all investigations
    investigations = src_conn.execute("SELECT * FROM investigations").fetchall()
    print(f"Found {len(investigations)} investigations to migrate.")
    
    # 2. Iterate and split
    migrated_count = 0
    for idx, inv in enumerate(investigations):
        inv_id = inv["id"]
        filename = inv["filename"]
        created_at = inv["created_at"]
        summary_json = inv["summary_json"]
        case_json = inv["case_json"]
        
        # Load case data to check structure
        analysis = {}
        if case_json:
            try:
                analysis = json.loads(case_json)
            except Exception:
                pass
        
        # Determine target database path
        target_db = get_db_path(filename, analysis)
        print(f"[{idx+1}/{len(investigations)}] Migrating '{filename}' -> {target_db.name}")
        
        # Initialize schema in target database
        target_db.parent.mkdir(parents=True, exist_ok=True)
        with get_connection(target_db) as conn:
            conn.executescript(SCHEMA_SQL)
            # Ensure case_json column exists
            columns = [row["name"] for row in conn.execute("PRAGMA table_info(investigations)").fetchall()]
            if "case_json" not in columns:
                conn.execute("ALTER TABLE investigations ADD COLUMN case_json TEXT")
                
        # Write to target database
        with get_connection(target_db) as tgt_conn:
            # Check if already exists in target
            exists = tgt_conn.execute("SELECT 1 FROM investigations WHERE id = ?", (inv_id,)).fetchone()
            if not exists:
                tgt_conn.execute(
                    "INSERT INTO investigations (id, filename, created_at, summary_json, case_json) VALUES (?, ?, ?, ?, ?)",
                    (inv_id, filename, created_at, summary_json, case_json)
                )
                
                # Fetch and copy destinations for this investigation
                dest_rows = src_conn.execute("SELECT * FROM destinations WHERE investigation_id = ?", (inv_id,)).fetchall()
                tgt_conn.executemany(
                    "INSERT INTO destinations (investigation_id, destination_ip, row_json) VALUES (?, ?, ?)",
                    [(d["investigation_id"], d["destination_ip"], d["row_json"]) for d in dest_rows]
                )
                migrated_count += 1
                
    src_conn.close()
    print(f"\nMigration copy completed successfully. {migrated_count} records copied.")
    
    # 3. Vacuum and optimize new databases to ensure minimal disk space
    print("\nRunning VACUUM optimization on new databases...")
    for context in ["network", "telecom", "live_capture"]:
        db_path = get_db_path(context)
        if db_path.is_file():
            print(f"  Optimizing {db_path.name}...")
            try:
                conn = sqlite3.connect(db_path)
                conn.execute("VACUUM")
                conn.close()
                print(f"  Optimized {db_path.name}: {os.path.getsize(db_path) / 1024 / 1024:.1f} MB")
            except Exception as e:
                print(f"  Failed to optimize {db_path.name}: {e}")

    print("\nMigration finished successfully!")

if __name__ == "__main__":
    migrate()
