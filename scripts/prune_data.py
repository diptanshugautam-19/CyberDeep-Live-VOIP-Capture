#!/usr/bin/env python3
import sys
import os
import sqlite3
from datetime import datetime, timedelta, timezone

# Add project root to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.storage.database import (
    PACKETS_DB_PATH, PAYLOADS_DB_PATH, LIVE_CAPTURE_DB_PATH, FLOWS_DB_PATH
)

def prune_database(db_path, tables, cutoff_time, time_column="timestamp", dry_run=False):
    if not db_path.is_file():
        return
    
    print(f"[{db_path.name}] Pruning data older than {cutoff_time}...")
    try:
        conn = sqlite3.connect(db_path)
        for table in tables:
            # First count how many would be deleted
            count_query = f"SELECT COUNT(*) FROM {table} WHERE {time_column} < ?"
            count = conn.execute(count_query, (cutoff_time,)).fetchone()[0]
            
            print(f"  {table}: {count} rows identified for pruning.")
            
            if not dry_run and count > 0:
                delete_query = f"DELETE FROM {table} WHERE {time_column} < ?"
                conn.execute(delete_query, (cutoff_time,))
                conn.commit()
                print(f"  {table}: Successfully deleted {count} rows.")
        
        if not dry_run:
            print(f"  Running VACUUM to reclaim space...")
            conn.execute("VACUUM")
            conn.execute("ANALYZE")
            conn.execute("PRAGMA optimize")
        
    except Exception as e:
        print(f"  Error pruning {db_path.name}: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CyberDEEP Data Retention & Pruning Engine")
    parser.add_argument("--days", type=int, default=30, help="Number of days to retain (default: 30)")
    parser.add_argument("--dry-run", action="store_true", help="Calculate what would be deleted without actually deleting")
    args = parser.parse_args()

    cutoff = (datetime.now(timezone.utc) - timedelta(days=args.days)).isoformat()
    
    print(f"CyberDEEP Pruning Engine")
    print(f"Retention Policy: {args.days} days")
    print(f"Cutoff Timestamp: {cutoff}")
    if args.dry_run:
        print("MODE: DRY RUN (No data will be deleted)")
    print("=" * 50)
    
    prune_database(PACKETS_DB_PATH, ["packets"], cutoff, dry_run=args.dry_run)
    prune_database(LIVE_CAPTURE_DB_PATH, ["live_capture_packets"], cutoff, dry_run=args.dry_run)
    prune_database(FLOWS_DB_PATH, ["sessions"], cutoff, time_column="start_time", dry_run=args.dry_run)
    
    print("=" * 50)
    print("Pruning complete.")
