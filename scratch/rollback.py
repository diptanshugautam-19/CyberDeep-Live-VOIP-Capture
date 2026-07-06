import os
from pathlib import Path

def rollback():
    print("=== Reversing 10-Database Redesign (Rollback) ===")
    
    # Define files and folders
    data_dir = Path("data")
    packets_dir = data_dir / "packets"
    payloads_dir = data_dir / "payloads"
    live_capture_dir = data_dir / "live_capture"
    
    # 1. Back up/Remove the new 10 specialized databases
    new_dbs = [
        "investigations.sqlite3", "packets.sqlite3", "payloads.sqlite3",
        "live_capture.sqlite3", "telecom.sqlite3", "geoip.sqlite3",
        "threatintel.sqlite3", "dns.sqlite3", "users.sqlite3", "cache.sqlite3",
        "flows.sqlite3"
    ]
    
    backup_dir = data_dir / "new_db_backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    print("\n[1/3] Backing up and removing new specialized databases...")
    for db_name in new_dbs:
        db_path = data_dir / db_name
        if db_path.is_file():
            try:
                dest = backup_dir / db_name
                if dest.is_file():
                    dest.unlink()
                db_path.rename(dest)
                print(f"  Moved new {db_name} to {backup_dir.name}/")
            except Exception as e:
                print(f"  Warning: could not backup/remove new {db_name}: {e}")

    # 2. Restore monolithic databases
    print("\n[2/3] Restoring original monolithic databases...")
    monolithic_backups = {
        "ip_intel.sqlite3.old": "ip_intel.sqlite3",
        "sessions.sqlite3.old": "sessions.sqlite3",
        "alerts.sqlite3.old": "alerts.sqlite3"
    }
    
    for old_name, new_name in monolithic_backups.items():
        old_path = data_dir / old_name
        new_path = data_dir / new_name
        if old_path.is_file():
            try:
                if new_path.is_file():
                    new_path.unlink()
                old_path.rename(new_path)
                print(f"  Restored {old_name} -> {new_name}")
            except Exception as e:
                print(f"  Error restoring {old_name}: {e}")
        else:
            print(f"  Backup not found: {old_name}")

    # 3. Restore monthly partitioned files
    print("\n[3/3] Restoring monthly partition database files...")
    
    for folder in [packets_dir, payloads_dir, live_capture_dir]:
        if folder.is_dir():
            for f in folder.glob("*.sqlite3.old"):
                new_f = f.with_suffix("") # Strip .old
                try:
                    if new_f.is_file():
                        new_f.unlink()
                    f.rename(new_f)
                    print(f"  Restored {folder.name}/{f.name} -> {new_f.name}")
                except Exception as e:
                    print(f"  Error restoring {folder.name}/{f.name}: {e}")

    print("\nRollback complete. Original databases and partitions restored.")

if __name__ == "__main__":
    rollback()
