import sqlite3
import sys
import os
import json
import hashlib
from pathlib import Path

# Ensure app is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.storage.database import (
    INVESTIGATIONS_DB_PATH, PACKETS_DB_PATH, PAYLOADS_DB_PATH,
    LIVE_CAPTURE_DB_PATH, TELECOM_DB_PATH, GEOIP_DB_PATH,
    THREATINTEL_DB_PATH, DNS_DB_PATH, USERS_DB_PATH, CACHE_DB_PATH,
    FLOWS_DB_PATH, get_investigation, decompress_bytes
)

def check_integrity():
    dbs = {
        "investigations": INVESTIGATIONS_DB_PATH,
        "packets": PACKETS_DB_PATH,
        "payloads": PAYLOADS_DB_PATH,
        "live_capture": LIVE_CAPTURE_DB_PATH,
        "telecom": TELECOM_DB_PATH,
        "geoip": GEOIP_DB_PATH,
        "threatintel": THREATINTEL_DB_PATH,
        "dns": DNS_DB_PATH,
        "users": USERS_DB_PATH,
        "cache": CACHE_DB_PATH,
        "flows": FLOWS_DB_PATH
    }

    print("=== CyberDeep Storage Integrity Checker ===")
    
    # 1. PRAGMA integrity_check
    print("\n[1/4] Running SQLite PRAGMA integrity_check...")
    all_ok = True
    for name, path in dbs.items():
        if not path.is_file():
            print(f"  {name:<15}: Warning: File not found ({path})")
            all_ok = False
            continue
        try:
            with sqlite3.connect(path) as conn:
                res = conn.execute("PRAGMA integrity_check").fetchone()[0]
                print(f"  {name:<15}: {res}")
                if res != "ok":
                    all_ok = False
        except Exception as e:
            print(f"  {name:<15}: Error running integrity_check: {e}")
            all_ok = False
            
    # 2. Structural & Referential Checks
    print("\n[2/4] Running database referential and constraint checks...")
    
    if not INVESTIGATIONS_DB_PATH.is_file():
        print("  Error: investigations.sqlite3 not found. Skipping remaining checks.")
        sys.exit(1)
        
    # Load all investigation IDs
    with sqlite3.connect(INVESTIGATIONS_DB_PATH) as conn:
        inv_ids = {r[0] for r in conn.execute("SELECT id FROM investigations").fetchall()}
        
    print(f"  Loaded {len(inv_ids)} valid investigation IDs from investigations.sqlite3")
    
    # Check destinations
    with sqlite3.connect(INVESTIGATIONS_DB_PATH) as conn:
        # Orphan destinations
        orphans = conn.execute("SELECT COUNT(*) FROM destinations WHERE investigation_id NOT IN (SELECT id FROM investigations)").fetchone()[0]
        if orphans > 0:
            print(f"  [FAIL] destinations: Found {orphans} orphan destinations.")
            all_ok = False
        else:
            print("  [PASS] destinations: No orphan destinations found.")
            
        # Duplicate destinations per investigation
        dupes = conn.execute(
            "SELECT COUNT(*) FROM (SELECT investigation_id, destination_ip FROM destinations GROUP BY investigation_id, destination_ip HAVING COUNT(*) > 1)"
        ).fetchone()[0]
        if dupes > 0:
            print(f"  [FAIL] destinations: Found {dupes} duplicate destination IPs in an investigation.")
            all_ok = False
        else:
            print("  [PASS] destinations: No duplicate destination IPs per case.")

    # Check packets
    if PACKETS_DB_PATH.is_file():
        with sqlite3.connect(PACKETS_DB_PATH) as conn:
            # Orphan packets
            conn.execute(f"ATTACH DATABASE '{INVESTIGATIONS_DB_PATH}' AS inv_db")
            orphans = conn.execute("SELECT COUNT(*) FROM packets WHERE investigation_id NOT IN (SELECT id FROM inv_db.investigations)").fetchone()[0]
            if orphans > 0:
                print(f"  [FAIL] packets: Found {orphans} orphan packets.")
                all_ok = False
            else:
                print("  [PASS] packets: No orphan packets found.")
                
            # All packets should have a matching payload (by packet_id FK)
            conn.execute(f"ATTACH DATABASE '{PAYLOADS_DB_PATH}' AS pay_db")
            orphans_pl = conn.execute("SELECT COUNT(*) FROM packets WHERE id NOT IN (SELECT packet_id FROM pay_db.payloads)").fetchone()[0]
            if orphans_pl > 0:
                print(f"  [FAIL] packets: Found {orphans_pl} packets with no matching payload record (by packet_id FK).")
                all_ok = False
            else:
                print("  [PASS] packets: All packets have matching payload records via packet_id FK.")

            # Invalid flow IDs (null/blank)
            invalid_flows = conn.execute("SELECT COUNT(*) FROM packets WHERE flow_id IS NULL OR flow_id = ''").fetchone()[0]
            if invalid_flows > 0:
                print(f"  [WARN] packets: Found {invalid_flows} packets with null or empty flow_id.")
            else:
                print("  [PASS] packets: All packets have valid flow_id.")

    # Check payloads
    if PAYLOADS_DB_PATH.is_file():
        with sqlite3.connect(PAYLOADS_DB_PATH) as conn:
            # Orphan payloads (no investigation)
            conn.execute(f"ATTACH DATABASE '{INVESTIGATIONS_DB_PATH}' AS inv_db")
            orphans = conn.execute("SELECT COUNT(*) FROM payloads WHERE investigation_id NOT IN (SELECT id FROM inv_db.investigations)").fetchone()[0]
            if orphans > 0:
                print(f"  [FAIL] payloads: Found {orphans} orphan payloads (no investigation).")
                all_ok = False
            else:
                print("  [PASS] payloads: No orphan payloads (no investigation) found.")
                
            # Alignment via packet_id FK
            if PACKETS_DB_PATH.is_file():
                conn.execute(f"ATTACH DATABASE '{PACKETS_DB_PATH}' AS pkt_db")
                
                # Check for mismatched FK (packet_id points to a packet, but meta differs)
                mismatches = conn.execute("""
                    SELECT COUNT(*) FROM payloads pl
                    JOIN pkt_db.packets p ON pl.packet_id = p.id
                    WHERE pl.investigation_id != p.investigation_id OR pl.packet_index != p.packet_index
                """).fetchone()[0]
                
                # Check for orphaned payloads by packet_id FK
                orphans_p = conn.execute("""
                    SELECT COUNT(*) FROM payloads WHERE packet_id NOT IN (SELECT id FROM pkt_db.packets)
                """).fetchone()[0]
                
                if mismatches > 0:
                    print(f"  [FAIL] payloads: Found {mismatches} records with mismatched investigation_id/packet_index between databases.")
                    all_ok = False
                elif orphans_p > 0:
                    print(f"  [FAIL] payloads: Found {orphans_p} orphan payloads with no matching packet record by packet_id FK.")
                    all_ok = False
                else:
                    print("  [PASS] payloads: All payloads are aligned 1-to-1 with packet metadata via packet_id FK.")

    # 3. Flows database checks
    print("\n[3/4] Checking flows.sqlite3 referential integrity...")
    if FLOWS_DB_PATH.is_file():
        with sqlite3.connect(FLOWS_DB_PATH) as conn:
            # Count sessions
            session_count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            print(f"  sessions: {session_count} rows")
            
            # Check orphaned sessions
            conn.execute(f"ATTACH DATABASE '{INVESTIGATIONS_DB_PATH}' AS inv_db")
            orphan_sessions = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE investigation_id NOT IN (SELECT id FROM inv_db.investigations)"
            ).fetchone()[0]
            if orphan_sessions > 0:
                print(f"  [FAIL] sessions: Found {orphan_sessions} orphan sessions (no investigation).")
                all_ok = False
            else:
                print("  [PASS] sessions: No orphan sessions found.")

            # Check for tables existence (rtp_streams, sip_dialogs, ice_sessions)
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            for tbl in ["rtp_streams", "sip_dialogs", "ice_sessions"]:
                if tbl in tables:
                    count = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
                    print(f"  [PASS] {tbl}: Table exists ({count} rows)")
                else:
                    print(f"  [FAIL] {tbl}: Table missing from flows.sqlite3")
                    all_ok = False
    else:
        print("  [FAIL] flows.sqlite3 not found.")
        all_ok = False

    # 4. Hash-based verification (sample 5 investigations)
    print("\n[4/4] Running hash-based case reconstruction verification...")
    
    # Find the monolithic backup to compare against
    backup_path = None
    for candidate in [Path("data") / "ip_intel.sqlite3.old", Path("data") / "ip_intel.sqlite3"]:
        if candidate.is_file():
            backup_path = candidate
            break
    
    if not backup_path:
        print("  [SKIP] No monolithic backup found for hash comparison.")
    else:
        try:
            with sqlite3.connect(backup_path) as backup_conn:
                backup_conn.row_factory = sqlite3.Row
                sample_ids = [r[0] for r in backup_conn.execute(
                    "SELECT id FROM investigations ORDER BY RANDOM() LIMIT 5"
                ).fetchall()]
                
            if not sample_ids:
                print("  [SKIP] No investigations found in backup for comparison.")
            else:
                hash_pass = 0
                hash_fail = 0
                
                for inv_id in sample_ids:
                    # Get original case from backup
                    with sqlite3.connect(backup_path) as backup_conn:
                        backup_conn.row_factory = sqlite3.Row
                        original = backup_conn.execute(
                            "SELECT case_json FROM investigations WHERE id = ?", (inv_id,)
                        ).fetchone()
                    
                    if not original or not original["case_json"]:
                        print(f"  [SKIP] Investigation {inv_id[:8]}...: no case_json in backup.")
                        continue
                        
                    original_case = json.loads(original["case_json"])
                    original_packets = original_case.get("packet_rows", [])
                    
                    # Normalize original packets for comparison
                    normalized_original = []
                    for pkt in original_packets:
                        normalized_original.append({
                            "packet_index": pkt.get("packet_index"),
                            "protocol": pkt.get("protocol"),
                            "source_ip": pkt.get("source_ip"),
                            "destination_ip": pkt.get("destination_ip"),
                            "length": pkt.get("length"),
                            "summary": pkt.get("summary"),
                        })
                    
                    # Rebuild from modular databases
                    rebuilt = get_investigation(inv_id)
                    if not rebuilt:
                        print(f"  [FAIL] Investigation {inv_id[:8]}...: could not rebuild from modular DBs.")
                        hash_fail += 1
                        continue
                    
                    rebuilt_packets = rebuilt.get("packet_rows", [])
                    normalized_rebuilt = []
                    for pkt in rebuilt_packets:
                        normalized_rebuilt.append({
                            "packet_index": pkt.get("packet_index"),
                            "protocol": pkt.get("protocol"),
                            "source_ip": pkt.get("source_ip"),
                            "destination_ip": pkt.get("destination_ip"),
                            "length": pkt.get("length"),
                            "summary": pkt.get("summary"),
                        })
                    
                    # Hash comparison
                    orig_hash = hashlib.sha256(json.dumps(normalized_original, sort_keys=True).encode()).hexdigest()
                    rebuilt_hash = hashlib.sha256(json.dumps(normalized_rebuilt, sort_keys=True).encode()).hexdigest()
                    
                    if orig_hash == rebuilt_hash:
                        print(f"  [PASS] Investigation {inv_id[:8]}...: SHA-256 match ({len(original_packets)} packets)")
                        hash_pass += 1
                    else:
                        print(f"  [FAIL] Investigation {inv_id[:8]}...: SHA-256 mismatch! orig={orig_hash[:16]}... rebuilt={rebuilt_hash[:16]}...")
                        print(f"         Original: {len(original_packets)} packets, Rebuilt: {len(rebuilt_packets)} packets")
                        hash_fail += 1
                        all_ok = False
                
                print(f"\n  Hash verification results: {hash_pass} passed, {hash_fail} failed out of {len(sample_ids)} sampled")
                
        except Exception as e:
            print(f"  [ERROR] Hash verification failed: {e}")
            import traceback
            traceback.print_exc()

    if all_ok:
        print("\n=== STORAGE INTEGRITY CHECK PASSED ===")
    else:
        print("\n=== STORAGE INTEGRITY CHECK FAILED ===")
        sys.exit(1)

if __name__ == "__main__":
    check_integrity()
