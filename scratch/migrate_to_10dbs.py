import sys
import os
import json
import sqlite3
import uuid
import zlib
from pathlib import Path
from datetime import datetime, timezone

# Ensure app is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.storage.database import (
    init_db, router, get_endpoint_id, compress_bytes, calculate_entropy,
    INVESTIGATIONS_DB_PATH, PACKETS_DB_PATH, PAYLOADS_DB_PATH,
    LIVE_CAPTURE_DB_PATH, TELECOM_DB_PATH, GEOIP_DB_PATH,
    THREATINTEL_DB_PATH, DNS_DB_PATH, USERS_DB_PATH, CACHE_DB_PATH,
    FLOWS_DB_PATH, SCHEMAS
)

def clean_target_databases():
    """Delete any existing destination databases to ensure a clean migration."""
    print("Cleaning existing target database files for a clean slate...")
    targets = [
        INVESTIGATIONS_DB_PATH, PACKETS_DB_PATH, PAYLOADS_DB_PATH,
        LIVE_CAPTURE_DB_PATH, CACHE_DB_PATH, FLOWS_DB_PATH
    ]
    for path in targets:
        if path.is_file():
            try:
                # Close any active connections first
                path.unlink()
                print(f"  Deleted existing target: {path.name}")
            except Exception as e:
                print(f"  Warning: could not delete {path.name}: {e}")

def migrate_table_attached(src_path: Path, dst_path: Path, table_name: str, check_duplicate_inv: bool = False) -> int:
    """Migrate a table from src_path to dst_path using ATTACH DATABASE."""
    if not src_path.is_file():
        return 0
        
    try:
        with sqlite3.connect(src_path) as s_conn:
            cursor = s_conn.execute(f"SELECT * FROM {table_name} LIMIT 1")
            columns = [desc[0] for desc in cursor.description]
    except Exception:
        return 0
        
    col_str = ", ".join(columns)
    
    with sqlite3.connect(dst_path) as d_conn:
        d_conn.execute(f"ATTACH DATABASE '{src_path}' AS src_db")
        try:
            if check_duplicate_inv and "investigation_id" in columns:
                query = f"""
                    INSERT INTO {table_name} ({col_str})
                    SELECT {col_str} FROM src_db.{table_name}
                    WHERE investigation_id NOT IN (SELECT DISTINCT investigation_id FROM main.{table_name})
                """
            else:
                query = f"INSERT OR IGNORE INTO {table_name} ({col_str}) SELECT {col_str} FROM src_db.{table_name}"
                
            d_conn.execute(query)
            cursor = d_conn.execute("SELECT changes()")
            rows_migrated = cursor.fetchone()[0]
            d_conn.commit()
            return rows_migrated
        except Exception as e:
            print(f"Error migrating table {table_name} from {src_path.name}: {e}")
            return 0
        finally:
            try:
                d_conn.execute("DETACH DATABASE src_db")
            except Exception:
                pass

def migrate_to_10dbs():
    print("=== Starting SQLite 10-Database Redesign Migration (v2 Clean Slate) ===")
    
    # 1. Clean targets
    clean_target_databases()
    
    # 2. Pre-migration schema evolution (handle old column layouts before init_db)
    print("\n[1/6] Initializing specialized modular databases...")
    
    # Evolve geoip_lookup: drop old table with lookup_json (has 0 rows) so init_db creates new schema
    if GEOIP_DB_PATH.is_file():
        try:
            with sqlite3.connect(GEOIP_DB_PATH) as conn:
                cols = [r[1] for r in conn.execute("PRAGMA table_info(geoip_lookup)").fetchall()]
                if "lookup_json" in cols:
                    print("  Evolving geoip_lookup schema: dropping old lookup_json table...")
                    conn.execute("DROP TABLE IF EXISTS geoip_lookup")
                    conn.commit()
        except Exception:
            pass
    
    # Evolve payloads: add packet_id column if missing (for re-runs on existing data)
    if PAYLOADS_DB_PATH.is_file():
        try:
            with sqlite3.connect(PAYLOADS_DB_PATH) as conn:
                cols = [r[1] for r in conn.execute("PRAGMA table_info(payloads)").fetchall()]
                if "packet_id" not in cols:
                    print("  Evolving payloads schema: adding packet_id column...")
                    conn.execute("ALTER TABLE payloads ADD COLUMN packet_id INTEGER NOT NULL DEFAULT 0")
                    conn.commit()
        except Exception:
            pass
    
    # Evolve threat_indicators: add source_url column if missing
    if THREATINTEL_DB_PATH.is_file():
        try:
            with sqlite3.connect(THREATINTEL_DB_PATH) as conn:
                cols = [r[1] for r in conn.execute("PRAGMA table_info(threat_indicators)").fetchall()]
                if "source_url" not in cols:
                    print("  Evolving threat_indicators schema: adding source_url column...")
                    conn.execute("ALTER TABLE threat_indicators ADD COLUMN source_url TEXT")
                    conn.commit()
        except Exception:
            pass
    
    init_db()
    
    migrated_stats = {
        "investigations": 0,
        "destinations": 0,
        "packets_from_json": 0,
        "payloads_from_json": 0,
        "sessions_from_json": 0,
        "alerts_from_json": 0,
        "investigation_search": 0
    }
    
    # 3. Identify and migrate monolithic database sources
    print("\n[2/6] Processing monolithic database metadata & embedded packets...")
    monolithic_sources = [
        Path("data") / "network_analysis.sqlite3",
        Path("data") / "ip_intel.sqlite3.old",
        Path("data") / "ip_intel.sqlite3"
    ]
    
    processed_investigations = set()
    
    for src_path in monolithic_sources:
        if not src_path.is_file():
            continue
            
        print(f"\nProcessing monolithic source: {src_path} ({src_path.stat().st_size / 1024 / 1024:.1f} MB)")
        
        try:
            src_conn = sqlite3.connect(src_path)
            src_conn.row_factory = sqlite3.Row
            tables = [r[0] for r in src_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            
            if "investigations" not in tables:
                src_conn.close()
                continue
                
            investigations = src_conn.execute("SELECT * FROM investigations").fetchall()
            print(f"  Found {len(investigations)} investigations in source.")
            
            for inv in investigations:
                inv_id = inv["id"]
                if inv_id in processed_investigations:
                    continue
                    
                filename = inv["filename"]
                created_at = inv["created_at"]
                summary_json = inv["summary_json"]
                case_json = inv["case_json"]
                
                analysis = {}
                packet_rows = []
                if case_json:
                    try:
                        analysis = json.loads(case_json)
                        packet_rows = analysis.pop("packet_rows", [])
                    except Exception:
                        pass
                
                # Save metadata case to investigations.sqlite3 (with popped packet_rows)
                with sqlite3.connect(INVESTIGATIONS_DB_PATH) as conn:
                    conn.execute(
                        "INSERT OR IGNORE INTO investigations (id, filename, created_at, summary_json, case_json) VALUES (?, ?, ?, ?, ?)",
                        (inv_id, filename, created_at, summary_json, json.dumps(analysis))
                    )
                    
                    # Copy destinations
                    dest_rows = src_conn.execute("SELECT * FROM destinations WHERE investigation_id = ?", (inv_id,)).fetchall()
                    conn.executemany(
                        "INSERT OR IGNORE INTO destinations (investigation_id, destination_ip, row_json) VALUES (?, ?, ?)",
                        [(d["investigation_id"], d["destination_ip"], d["row_json"]) for d in dest_rows]
                    )
                    
                migrated_stats["investigations"] += 1
                migrated_stats["destinations"] += len(dest_rows)
                processed_investigations.add(inv_id)
                
                # Migrate embedded packets & payloads
                if packet_rows:
                    packets_to_insert = []
                    payloads_to_insert = []
                    flows_seen = {}
                    
                    dns_list = []
                    http_list = []
                    sip_list = []
                    previews_list = []
                    
                    for pkt in packet_rows:
                        ts = pkt.get("timestamp", created_at)
                        src_id = get_endpoint_id(pkt["source_ip"], pkt.get("source_mac"))
                        dst_id = get_endpoint_id(pkt["destination_ip"], pkt.get("destination_mac"))
                        flow_id = pkt.get("flow_id")
                        
                        if flow_id and flow_id not in flows_seen:
                            flows_seen[flow_id] = {
                                "flow_id": flow_id,
                                "investigation_id": inv_id,
                                "protocol": pkt["protocol"],
                                "start_time": ts,
                                "end_time": ts,
                                "bytes": pkt.get("length", 0),
                                "packets": 1
                            }
                        elif flow_id:
                            flows_seen[flow_id]["end_time"] = ts
                            flows_seen[flow_id]["bytes"] += pkt.get("length", 0)
                            flows_seen[flow_id]["packets"] += 1
                            
                        packets_to_insert.append((
                            inv_id, pkt["packet_index"], ts, pkt["length"], pkt["protocol"],
                            src_id, dst_id, pkt.get("source_port"), pkt.get("destination_port"),
                            pkt.get("tcp_flags"), flow_id, pkt["summary"]
                        ))
                        
                        # Compress payload
                        raw_text = pkt.get("payload_hex") or pkt.get("payload_ascii") or ""
                        payload_bytes = bytes.fromhex(pkt.get("payload_hex")) if pkt.get("payload_hex") else raw_text.encode("utf-8", errors="ignore")
                        compressed = compress_bytes(payload_bytes)
                        entropy = calculate_entropy(payload_bytes)
                        
                        payloads_to_insert.append((
                            inv_id, pkt["packet_index"], compressed, pkt.get("payload_preview") or "",
                            pkt.get("payload_kind") or "plaintext", json.dumps(pkt.get("decoded_fields", {})),
                            "zlib", entropy
                        ))
                        
                        prev = pkt.get("payload_preview") or ""
                        if prev:
                            previews_list.append(prev)
                        if pkt["protocol"] == "DNS" and prev:
                            dns_list.append(prev)
                        if "HTTP" in pkt["protocol"] and prev:
                            http_list.append(prev)
                        if pkt["protocol"] == "SIP" and prev:
                            sip_list.append(prev)
                            
                    # Batch write to packets database and capture starting ID
                    with sqlite3.connect(PACKETS_DB_PATH) as conn:
                        cursor = conn.execute("SELECT COALESCE(MAX(id), 0) FROM packets")
                        base_packet_id = cursor.fetchone()[0] + 1
                        conn.executemany(
                            "INSERT INTO packets (investigation_id, packet_index, timestamp, length, protocol, src_endpoint_id, dst_endpoint_id, source_port, destination_port, tcp_flags, flow_id, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            packets_to_insert
                        )
                    # Write payloads with explicit packet_id FK
                    with sqlite3.connect(PAYLOADS_DB_PATH) as conn:
                        conn.executemany(
                            "INSERT INTO payloads (packet_id, investigation_id, packet_index, payload_blob, payload_preview, mime_type, decoded_json, compression, entropy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            [
                                (base_packet_id + i, *pl)
                                for i, pl in enumerate(payloads_to_insert)
                            ]
                        )
                        
                    # Batch write sessions to flows.sqlite3
                    if flows_seen:
                        with sqlite3.connect(FLOWS_DB_PATH) as conn:
                            conn.executemany(
                                """INSERT OR IGNORE INTO sessions 
                                (flow_id, investigation_id, protocol, start_time, end_time, bytes, packets, jitter, loss, mos, classification)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                [
                                    (
                                        f["flow_id"], f["investigation_id"], f["protocol"], f["start_time"], f["end_time"],
                                        f["bytes"], f["packets"], 0.0, 0.0, 4.0, "Attributed Flow"
                                    )
                                    for f in flows_seen.values()
                                ]
                            )
                        migrated_stats["sessions_from_json"] += len(flows_seen)
                        
                    # Batch write alerts to cache
                    alerts_to_insert = []
                    for anomaly in analysis.get("anomalies", []):
                        alert_id = str(uuid.uuid4())[:8]
                        alerts_to_insert.append((
                            alert_id, anomaly.get("flow_id") or "global", anomaly.get("packet_index"),
                            anomaly.get("severity", "Medium"), anomaly.get("name", "Alert Rule"),
                            anomaly.get("confidence", 1.0), created_at, "New", 0
                        ))
                    if alerts_to_insert:
                        with sqlite3.connect(CACHE_DB_PATH) as conn:
                            conn.executemany(
                                "INSERT OR IGNORE INTO alerts (alert_id, flow_id, packet_id, severity, rule, confidence, timestamp, status, resolved) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                alerts_to_insert
                            )
                        migrated_stats["alerts_from_json"] += len(alerts_to_insert)
                        
                    # Write search table
                    with sqlite3.connect(INVESTIGATIONS_DB_PATH) as conn:
                        conn.execute(
                            """INSERT OR IGNORE INTO investigation_search 
                            (investigation_id, filename, notes, dns_queries, http_headers, sip_messages, payload_previews)
                            VALUES (?, ?, ?, ?, ?, ?, ?)""",
                            (
                                inv_id, filename, "Forensic analysis case split to specialized structure",
                                " ".join(dns_list)[:20000], " ".join(http_list)[:20000],
                                " ".join(sip_list)[:20000], " ".join(previews_list)[:50000]
                            )
                        )
                    migrated_stats["investigation_search"] += 1
                    migrated_stats["packets_from_json"] += len(packets_to_insert)
                    migrated_stats["payloads_from_json"] += len(payloads_to_insert)
            
            src_conn.close()
        except Exception as e:
            print(f"  Error reading source database: {e}")

    # 4. Migrate sessions (to flows.sqlite3) and alerts (to cache.sqlite3)
    print("\n[3/6] Migrating sessions and alerts from old databases...")
    for old_file in ["sessions.sqlite3", "sessions.sqlite3.old"]:
        src_path = Path("data") / old_file
        rows = migrate_table_attached(src_path, FLOWS_DB_PATH, "sessions")
        if rows > 0:
            print(f"  Migrated {rows} sessions from '{old_file}' to flows.sqlite3")
    for old_file in ["alerts.sqlite3", "alerts.sqlite3.old"]:
        src_path = Path("data") / old_file
        rows = migrate_table_attached(src_path, CACHE_DB_PATH, "alerts")
        if rows > 0:
            print(f"  Migrated {rows} alerts from '{old_file}' to cache.sqlite3")

    # 5. Migrate monthly partitioned packets and payloads
    print("\n[4/6] Migrating monthly partitioned database files...")
    
    packets_dir = Path("data") / "packets"
    payloads_dir = Path("data") / "payloads"
    live_capture_dir = Path("data") / "live_capture"
    
    total_packets = 0
    if packets_dir.is_dir():
        for f in packets_dir.glob("packets_*.sqlite3*"):
            # Skip backup files
            if f.name.endswith(".old"):
                continue
            rows = migrate_table_attached(f, PACKETS_DB_PATH, "packets", check_duplicate_inv=True)
            total_packets += rows
            if rows > 0:
                print(f"  Migrated {rows} rows from partitioned file '{f.name}' to packets.sqlite3")
            
    total_payloads = 0
    if payloads_dir.is_dir():
        for f in payloads_dir.glob("payloads_*.sqlite3*"):
            if f.name.endswith(".old"):
                continue
            rows = migrate_table_attached(f, PAYLOADS_DB_PATH, "payloads", check_duplicate_inv=True)
            total_payloads += rows
            if rows > 0:
                print(f"  Migrated {rows} rows from partitioned file '{f.name}' to payloads.sqlite3")

    total_capture_packets = 0
    total_capture_stats = 0
    if live_capture_dir.is_dir():
        for f in live_capture_dir.glob("*.sqlite3*"):
            if f.name.endswith(".old"):
                continue
            rows_p = migrate_table_attached(f, LIVE_CAPTURE_DB_PATH, "live_capture_packets")
            rows_s = migrate_table_attached(f, LIVE_CAPTURE_DB_PATH, "capture_statistics")
            total_capture_packets += rows_p
            total_capture_stats += rows_s
            if rows_p > 0 or rows_s > 0:
                print(f"  Migrated {rows_p} packets / {rows_s} stats from capture file '{f.name}' to live_capture.sqlite3")

    migrated_stats["packets_from_partitions"] = total_packets
    migrated_stats["payloads_from_partitions"] = total_payloads
    migrated_stats["live_capture_packets"] = total_capture_packets
    migrated_stats["live_capture_statistics"] = total_capture_stats

    # 6. Populate/update schema_info tables
    print("\n[5/6] Writing schema metadata & versioning...")
    now_str = datetime.now(timezone.utc).isoformat()
    for db_path in SCHEMAS.keys():
        if db_path.is_file():
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    "UPDATE schema_info SET version = 1, last_migration = ? WHERE version IS NOT NULL",
                    (now_str,)
                )
                conn.commit()

    # 7. Optimize all target databases
    print("\n[6/6] Running database optimizations (VACUUM, ANALYZE, PRAGMA optimize)...")
    for db_path in SCHEMAS.keys():
        if db_path.is_file():
            print(f"  Optimizing {db_path.name}...")
            with sqlite3.connect(db_path) as conn:
                conn.execute("VACUUM")
                conn.execute("ANALYZE")
                conn.execute("PRAGMA optimize")
                conn.commit()

    # Rename migrated files to .old to avoid confusion
    print("\n[Post-Migration] Renaming old databases to .old for safety...")
    
    # Monolithic databases
    for name in ["ip_intel.sqlite3", "network_analysis.sqlite3"]:
        active = Path("data") / name
        if active.is_file():
            try:
                dest = Path("data") / f"{name}.old"
                if dest.is_file():
                    dest.unlink()
                active.rename(dest)
                print(f"  Renamed {name} -> {name}.old")
            except Exception as e:
                print(f"  Warning: could not rename {name}: {e}")
                
    # Sessions & Alerts
    for name in ["sessions.sqlite3", "alerts.sqlite3"]:
        active = Path("data") / name
        if active.is_file():
            try:
                dest = Path("data") / f"{name}.old"
                if dest.is_file():
                    dest.unlink()
                active.rename(dest)
                print(f"  Renamed {name} -> {name}.old")
            except Exception as e:
                print(f"  Warning: could not rename {name}: {e}")

    # Partitioned files
    if packets_dir.is_dir():
        for f in packets_dir.glob("packets_*.sqlite3"):
            try:
                f.rename(f.with_suffix(".sqlite3.old"))
            except Exception:
                pass
    if payloads_dir.is_dir():
        for f in payloads_dir.glob("payloads_*.sqlite3"):
            try:
                f.rename(f.with_suffix(".sqlite3.old"))
            except Exception:
                pass
    if live_capture_dir.is_dir():
        for f in live_capture_dir.glob("*.sqlite3"):
            try:
                f.rename(f.with_suffix(".sqlite3.old"))
            except Exception:
                pass

    print("\n=== Migration Completed successfully! ===")
    print("Migrated Row Counts:")
    for key, count in migrated_stats.items():
        print(f"  {key:<35}: {count:,} rows")
        
    print("\nNew Specialized Databases:")
    for db_path in sorted(SCHEMAS.keys()):
        if db_path.is_file():
            print(f"  {db_path.name:<25}: {db_path.stat().st_size / 1024 / 1024:.2f} MB")

if __name__ == "__main__":
    migrate_to_10dbs()
