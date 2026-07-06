import time
import sqlite3
import sys
import os
from pathlib import Path

# Ensure app is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.storage.database import (
    router, INVESTIGATIONS_DB_PATH, PACKETS_DB_PATH,
    PAYLOADS_DB_PATH, GEOIP_DB_PATH, CACHE_DB_PATH
)

def run_benchmark():
    print("=== CyberDeep Storage Performance Benchmark ===")
    
    # Check if DB files exist
    dbs = [INVESTIGATIONS_DB_PATH, PACKETS_DB_PATH, PAYLOADS_DB_PATH, GEOIP_DB_PATH]
    for db in dbs:
        if not db.is_file():
            print(f"Error: {db.name} not found. Please run migration first.")
            return

    # 1. Test single-db read queries (Investigations metadata)
    print("\n[1/3] Benchmarking single-DB metadata query speed...")
    t0 = time.perf_counter()
    with sqlite3.connect(INVESTIGATIONS_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT id, filename, created_at FROM investigations LIMIT 100").fetchall()
    t1 = time.perf_counter()
    print(f"  Fetched {len(rows)} investigations in {(t1 - t0)*1000:.2f} ms")

    # 2. Test cross-DB packet-payload-geoip joined query
    print("\n[2/3] Benchmarking cross-DB joined query (Reconstruct Investigation)...")
    
    # Find a valid case ID
    with sqlite3.connect(INVESTIGATIONS_DB_PATH) as conn:
        inv = conn.execute("SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1").fetchone()
        if not inv:
            print("  Error: No investigations found in database to benchmark.")
            return
        inv_id = inv[0]

    print(f"  Benchmarking query for case ID: {inv_id}")
    
    # Run the optimized join using primary key ID
    t0 = time.perf_counter()
    with sqlite3.connect(PACKETS_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute(f"ATTACH DATABASE '{PAYLOADS_DB_PATH}' AS payloads_db")
        conn.execute(f"ATTACH DATABASE '{GEOIP_DB_PATH}' AS geoip_db")
        
        query = """
            SELECT 
                p.packet_index, p.timestamp, p.length, p.protocol,
                p.source_port, p.destination_port, p.tcp_flags, p.flow_id, p.summary,
                src.ip as source_ip, src.mac as source_mac,
                dst.ip as destination_ip, dst.mac as destination_mac,
                pl.payload_blob, pl.payload_preview, pl.mime_type as payload_kind, pl.decoded_json
            FROM packets p
            JOIN payloads_db.payloads pl ON p.id = pl.id
            JOIN geoip_db.endpoints src ON p.src_endpoint_id = src.id
            JOIN geoip_db.endpoints dst ON p.dst_endpoint_id = dst.id
            WHERE p.investigation_id = ?
            ORDER BY p.id ASC
        """
        results = conn.execute(query, (inv_id,)).fetchall()
    t1 = time.perf_counter()
    duration_ms = (t1 - t0) * 1000
    print(f"  Reconstructed {len(results)} packets (with payloads & endpoints) in {duration_ms:.2f} ms")
    if len(results) > 0:
        print(f"  Average query speed: {duration_ms / len(results):.4f} ms per packet")

    # 3. Test Cache reads/writes
    print("\n[3/3] Benchmarking Cache database write/read throughput...")
    t0 = time.perf_counter()
    with sqlite3.connect(CACHE_DB_PATH) as conn:
        # Batch write temp keys
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE IF NOT EXISTS benchmark_temp (k TEXT PRIMARY KEY, v TEXT)")
        conn.execute("DELETE FROM benchmark_temp")
        
        # Insert 1000 rows in a transaction
        conn.executemany(
            "INSERT INTO benchmark_temp (k, v) VALUES (?, ?)",
            [(f"key_{i}", f"val_{i}") for i in range(1000)]
        )
        conn.commit()
        
        # Read them back
        keys = conn.execute("SELECT * FROM benchmark_temp").fetchall()
        
        # Clean up
        conn.execute("DROP TABLE benchmark_temp")
        conn.commit()
        
    t1 = time.perf_counter()
    print(f"  Wrote and read 1,000 temp records (WAL mode) in {(t1 - t0)*1000:.2f} ms")

    print("\n=== Benchmark Completed ===")

if __name__ == "__main__":
    run_benchmark()
