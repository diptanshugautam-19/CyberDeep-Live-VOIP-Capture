"""
Inspect the monolithic ip_intel.sqlite3 database.
Shows all tables, their row counts, and estimated sizes.
"""
import sys
import os
import sqlite3
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.core.config import DB_PATH

DB_PATH_OLD = DB_PATH.with_name("ip_intel.sqlite3.old")
print(f"Database: {DB_PATH_OLD}")
print(f"File size: {os.path.getsize(DB_PATH_OLD) / 1024 / 1024:.1f} MB")
print()

con = sqlite3.connect(DB_OLD if 'DB_OLD' in locals() else DB_PATH_OLD)
con.row_factory = sqlite3.Row

# List all tables
tables = con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
print(f"Tables found: {[t[0] for t in tables]}")
print()

for table in tables:
    name = table[0]
    count = con.execute(f"SELECT COUNT(*) FROM [{name}]").fetchone()[0]
    # Estimate bytes per row using first 5 rows
    sample = con.execute(f"SELECT * FROM [{name}] LIMIT 5").fetchall()
    avg_bytes = 0
    if sample:
        total_bytes = sum(len(str(dict(r))) for r in sample)
        avg_bytes = total_bytes / len(sample)
    est_size_mb = (count * avg_bytes) / 1024 / 1024
    print(f"Table: {name:<25} | Rows: {count:>8,} | ~Avg row: {avg_bytes:>6.0f} bytes | ~Est: {est_size_mb:.1f} MB")

print()

# Sample the filename values to understand what tools produce what data
print("=== Sample filenames from investigations (last 30) ===")
inv_rows = con.execute(
    "SELECT id, filename, created_at FROM investigations ORDER BY created_at DESC LIMIT 30"
).fetchall()
for row in inv_rows:
    print(f"  {row['created_at'][:19]}  {row['filename'][:80]}")

con.close()
