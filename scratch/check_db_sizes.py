import sqlite3
import os

db_path = r"D:\cyberdeep\data\ip_intel.sqlite3"
con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row

print("=== Column Length Statistics ===")

# Investigations lengths
inv_stats = con.execute("""
    SELECT 
        COUNT(*) as count,
        AVG(LENGTH(summary_json)) as avg_summary,
        MAX(LENGTH(summary_json)) as max_summary,
        AVG(LENGTH(case_json)) as avg_case,
        MAX(LENGTH(case_json)) as max_case
    FROM investigations
""").fetchone()

print(f"Investigations (total {inv_stats['count']}):")
print(f"  summary_json: avg = {inv_stats['avg_summary']:.1f} chars, max = {inv_stats['max_summary']} chars")
print(f"  case_json:    avg = {inv_stats['avg_case']:.1f} chars, max = {inv_stats['max_case']} chars")

# Destinations lengths
dest_stats = con.execute("""
    SELECT 
        COUNT(*) as count,
        AVG(LENGTH(row_json)) as avg_row,
        MAX(LENGTH(row_json)) as max_row
    FROM destinations
""").fetchone()

print(f"\nDestinations (total {dest_stats['count']}):")
print(f"  row_json:     avg = {dest_stats['avg_row']:.1f} chars, max = {dest_stats['max_row']} chars")

# Check page info
page_count = con.execute("PRAGMA page_count").fetchone()[0]
page_size = con.execute("PRAGMA page_size").fetchone()[0]
freelist_count = con.execute("PRAGMA freelist_count").fetchone()[0]

print(f"\nSQLite internal stats:")
print(f"  Page size: {page_size} bytes")
print(f"  Page count: {page_count:,}")
print(f"  Total size calculated: {(page_count * page_size) / 1024 / 1024:.1f} MB")
print(f"  Freelist page count: {freelist_count:,} (can be recovered by VACUUM)")
print(f"  Freelist size: {(freelist_count * page_size) / 1024 / 1024:.1f} MB")

con.close()
