import sys
import os
import json
import sqlite3
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.storage.database import get_investigation

def normalize_packet(p):
    return {
        "packet_index": p.get("packet_index"),
        "timestamp": p.get("timestamp"),
        "length": p.get("length"),
        "protocol": p.get("protocol"),
        "source_ip": p.get("source_ip"),
        "destination_ip": p.get("destination_ip"),
        "source_port": p.get("source_port"),
        "destination_port": p.get("destination_port"),
        "tcp_flags": p.get("tcp_flags"),
        "summary": p.get("summary"),
        "source_mac": p.get("source_mac") or None,  # normalize None/empty
        "destination_mac": p.get("destination_mac") or None,
        "payload_preview": p.get("payload_preview") or "",
        "payload_hex": p.get("payload_hex") or "",
        "decoded_fields": p.get("decoded_fields") or {}
    }

def normalize_case(c):
    # Core metadata
    summary = c.get("summary") or {}
    rows = c.get("rows") or []
    packet_rows = [normalize_packet(p) for p in c.get("packet_rows") or []]
    
    return {
        "summary": summary,
        "rows": sorted(rows, key=lambda x: (x.get("destination_ip") or "", x.get("port") or 0)),
        "packet_rows": sorted(packet_rows, key=lambda x: (x.get("packet_index") or 0, x.get("timestamp") or "")),
        "anomalies": c.get("anomalies") or [],
        "voip_analysis": c.get("voip_analysis") or [],
        "telecom_records": c.get("telecom_records") or []
    }

def get_hash(d):
    s = json.dumps(d, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

old_conn = sqlite3.connect("data/ip_intel.sqlite3.old")
old_conn.row_factory = sqlite3.Row

# Get a sample investigation
sample = old_conn.execute("SELECT id, filename, case_json FROM investigations ORDER BY created_at DESC LIMIT 1").fetchone()
if sample:
    inv_id = sample["id"]
    filename = sample["filename"]
    print(f"Comparing Case ID: {inv_id} | Filename: {filename}")
    
    # 1. Reconstruct from new databases
    rebuilt = get_investigation(inv_id)
    
    # 2. Get original from old database
    orig_case = json.loads(sample["case_json"])
    
    # Normalize both
    norm_orig = normalize_case(orig_case)
    norm_rebuilt = normalize_case(rebuilt)
    
    hash_orig = get_hash(norm_orig)
    hash_rebuilt = get_hash(norm_rebuilt)
    
    print("Original Hash:", hash_orig)
    print("Rebuilt Hash :", hash_rebuilt)
    print("Match?", hash_orig == hash_rebuilt)
    
    if hash_orig != hash_rebuilt:
        # Check first difference in packet_rows
        p_orig = norm_orig["packet_rows"]
        p_reb = norm_rebuilt["packet_rows"]
        print(f"Sizes: orig = {len(p_orig)}, rebuilt = {len(p_reb)}")
        for idx in range(min(len(p_orig), len(p_reb))):
            if p_orig[idx] != p_reb[idx]:
                print(f"First diff at packet index {idx}:")
                print("Original:", p_orig[idx])
                print("Rebuilt :", p_reb[idx])
                break

old_conn.close()
