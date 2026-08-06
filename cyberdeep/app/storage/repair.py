"""
CyberDEEP Storage Repair & Evidence Quarantine Utility
Executes non-destructive database maintenance, moves orphaned payload records 
into a dedicated quarantine table for forensic auditing, and performs database maintenance.
"""

import sqlite3
import logging
import uuid
from datetime import datetime, timezone, timedelta
from app.core.config import DATA_DIR

logger = logging.getLogger(__name__)

PACKETS_DB_PATH = DATA_DIR / "packets.sqlite3"
PAYLOADS_DB_PATH = DATA_DIR / "payloads.sqlite3"
DNS_DB_PATH = DATA_DIR / "dns.sqlite3"
INVESTIGATIONS_DB_PATH = DATA_DIR / "investigations.sqlite3"


def init_quarantine_schema(conn: sqlite3.Connection) -> None:
    """Ensure quarantine table exists in payloads.sqlite3."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS payloads_quarantine (
            quarantine_id TEXT PRIMARY KEY,
            original_payload_id INTEGER,
            packet_id INTEGER,
            investigation_id TEXT,
            packet_index INTEGER,
            payload_blob BLOB,
            payload_preview TEXT,
            quarantined_at TEXT,
            reason TEXT
        );
    """)
    conn.commit()


def repair_storage_integrity() -> dict:
    """
    Non-destructive storage health check.
    Quarantines orphaned payloads rather than deleting them silently.
    """
    results = {
        "orphans_quarantined": 0,
        "dns_vacuumed": False,
        "investigations_repaired": 0,
        "errors": []
    }

    # 1. Quarantining Orphaned Payloads
    if PACKETS_DB_PATH.is_file() and PAYLOADS_DB_PATH.is_file():
        try:
            conn_packets = sqlite3.connect(PACKETS_DB_PATH)
            cur_p = conn_packets.cursor()
            valid_packet_ids = {row[0] for row in cur_p.execute("SELECT id FROM packets").fetchall()}
            cur_p.close()
            conn_packets.close()

            conn_payloads = sqlite3.connect(PAYLOADS_DB_PATH)
            init_quarantine_schema(conn_payloads)
            
            cur_pl = conn_payloads.cursor()
            cur_pl.execute("SELECT id, packet_id, investigation_id, packet_index, payload_blob, payload_preview FROM payloads")
            payload_rows = cur_pl.fetchall()
            cur_pl.close()
            
            orphan_rows = [row for row in payload_rows if row[1] not in valid_packet_ids]
            
            if orphan_rows:
                logger.warning(f"Found {len(orphan_rows)} orphaned payloads. Moving to quarantine table...")
                now_str = datetime.now(timezone.utc).isoformat()
                
                quarantine_entries = [
                    (
                        str(uuid.uuid4()),
                        r[0],  # original_payload_id
                        r[1],  # packet_id
                        r[2],  # investigation_id
                        r[3],  # packet_index
                        r[4],  # payload_blob
                        r[5],  # payload_preview
                        now_str,
                        "Missing packet_id foreign key in packets.sqlite3"
                    )
                    for r in orphan_rows
                ]
                
                conn_payloads.execute("BEGIN TRANSACTION")
                conn_payloads.executemany("""
                    INSERT INTO payloads_quarantine (
                        quarantine_id, original_payload_id, packet_id, investigation_id, 
                        packet_index, payload_blob, payload_preview, quarantined_at, reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, quarantine_entries)
                
                orphan_ids = [(r[0],) for r in orphan_rows]
                conn_payloads.executemany("DELETE FROM payloads WHERE id = ?", orphan_ids)
                conn_payloads.commit()
                results["orphans_quarantined"] = len(orphan_rows)
                logger.info(f"Successfully quarantined {len(orphan_rows)} orphaned payload records.")
            
            conn_payloads.close()
        except Exception as e:
            err = f"Orphan payload quarantine error: {e}"
            logger.error(err)
            results["errors"].append(err)

    # 2. Maintenance: VACUUM & WAL setting on dns.sqlite3
    if DNS_DB_PATH.is_file():
        try:
            conn_dns = sqlite3.connect(DNS_DB_PATH)
            conn_dns.execute("PRAGMA journal_mode = WAL;")
            conn_dns.execute("VACUUM;")
            conn_dns.close()
            results["dns_vacuumed"] = True
            logger.info("Successfully executed VACUUM and WAL mode on dns.sqlite3")
        except Exception as e:
            err = f"DNS database VACUUM error: {e}"
            logger.error(err)
            results["errors"].append(err)

    return results


def purge_quarantine(retention_days: int = 30) -> int:
    """
    Explicit cleanup pass for quarantined payloads older than retention_days.
    """
    if not PAYLOADS_DB_PATH.is_file():
        return 0
        
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    purged_count = 0
    try:
        conn = sqlite3.connect(PAYLOADS_DB_PATH)
        init_quarantine_schema(conn)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM payloads_quarantine WHERE quarantined_at < ?", (cutoff,))
        purged_count = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()
        logger.info(f"Purged {purged_count} quarantined payload records older than {retention_days} days.")
    except Exception as e:
        logger.error(f"Error purging quarantine records: {e}")
        
    return purged_count


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    res = repair_storage_integrity()
    print("Storage Health Check & Quarantine Results:", res)
