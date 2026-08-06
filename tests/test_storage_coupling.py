import unittest
import sqlite3
import uuid
from unittest.mock import patch

from app.storage.repair import repair_storage_integrity
from app.storage.database import save_investigation, router, PACKETS_DB_PATH, PAYLOADS_DB_PATH, CACHE_DB_PATH


class TestStorageCoupling(unittest.TestCase):

    def test_orphan_payload_quarantine_path(self):
        """
        Simulate crash artifact by seeding an orphan payload directly into payloads.sqlite3.
        Verify repair_storage_integrity moves it to payloads_quarantine instead of silent deletion.
        """
        fake_packet_id = 99999999
        fake_inv_id = str(uuid.uuid4())
        
        # 1. Seed orphan payload
        with router._get_connection(PAYLOADS_DB_PATH) as conn:
            conn.execute("""
                INSERT INTO payloads (packet_id, investigation_id, packet_index, payload_blob, payload_preview, mime_type, decoded_json, compression, entropy)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (fake_packet_id, fake_inv_id, 1, b"crash_payload_data", "crash preview", "plaintext", "{}", "zlib", 5.0))
            conn.commit()

        # 2. Execute health check / repair
        res = repair_storage_integrity()
        self.assertGreaterEqual(res["orphans_quarantined"], 1)

        # 3. Assert orphan is removed from payloads and archived in payloads_quarantine
        with router._get_connection(PAYLOADS_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            active_orphan = conn.execute("SELECT * FROM payloads WHERE investigation_id = ?", (fake_inv_id,)).fetchone()
            quarantined = conn.execute("SELECT * FROM payloads_quarantine WHERE investigation_id = ?", (fake_inv_id,)).fetchone()
            
            self.assertIsNone(active_orphan)
            self.assertIsNotNone(quarantined)
            self.assertEqual(quarantined["investigation_id"], fake_inv_id)
            self.assertEqual(quarantined["reason"], "Missing packet_id foreign key in packets.sqlite3")

        # 4. Assert idempotency (second run finds 0 new orphans)
        res2 = repair_storage_integrity()
        self.assertEqual(res2["orphans_quarantined"], 0)

    def test_alert_fallback_chain(self):
        """Verify anomaly dictionary with missing keys resolves safely to fallback string without crashing."""
        analysis_empty_keys = {
            "packet_rows": [],
            "anomalies": [
                {},  # completely empty dictionary
                {"title": "Custom Title Alert"},
                {"name": "Canonical Name Alert"},
            ]
        }
        
        inv_id = save_investigation("test_file.pcap", analysis_empty_keys)
        self.assertTrue(inv_id)
        
        with router._get_connection(CACHE_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT rule FROM alerts ORDER BY rowid DESC LIMIT 3").fetchall()
            rules = [r["rule"] for r in rows]
            self.assertIn("Security Anomaly", rules)
            self.assertIn("Custom Title Alert", rules)
            self.assertIn("Canonical Name Alert", rules)

    def test_packet_insert_coupling_integrity(self):
        """Verify payload insertion is linked strictly to confirmed packet IDs."""
        analysis_data = {
            "packet_rows": [
                {
                    "packet_index": 1,
                    "timestamp": "2026-07-30T12:00:00Z",
                    "length": 100,
                    "protocol": "TCP",
                    "source_ip": "10.0.0.1",
                    "destination_ip": "10.0.0.2",
                    "summary": "Test packet 1"
                },
                {
                    "packet_index": 2,
                    "timestamp": "2026-07-30T12:00:01Z",
                    "length": 150,
                    "protocol": "UDP",
                    "source_ip": "10.0.0.1",
                    "destination_ip": "10.0.0.2",
                    "summary": "Test packet 2"
                }
            ],
            "anomalies": []
        }
        
        inv_id = save_investigation("coupling_test.pcap", analysis_data)
        self.assertTrue(inv_id)
        
        with router._get_connection(PACKETS_DB_PATH) as conn:
            pkt_cnt = conn.execute("SELECT COUNT(*) FROM packets WHERE investigation_id = ?", (inv_id,)).fetchone()[0]
        with router._get_connection(PAYLOADS_DB_PATH) as conn:
            pl_cnt = conn.execute("SELECT COUNT(*) FROM payloads WHERE investigation_id = ?", (inv_id,)).fetchone()[0]
            
        self.assertEqual(pkt_cnt, 2)
        self.assertEqual(pl_cnt, 2)


if __name__ == "__main__":
    unittest.main()
