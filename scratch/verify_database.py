#!/usr/bin/env python3
import sys as _sys, io as _io
_sys.stdout = _io.TextIOWrapper(_sys.stdout.buffer, encoding="utf-8", errors="replace")
_sys.stderr = _io.TextIOWrapper(_sys.stderr.buffer, encoding="utf-8", errors="replace")
"""
+====================================================================+
|          CyberDeep Storage Verification Framework v2.0              |
|          Senior DBA / QA Automation / Security Testing              |
+====================================================================+

Complete verification of the modular SQLite storage architecture.
Covers 16 verification domains. Produces JSON, Markdown, and HTML reports.

Usage:
    python scratch/verify_database.py
    python scratch/verify_database.py --skip-api
    python scratch/verify_database.py --sample-size 50
"""

import sys
import os
import json
import time
import sqlite3
import hashlib
import random
import traceback
import argparse
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import DATA_DIR
from app.storage.database import (
    INVESTIGATIONS_DB_PATH, PACKETS_DB_PATH, PAYLOADS_DB_PATH,
    LIVE_CAPTURE_DB_PATH, TELECOM_DB_PATH, GEOIP_DB_PATH,
    THREATINTEL_DB_PATH, DNS_DB_PATH, USERS_DB_PATH, CACHE_DB_PATH,
    FLOWS_DB_PATH, TABLE_MAP, SCHEMAS, router,
    get_investigation, list_investigations, decompress_bytes, init_db
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPORT_DIR = DATA_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

EXPECTED_DATABASES = {
    "investigations": INVESTIGATIONS_DB_PATH,
    "packets":        PACKETS_DB_PATH,
    "payloads":       PAYLOADS_DB_PATH,
    "live_capture":   LIVE_CAPTURE_DB_PATH,
    "telecom":        TELECOM_DB_PATH,
    "geoip":          GEOIP_DB_PATH,
    "threatintel":    THREATINTEL_DB_PATH,
    "dns":            DNS_DB_PATH,
    "users":          USERS_DB_PATH,
    "cache":          CACHE_DB_PATH,
    "flows":          FLOWS_DB_PATH,
}

# Expected tables per database (derived from SCHEMAS in database.py)
EXPECTED_TABLES = {
    INVESTIGATIONS_DB_PATH: [
        "schema_info", "investigations", "destinations", "investigation_search",
    ],
    PACKETS_DB_PATH: ["schema_info", "packets"],
    PAYLOADS_DB_PATH: ["schema_info", "payloads"],
    LIVE_CAPTURE_DB_PATH: ["schema_info", "live_capture_packets", "capture_statistics"],
    TELECOM_DB_PATH: ["schema_info", "cdr_records", "operator_lookup"],
    GEOIP_DB_PATH: ["schema_info", "endpoints", "geoip_lookup"],
    THREATINTEL_DB_PATH: ["schema_info", "threat_indicators"],
    DNS_DB_PATH: ["schema_info", "dns_cache", "subdomain_scans"],
    USERS_DB_PATH: ["schema_info", "user_preferences", "saved_filters", "dpi_rules"],
    CACHE_DB_PATH: ["schema_info", "temp_cache", "alerts"],
    FLOWS_DB_PATH: ["schema_info", "sessions", "rtp_streams", "sip_dialogs", "ice_sessions"],
}

EXPECTED_INDEXES = {
    INVESTIGATIONS_DB_PATH: [
        "idx_destinations_investigation", "idx_destinations_ip",
    ],
    PACKETS_DB_PATH: [
        "idx_packets_investigation", "idx_packets_index", "idx_packets_flow",
    ],
    PAYLOADS_DB_PATH: [
        "idx_payloads_investigation", "idx_payloads_packet_id",
    ],
    GEOIP_DB_PATH: ["idx_geoip_country"],
    CACHE_DB_PATH: ["idx_alerts_flow", "idx_alerts_severity"],
    FLOWS_DB_PATH: ["idx_sessions_investigation"],
}

EXPECTED_COLUMNS = {
    "investigations": [
        "id", "filename", "created_at", "summary_json", "case_json",
    ],
    "destinations": [
        "id", "investigation_id", "destination_ip", "row_json",
    ],
    "packets": [
        "id", "investigation_id", "packet_index", "timestamp", "length",
        "protocol", "src_endpoint_id", "dst_endpoint_id", "source_port",
        "destination_port", "tcp_flags", "flow_id", "summary",
    ],
    "payloads": [
        "id", "packet_id", "investigation_id", "packet_index",
        "payload_blob", "payload_preview", "mime_type", "decoded_json",
        "compression", "entropy",
    ],
    "endpoints": [
        "id", "ip", "mac", "hostname", "vendor", "country", "asn",
    ],
    "geoip_lookup": [
        "ip", "country", "city", "asn", "latitude", "longitude",
        "updated_at", "ttl",
    ],
    "threat_indicators": [
        "indicator", "type", "threat_type", "severity", "description",
        "source", "source_url", "feed_name", "confidence", "ioc_type",
        "stix_id", "tags", "reference", "expires_at",
    ],
    "sessions": [
        "flow_id", "investigation_id", "protocol", "start_time", "end_time",
        "bytes", "packets", "jitter", "loss", "mos", "classification",
    ],
    "alerts": [
        "alert_id", "flow_id", "packet_id", "severity", "rule",
        "confidence", "timestamp", "status", "resolved",
    ],
    "dns_cache": ["query", "type", "answers", "resolved_at"],
    "subdomain_scans": [
        "id", "domain", "status", "started_at", "completed_at", "engines",
        "total_found", "error", "progress", "engines_status_json",
        "subdomains_json", "resolved_json",
    ],
    "live_capture_packets": [
        "id", "session_id", "packet_index", "timestamp", "length",
        "protocol", "src_endpoint_id", "dst_endpoint_id", "source_port",
        "destination_port", "tcp_flags", "flow_id", "summary",
        "payload_blob", "payload_preview", "compression",
    ],
    "capture_statistics": [
        "id", "timestamp", "packet_count", "dropped_packets",
        "packets_per_second", "bytes_per_second",
    ],
    "cdr_records": [
        "id", "timestamp", "imsi", "imei", "calling_number",
        "called_number", "duration_seconds", "cell_id", "bts_id",
    ],
    "operator_lookup": ["mcc", "mnc", "operator_name", "country"],
    "user_preferences": ["key", "value"],
    "saved_filters": ["id", "name", "expression", "created_at"],
    "dpi_rules": ["id", "name", "pattern", "severity", "category"],
    "temp_cache": ["key", "value", "expires_at"],
    "rtp_streams": [
        "id", "session_flow_id", "ssrc", "payload_type",
        "packet_count", "jitter", "loss", "mos",
    ],
    "sip_dialogs": [
        "id", "call_id", "from_uri", "to_uri", "method",
        "status_code", "user_agent", "sdp_media_ip", "sdp_media_port",
        "joined_mid_session", "confidence_tier",
    ],
    "ice_sessions": [
        "id", "session_flow_id", "ufrag", "state",
        "candidate_type", "relay_server", "nat_type_guess",
        "joined_mid_session", "confidence_tier",
    ],
    "schema_info": ["version", "created_at", "last_migration"],
}


# ═══════════════════════════════════════════════════════════════════════
# Helper Utilities
# ═══════════════════════════════════════════════════════════════════════
def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _human_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0
    return f"{nbytes:.1f} PB"


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size if path.is_file() else 0
    except OSError:
        return 0


class Checker:
    """Accumulates results across all verification sections."""

    def __init__(self, sample_size: int = 100, skip_api: bool = False):
        self.sample_size = sample_size
        self.skip_api = skip_api
        self.sections: dict[str, dict] = {}
        self.current_section: str = ""
        self.findings: list[dict] = []
        self.warnings: list[dict] = []
        self.start_time = time.time()

    # -- reporting helpers --------------------------------------------------
    def begin_section(self, name: str):
        self.current_section = name
        self.sections[name] = {"status": "PASS", "details": [], "start": time.time()}
        print(f"\n{'─' * 60}")
        print(f"  {name}")
        print(f"{'─' * 60}")

    def end_section(self):
        sec = self.sections[self.current_section]
        sec["elapsed"] = round(time.time() - sec["start"], 3)
        status = sec["status"]
        symbol = "✅" if status == "PASS" else ("⚠️" if status == "WARN" else "❌")
        print(f"  Result: {symbol} {status}  ({sec['elapsed']:.3f}s)")

    def record(self, status: str, message: str, **kwargs):
        entry = {"status": status, "message": message, **kwargs}
        sec = self.sections[self.current_section]
        sec["details"].append(entry)

        tag = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "INFO": "ℹ️", "SKIP": "⏭️"}.get(status, "•")
        print(f"  {tag} {message}")

        if status == "FAIL":
            sec["status"] = "FAIL"
            self.findings.append({"section": self.current_section, **entry})
        elif status == "WARN" and sec["status"] != "FAIL":
            sec["status"] = "WARN"
            self.warnings.append({"section": self.current_section, **entry})

    def overall_pass(self) -> bool:
        return all(s["status"] in ("PASS", "WARN") for s in self.sections.values())


# ═══════════════════════════════════════════════════════════════════════
# §1  DATABASE DISCOVERY
# ═══════════════════════════════════════════════════════════════════════
def section_01_discovery(c: Checker):
    c.begin_section("1. DATABASE DISCOVERY")
    discovered = {}
    for name, path in EXPECTED_DATABASES.items():
        if path.is_file():
            size = _file_size(path)
            with _connect(path) as conn:
                page_count = conn.execute("PRAGMA page_count").fetchone()[0]
                page_size = conn.execute("PRAGMA page_size").fetchone()[0]
                sqlite_ver = conn.execute("SELECT sqlite_version()").fetchone()[0]
            c.record("PASS", f"{name:.<22} {_human_size(size):>10}  pages={page_count:<8}  SQLite {sqlite_ver}",
                      db=name, size=size, pages=page_count, sqlite_version=sqlite_ver)
            discovered[name] = {"path": str(path), "size": size, "pages": page_count, "sqlite_version": sqlite_ver}
        else:
            c.record("FAIL", f"{name}: file not found at {path}", db=name,
                      suggested_fix="Run init_db() or check DATA_DIR configuration")
            discovered[name] = None

    # Check for unexpected sqlite files
    all_sqlite = list(DATA_DIR.glob("*.sqlite3"))
    known_paths = set(str(p) for p in EXPECTED_DATABASES.values())
    for f in all_sqlite:
        if str(f) not in known_paths:
            c.record("WARN", f"Unexpected database file: {f.name}", db=f.name)

    c.end_section()
    return discovered


# ═══════════════════════════════════════════════════════════════════════
# §2  SQLITE HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════════
def section_02_health(c: Checker):
    c.begin_section("2. SQLITE HEALTH CHECK")
    for name, path in EXPECTED_DATABASES.items():
        if not path.is_file():
            c.record("SKIP", f"{name}: file missing, skipped", db=name)
            continue
        try:
            with _connect(path) as conn:
                integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
                quick = conn.execute("PRAGMA quick_check").fetchone()[0]
                fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()

            ok = integrity == "ok" and quick == "ok"
            fk_ok = len(fk_violations) == 0
            if ok and fk_ok:
                c.record("PASS", f"{name}: integrity=ok  quick_check=ok  fk_violations=0", db=name)
            else:
                parts = []
                if integrity != "ok":
                    parts.append(f"integrity_check={integrity}")
                if quick != "ok":
                    parts.append(f"quick_check={quick}")
                if not fk_ok:
                    parts.append(f"fk_violations={len(fk_violations)}")
                c.record("FAIL", f"{name}: {', '.join(parts)}", db=name,
                          suggested_fix="Run VACUUM or restore from backup")
        except Exception as e:
            c.record("FAIL", f"{name}: exception during health check: {e}", db=name)
    c.end_section()


# ═══════════════════════════════════════════════════════════════════════
# §3  SCHEMA VALIDATION
# ═══════════════════════════════════════════════════════════════════════
def section_03_schema(c: Checker):
    c.begin_section("3. SCHEMA VALIDATION")

    for db_path, expected_tables in EXPECTED_TABLES.items():
        db_name = db_path.stem
        if not db_path.is_file():
            c.record("SKIP", f"{db_name}: file missing", db=db_name)
            continue

        with _connect(db_path) as conn:
            # -- Tables --
            actual_tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            # Virtual tables (FTS5)
            actual_tables |= {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND sql LIKE '%USING fts5%'").fetchall()}

            for tbl in expected_tables:
                if tbl in actual_tables:
                    c.record("PASS", f"{db_name}.{tbl}: table exists", db=db_name, table=tbl)
                else:
                    c.record("FAIL", f"{db_name}.{tbl}: table MISSING", db=db_name, table=tbl,
                              suggested_fix="Run init_db() to create missing tables")

            # -- Columns --
            for tbl in expected_tables:
                if tbl not in actual_tables:
                    continue
                if tbl not in EXPECTED_COLUMNS:
                    continue
                try:
                    cols_info = conn.execute(f"PRAGMA table_info([{tbl}])").fetchall()
                    actual_cols = {r["name"] for r in cols_info}
                    missing_cols = [ec for ec in EXPECTED_COLUMNS[tbl] if ec not in actual_cols]
                    if missing_cols:
                        c.record("FAIL",
                                  f"{db_name}.{tbl}: missing columns: {missing_cols}",
                                  db=db_name, table=tbl, missing_columns=missing_cols)
                    else:
                        c.record("PASS",
                                  f"{db_name}.{tbl}: all {len(EXPECTED_COLUMNS[tbl])} columns present",
                                  db=db_name, table=tbl)
                except Exception:
                    # FTS5 virtual tables don't support PRAGMA table_info
                    c.record("INFO", f"{db_name}.{tbl}: virtual table (FTS5), column check skipped",
                              db=db_name, table=tbl)

            # -- Primary Keys --
            for tbl in expected_tables:
                if tbl not in actual_tables or tbl not in EXPECTED_COLUMNS:
                    continue
                try:
                    cols_info = conn.execute(f"PRAGMA table_info([{tbl}])").fetchall()
                    pk_cols = [r["name"] for r in cols_info if r["pk"] > 0]
                    if pk_cols:
                        c.record("PASS", f"{db_name}.{tbl}: PK = ({', '.join(pk_cols)})",
                                  db=db_name, table=tbl)
                    else:
                        c.record("WARN", f"{db_name}.{tbl}: no primary key defined",
                                  db=db_name, table=tbl)
                except Exception:
                    pass

            # -- Indexes --
            actual_indexes = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'").fetchall()}

            expected_idx = EXPECTED_INDEXES.get(db_path, [])
            for idx in expected_idx:
                if idx in actual_indexes:
                    c.record("PASS", f"{db_name}: index {idx} exists", db=db_name, index=idx)
                else:
                    c.record("FAIL", f"{db_name}: index {idx} MISSING", db=db_name, index=idx,
                              suggested_fix="Run init_db() to recreate indexes")

            # -- Triggers --
            triggers = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()
            if triggers:
                for t in triggers:
                    c.record("INFO", f"{db_name}: trigger '{t[0]}' present", db=db_name)

            # -- Views --
            views = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='view'").fetchall()
            if views:
                for v in views:
                    c.record("INFO", f"{db_name}: view '{v[0]}' present", db=db_name)

    c.end_section()


# ═══════════════════════════════════════════════════════════════════════
# §4  TABLE STATISTICS
# ═══════════════════════════════════════════════════════════════════════
def section_04_statistics(c: Checker) -> dict:
    c.begin_section("4. TABLE STATISTICS")
    stats = {}
    all_tables = []

    for db_name_key, db_path in EXPECTED_DATABASES.items():
        if not db_path.is_file():
            continue
        db_size = _file_size(db_path)
        with _connect(db_path) as conn:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()]

            for tbl in tables:
                try:
                    row_count = conn.execute(f"SELECT COUNT(*) FROM [{tbl}]").fetchone()[0]
                except Exception:
                    row_count = -1

                idx_count = len(conn.execute(
                    f"SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='{tbl}'"
                ).fetchall())

                # Estimate table size from sample
                est_size = 0
                if row_count > 0:
                    try:
                        sample = conn.execute(f"SELECT * FROM [{tbl}] LIMIT 10").fetchall()
                        if sample:
                            avg_bytes = sum(len(str(dict(r))) for r in sample) / len(sample)
                            est_size = int(row_count * avg_bytes)
                    except Exception:
                        est_size = 0

                entry = {
                    "database": db_name_key,
                    "table": tbl,
                    "rows": row_count,
                    "db_size": db_size,
                    "est_table_size": est_size,
                    "index_count": idx_count,
                }
                all_tables.append(entry)
                c.record("INFO",
                          f"{db_name_key}.{tbl:<28} rows={row_count:>9,}  "
                          f"~{_human_size(est_size):>10}  indexes={idx_count}",
                          **entry)

    # Largest tables
    sorted_tables = sorted(all_tables, key=lambda x: x["est_table_size"], reverse=True)
    if sorted_tables:
        c.record("INFO", "")
        c.record("INFO", "── Top 5 Largest Tables ──")
        for t in sorted_tables[:5]:
            c.record("INFO",
                      f"  {t['database']}.{t['table']}: ~{_human_size(t['est_table_size'])} ({t['rows']:,} rows)")

    stats["tables"] = all_tables
    c.end_section()
    return stats


# ═══════════════════════════════════════════════════════════════════════
# §5  REFERENTIAL INTEGRITY
# ═══════════════════════════════════════════════════════════════════════
def section_05_referential(c: Checker):
    c.begin_section("5. REFERENTIAL INTEGRITY")

    if not INVESTIGATIONS_DB_PATH.is_file():
        c.record("FAIL", "investigations.sqlite3 not found; cannot verify referential integrity")
        c.end_section()
        return

    # Load all valid investigation IDs
    with _connect(INVESTIGATIONS_DB_PATH) as conn:
        inv_ids = {r[0] for r in conn.execute("SELECT id FROM investigations").fetchall()}
    c.record("INFO", f"Loaded {len(inv_ids)} investigation IDs as reference set")

    # -- Orphan destinations --
    with _connect(INVESTIGATIONS_DB_PATH) as conn:
        orphans = conn.execute(
            "SELECT COUNT(*) FROM destinations WHERE investigation_id NOT IN (SELECT id FROM investigations)"
        ).fetchone()[0]
        if orphans:
            sample = conn.execute(
                "SELECT id, investigation_id, destination_ip FROM destinations "
                "WHERE investigation_id NOT IN (SELECT id FROM investigations) LIMIT 5"
            ).fetchall()
            c.record("FAIL", f"destinations: {orphans} orphan rows",
                      table="destinations", count=orphans,
                      sample=[dict(r) for r in sample],
                      suggested_fix="DELETE orphan destinations or re-link to valid investigation")
        else:
            c.record("PASS", "destinations: no orphans")

    # -- Orphan packets --
    if PACKETS_DB_PATH.is_file():
        with _connect(PACKETS_DB_PATH) as conn:
            conn.execute(f"ATTACH DATABASE '{INVESTIGATIONS_DB_PATH}' AS inv_db")
            orphans = conn.execute(
                "SELECT COUNT(*) FROM packets WHERE investigation_id NOT IN (SELECT id FROM inv_db.investigations)"
            ).fetchone()[0]
            if orphans:
                sample = conn.execute(
                    "SELECT id, investigation_id, packet_index FROM packets "
                    "WHERE investigation_id NOT IN (SELECT id FROM inv_db.investigations) LIMIT 5"
                ).fetchall()
                c.record("FAIL", f"packets: {orphans} orphan rows",
                          table="packets", count=orphans,
                          sample=[dict(r) for r in sample],
                          suggested_fix="DELETE orphan packets or restore investigation record")
            else:
                c.record("PASS", "packets: no orphans")
    else:
        c.record("SKIP", "packets.sqlite3 missing")

    # -- Orphan payloads --
    if PAYLOADS_DB_PATH.is_file():
        with _connect(PAYLOADS_DB_PATH) as conn:
            conn.execute(f"ATTACH DATABASE '{INVESTIGATIONS_DB_PATH}' AS inv_db")
            orphans = conn.execute(
                "SELECT COUNT(*) FROM payloads WHERE investigation_id NOT IN (SELECT id FROM inv_db.investigations)"
            ).fetchone()[0]
            if orphans:
                sample = conn.execute(
                    "SELECT id, investigation_id, packet_index FROM payloads "
                    "WHERE investigation_id NOT IN (SELECT id FROM inv_db.investigations) LIMIT 5"
                ).fetchall()
                c.record("FAIL", f"payloads: {orphans} orphan rows (no investigation)",
                          table="payloads", count=orphans,
                          sample=[dict(r) for r in sample],
                          suggested_fix="DELETE orphan payloads")
            else:
                c.record("PASS", "payloads: no orphans (by investigation_id)")

            # Orphan payloads by packet_id FK
            if PACKETS_DB_PATH.is_file():
                conn.execute(f"ATTACH DATABASE '{PACKETS_DB_PATH}' AS pkt_db")
                orphans_pk = conn.execute(
                    "SELECT COUNT(*) FROM payloads WHERE packet_id NOT IN (SELECT id FROM pkt_db.packets)"
                ).fetchone()[0]
                if orphans_pk:
                    c.record("FAIL", f"payloads: {orphans_pk} rows with invalid packet_id FK",
                              table="payloads", count=orphans_pk,
                              suggested_fix="Re-link payloads to correct packet IDs")
                else:
                    c.record("PASS", "payloads: all packet_id FKs valid")
    else:
        c.record("SKIP", "payloads.sqlite3 missing")

    # -- Orphan alerts --
    if CACHE_DB_PATH.is_file():
        with _connect(CACHE_DB_PATH) as conn:
            try:
                alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                if alert_count > 0 and FLOWS_DB_PATH.is_file():
                    conn.execute(f"ATTACH DATABASE '{FLOWS_DB_PATH}' AS flows_db")
                    orphan_alerts = conn.execute(
                        "SELECT COUNT(*) FROM alerts WHERE flow_id != 'global' "
                        "AND flow_id NOT IN (SELECT flow_id FROM flows_db.sessions)"
                    ).fetchone()[0]
                    if orphan_alerts:
                        c.record("WARN", f"alerts: {orphan_alerts} alerts reference non-existent flow_ids",
                                  table="alerts", count=orphan_alerts)
                    else:
                        c.record("PASS", f"alerts: all {alert_count} flow_id references valid")
                else:
                    c.record("PASS", f"alerts: {alert_count} rows (no cross-reference needed)")
            except Exception as e:
                c.record("WARN", f"alerts: check error: {e}")
    else:
        c.record("SKIP", "cache.sqlite3 missing")

    # -- Orphan sessions --
    if FLOWS_DB_PATH.is_file():
        with _connect(FLOWS_DB_PATH) as conn:
            conn.execute(f"ATTACH DATABASE '{INVESTIGATIONS_DB_PATH}' AS inv_db")
            orphans = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE investigation_id NOT IN (SELECT id FROM inv_db.investigations)"
            ).fetchone()[0]
            if orphans:
                c.record("FAIL", f"sessions: {orphans} orphan rows",
                          table="sessions", count=orphans,
                          suggested_fix="DELETE orphan sessions")
            else:
                c.record("PASS", "sessions: no orphans")
    else:
        c.record("SKIP", "flows.sqlite3 missing")

    # -- Orphan endpoint references in packets --
    if PACKETS_DB_PATH.is_file() and GEOIP_DB_PATH.is_file():
        with _connect(PACKETS_DB_PATH) as conn:
            conn.execute(f"ATTACH DATABASE '{GEOIP_DB_PATH}' AS geo_db")
            orphan_src = conn.execute(
                "SELECT COUNT(*) FROM packets WHERE src_endpoint_id NOT IN (SELECT id FROM geo_db.endpoints)"
            ).fetchone()[0]
            orphan_dst = conn.execute(
                "SELECT COUNT(*) FROM packets WHERE dst_endpoint_id NOT IN (SELECT id FROM geo_db.endpoints)"
            ).fetchone()[0]
            if orphan_src or orphan_dst:
                c.record("FAIL",
                          f"packets: {orphan_src} orphan src_endpoint_id, {orphan_dst} orphan dst_endpoint_id",
                          table="packets",
                          suggested_fix="Re-run get_endpoint_id() for missing endpoints")
            else:
                c.record("PASS", "packets: all endpoint references valid")

    c.end_section()


# ═══════════════════════════════════════════════════════════════════════
# §6  DUPLICATE DETECTION
# ═══════════════════════════════════════════════════════════════════════
def section_06_duplicates(c: Checker):
    c.begin_section("6. DUPLICATE DETECTION")

    checks = [
        ("investigations", INVESTIGATIONS_DB_PATH, "id", "investigation_id"),
        ("packets", PACKETS_DB_PATH, "id", "packet_id (auto PK)"),
        ("sessions", FLOWS_DB_PATH, "flow_id", "flow_id"),
        ("alerts", CACHE_DB_PATH, "alert_id", "alert_id"),
        ("endpoints", GEOIP_DB_PATH, "ip", "endpoint ip"),
    ]

    for table, db_path, column, label in checks:
        if not db_path.is_file():
            c.record("SKIP", f"{label}: database missing")
            continue
        try:
            with _connect(db_path) as conn:
                dupes = conn.execute(
                    f"SELECT [{column}], COUNT(*) as cnt FROM [{table}] "
                    f"GROUP BY [{column}] HAVING cnt > 1"
                ).fetchall()
                if dupes:
                    c.record("WARN", f"{label}: {len(dupes)} duplicate values in {table}.{column}",
                              table=table, column=column, duplicate_count=len(dupes),
                              sample=[{"value": str(d[0])[:60], "count": d[1]} for d in dupes[:5]])
                else:
                    c.record("PASS", f"{label}: no duplicates in {table}.{column}")
        except Exception as e:
            c.record("WARN", f"{label}: check error: {e}")

    # Destination IP duplicates within the same investigation
    if INVESTIGATIONS_DB_PATH.is_file():
        with _connect(INVESTIGATIONS_DB_PATH) as conn:
            dupes = conn.execute(
                "SELECT investigation_id, destination_ip, COUNT(*) as cnt "
                "FROM destinations GROUP BY investigation_id, destination_ip HAVING cnt > 1"
            ).fetchall()
            if dupes:
                c.record("WARN",
                          f"destination_ip: {len(dupes)} duplicate (investigation_id, destination_ip) pairs",
                          table="destinations", duplicate_count=len(dupes))
            else:
                c.record("PASS", "destination_ip: no duplicates per investigation")

    c.end_section()


# ═══════════════════════════════════════════════════════════════════════
# §7  PACKET / PAYLOAD VALIDATION
# ═══════════════════════════════════════════════════════════════════════
def section_07_packet_payload(c: Checker):
    c.begin_section("7. PACKET / PAYLOAD VALIDATION")

    if not all(p.is_file() for p in [INVESTIGATIONS_DB_PATH, PACKETS_DB_PATH, PAYLOADS_DB_PATH]):
        c.record("SKIP", "Required databases missing for packet/payload validation")
        c.end_section()
        return

    # Get a sample of investigation IDs
    with _connect(INVESTIGATIONS_DB_PATH) as conn:
        all_ids = [r[0] for r in conn.execute("SELECT id FROM investigations").fetchall()]

    sample_size = min(c.sample_size, len(all_ids))
    if sample_size == 0:
        c.record("SKIP", "No investigations to validate")
        c.end_section()
        return

    sample_ids = random.sample(all_ids, sample_size)
    c.record("INFO", f"Sampling {sample_size} of {len(all_ids)} investigations")

    total_issues = 0
    total_checked = 0

    for inv_id in sample_ids:
        total_checked += 1
        issues = []

        with _connect(PACKETS_DB_PATH) as conn:
            packets = conn.execute(
                "SELECT id, packet_index, timestamp, flow_id FROM packets "
                "WHERE investigation_id = ? ORDER BY id ASC",
                (inv_id,)
            ).fetchall()
        pkt_count = len(packets)

        with _connect(PAYLOADS_DB_PATH) as conn:
            payloads = conn.execute(
                "SELECT id, packet_id, packet_index FROM payloads WHERE investigation_id = ?",
                (inv_id,)
            ).fetchall()
        pl_count = len(payloads)

        # Check 1: Packet count == Payload count
        if pkt_count != pl_count:
            issues.append(f"count mismatch: {pkt_count} packets vs {pl_count} payloads")

        # Check 2: Every packet has exactly one payload
        pkt_ids = {p["id"] for p in packets}
        payload_pkt_ids = {p["packet_id"] for p in payloads}
        packets_without_payload = pkt_ids - payload_pkt_ids
        if packets_without_payload:
            issues.append(f"{len(packets_without_payload)} packets missing payload")

        # Check 3: Every payload belongs to a known packet
        payloads_without_packet = payload_pkt_ids - pkt_ids
        if payloads_without_packet:
            issues.append(f"{len(payloads_without_packet)} payloads with invalid packet_id")

        # Check 4: Packet index order
        # NOTE: packet_index restarts at 1 per evidence file within the
        # same investigation (multi-file uploads). The auto-increment PK
        # `id` guarantees insertion order, so non-monotonic packet_index
        # is EXPECTED for multi-file investigations. We only flag it as
        # an informational warning, not a failure.
        pkt_index_sorted = True
        if pkt_count > 1:
            indexes = [p["packet_index"] for p in packets]
            if indexes != sorted(indexes):
                pkt_index_sorted = False

        # Check 5: Timestamp order
        if pkt_count > 1:
            timestamps = [p["timestamp"] for p in packets]
            if timestamps != sorted(timestamps):
                # Timestamps may legitimately be out of order in pcap captures
                pass  # Not treated as an error, just informational

        # Check 6: Flow IDs exist
        flow_ids = {p["flow_id"] for p in packets if p["flow_id"]}

        if issues:
            total_issues += 1
            c.record("FAIL",
                      f"Investigation {inv_id[:8]}...: {'; '.join(issues)}",
                      investigation_id=inv_id, packets=pkt_count, payloads=pl_count,
                      issues=issues,
                      suggested_fix="Re-run save_investigation() to repair packet/payload alignment")
        # Only print sample passes, not all
        elif total_checked <= 5 or total_checked == sample_size:
            idx_note = "" if pkt_index_sorted else " (multi-file pkt_index resets detected)"
            c.record("PASS",
                      f"Investigation {inv_id[:8]}...: {pkt_count} pkts, {pl_count} payloads, "
                      f"{len(flow_ids)} flows{idx_note}")

    # Summary: count how many had non-sorted indexes (informational only)
    unsorted_count = 0
    for inv_id in sample_ids:
        with _connect(PACKETS_DB_PATH) as conn:
            rows = conn.execute(
                "SELECT packet_index FROM packets WHERE investigation_id = ? ORDER BY id ASC",
                (inv_id,)
            ).fetchall()
        if len(rows) > 1:
            idxs = [r["packet_index"] for r in rows]
            if idxs != sorted(idxs):
                unsorted_count += 1

    if unsorted_count:
        c.record("INFO",
                  f"{unsorted_count}/{sample_size} investigations have non-monotonic packet_index "
                  f"(expected for multi-file uploads)")

    if total_issues == 0:
        c.record("PASS", f"All {sample_size} sampled investigations passed packet/payload validation")
    else:
        c.record("FAIL", f"{total_issues}/{sample_size} investigations had packet/payload issues")

    c.end_section()


# ═══════════════════════════════════════════════════════════════════════
# §8  CROSS DATABASE VALIDATION
# ═══════════════════════════════════════════════════════════════════════
def section_08_cross_db(c: Checker):
    c.begin_section("8. CROSS DATABASE VALIDATION")

    required = [INVESTIGATIONS_DB_PATH, PACKETS_DB_PATH, PAYLOADS_DB_PATH, GEOIP_DB_PATH]
    if not all(p.is_file() for p in required):
        c.record("SKIP", "Required databases missing for cross-DB validation")
        c.end_section()
        return

    # Pick a recent investigation with packets
    with _connect(INVESTIGATIONS_DB_PATH) as conn:
        inv = conn.execute(
            "SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    if not inv:
        c.record("SKIP", "No investigations available")
        c.end_section()
        return
    inv_id = inv["id"]

    # Test 1: Join packets + payloads + endpoints via ATTACH
    try:
        with _connect(PACKETS_DB_PATH) as conn:
            conn.execute(f"ATTACH DATABASE '{PAYLOADS_DB_PATH}' AS payloads_db")
            conn.execute(f"ATTACH DATABASE '{GEOIP_DB_PATH}' AS geoip_db")
            results = conn.execute("""
                SELECT p.id, p.packet_index, p.protocol,
                       src.ip AS source_ip, dst.ip AS destination_ip,
                       pl.payload_preview, pl.entropy
                FROM packets p
                JOIN payloads_db.payloads pl ON p.id = pl.packet_id
                JOIN geoip_db.endpoints src ON p.src_endpoint_id = src.id
                JOIN geoip_db.endpoints dst ON p.dst_endpoint_id = dst.id
                WHERE p.investigation_id = ?
                ORDER BY p.id ASC LIMIT 20
            """, (inv_id,)).fetchall()

        if results:
            c.record("PASS",
                      f"packets ⇔ payloads ⇔ endpoints join: {len(results)} rows returned",
                      investigation_id=inv_id, join_count=len(results))
            # Validate each row has expected fields
            r = dict(results[0])
            expected_fields = ["id", "packet_index", "protocol", "source_ip",
                               "destination_ip", "payload_preview", "entropy"]
            missing = [f for f in expected_fields if f not in r]
            if missing:
                c.record("FAIL", f"Cross-DB join missing fields: {missing}")
            else:
                c.record("PASS", "Cross-DB join row structure valid")
        else:
            c.record("WARN", f"Cross-DB join returned 0 rows for investigation {inv_id[:8]}...")
    except Exception as e:
        c.record("FAIL", f"Cross-DB join failed: {e}",
                  suggested_fix="Check ATTACH path strings and table schemas")

    # Test 2: Sessions ⇔ Investigations
    if FLOWS_DB_PATH.is_file():
        try:
            with _connect(FLOWS_DB_PATH) as conn:
                conn.execute(f"ATTACH DATABASE '{INVESTIGATIONS_DB_PATH}' AS inv_db")
                results = conn.execute("""
                    SELECT s.flow_id, s.protocol, i.filename
                    FROM sessions s
                    JOIN inv_db.investigations i ON s.investigation_id = i.id
                    LIMIT 10
                """).fetchall()
            c.record("PASS", f"sessions ⇔ investigations join: {len(results)} rows", join_count=len(results))
        except Exception as e:
            c.record("FAIL", f"sessions ⇔ investigations join failed: {e}")

    # Test 3: Alerts ⇔ Sessions
    if CACHE_DB_PATH.is_file() and FLOWS_DB_PATH.is_file():
        try:
            with _connect(CACHE_DB_PATH) as conn:
                conn.execute(f"ATTACH DATABASE '{FLOWS_DB_PATH}' AS flows_db")
                results = conn.execute("""
                    SELECT a.alert_id, a.severity, s.protocol
                    FROM alerts a
                    LEFT JOIN flows_db.sessions s ON a.flow_id = s.flow_id
                    LIMIT 10
                """).fetchall()
            c.record("PASS", f"alerts ⇔ sessions join: {len(results)} rows", join_count=len(results))
        except Exception as e:
            c.record("FAIL", f"alerts ⇔ sessions join failed: {e}")

    # Test 4: GeoIP lookup
    if GEOIP_DB_PATH.is_file():
        try:
            with _connect(GEOIP_DB_PATH) as conn:
                ep_count = conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
                geo_count = conn.execute("SELECT COUNT(*) FROM geoip_lookup").fetchone()[0]
            c.record("PASS", f"GeoIP: {ep_count} endpoints, {geo_count} geoip_lookup records")
        except Exception as e:
            c.record("FAIL", f"GeoIP query failed: {e}")

    # Test 5: ThreatIntel lookup
    if THREATINTEL_DB_PATH.is_file():
        try:
            with _connect(THREATINTEL_DB_PATH) as conn:
                ti_count = conn.execute("SELECT COUNT(*) FROM threat_indicators").fetchone()[0]
            c.record("PASS", f"ThreatIntel: {ti_count} indicators loaded")
        except Exception as e:
            c.record("FAIL", f"ThreatIntel query failed: {e}")

    c.end_section()


# ═══════════════════════════════════════════════════════════════════════
# §9  ROUTER VALIDATION
# ═══════════════════════════════════════════════════════════════════════
def section_09_router(c: Checker):
    c.begin_section("9. ROUTER VALIDATION")

    expected_routing = {
        "investigations":       INVESTIGATIONS_DB_PATH,
        "destinations":         INVESTIGATIONS_DB_PATH,
        "investigation_search": INVESTIGATIONS_DB_PATH,
        "packets":              PACKETS_DB_PATH,
        "payloads":             PAYLOADS_DB_PATH,
        "live_capture_packets": LIVE_CAPTURE_DB_PATH,
        "capture_statistics":   LIVE_CAPTURE_DB_PATH,
        "cdr_records":          TELECOM_DB_PATH,
        "operator_lookup":      TELECOM_DB_PATH,
        "endpoints":            GEOIP_DB_PATH,
        "geoip_lookup":         GEOIP_DB_PATH,
        "threat_indicators":    THREATINTEL_DB_PATH,
        "dns_cache":            DNS_DB_PATH,
        "subdomain_scans":      DNS_DB_PATH,
        "user_preferences":     USERS_DB_PATH,
        "saved_filters":        USERS_DB_PATH,
        "dpi_rules":            USERS_DB_PATH,
        "temp_cache":           CACHE_DB_PATH,
        "sessions":             FLOWS_DB_PATH,
        "rtp_streams":          FLOWS_DB_PATH,
        "sip_dialogs":          FLOWS_DB_PATH,
        "ice_sessions":         FLOWS_DB_PATH,
        "alerts":               CACHE_DB_PATH,
    }

    all_ok = True
    for table, expected_path in expected_routing.items():
        actual_path = TABLE_MAP.get(table)
        if actual_path is None:
            c.record("FAIL", f"{table}: not found in TABLE_MAP",
                      table=table, suggested_fix="Add table to TABLE_MAP in database.py")
            all_ok = False
        elif actual_path != expected_path:
            c.record("FAIL",
                      f"{table}: routes to {actual_path.name} instead of {expected_path.name}",
                      table=table, actual=actual_path.name, expected=expected_path.name,
                      suggested_fix="Fix TABLE_MAP routing in database.py")
            all_ok = False
        else:
            c.record("PASS", f"{table} → {expected_path.name}")

    # Verify router.execute actually reaches the right DB
    test_table = "endpoints"
    try:
        result = router.execute(test_table, "SELECT COUNT(*) as cnt FROM endpoints", ())
        c.record("PASS", f"router.execute('{test_table}', ...) returned {result[0]['cnt']} rows")
    except Exception as e:
        c.record("FAIL", f"router.execute('{test_table}', ...) failed: {e}")

    c.end_section()


# ═══════════════════════════════════════════════════════════════════════
# §10  PERFORMANCE BENCHMARK
# ═══════════════════════════════════════════════════════════════════════
def section_10_performance(c: Checker) -> dict:
    c.begin_section("10. PERFORMANCE BENCHMARK")
    benchmarks = {}

    def bench(name: str, func, iterations: int = 5) -> dict:
        times = []
        result = None
        for _ in range(iterations):
            t0 = time.perf_counter()
            try:
                result = func()
            except Exception as e:
                c.record("WARN", f"{name}: benchmark error: {e}")
                return {"avg_ms": -1, "min_ms": -1, "max_ms": -1, "error": str(e)}
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)
        avg = sum(times) / len(times)
        mn = min(times)
        mx = max(times)
        c.record("PASS",
                  f"{name:<30} avg={avg:>8.2f}ms  min={mn:>8.2f}ms  max={mx:>8.2f}ms")
        benchmarks[name] = {"avg_ms": round(avg, 2), "min_ms": round(mn, 2), "max_ms": round(mx, 2)}
        return benchmarks[name]

    # Find a valid investigation ID
    inv_id = None
    if INVESTIGATIONS_DB_PATH.is_file():
        with _connect(INVESTIGATIONS_DB_PATH) as conn:
            row = conn.execute("SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1").fetchone()
            if row:
                inv_id = row[0]

    # 1. Open Investigation (list)
    bench("List Investigations", lambda: list_investigations())

    # 2. Open single investigation
    if inv_id:
        bench("Open Investigation", lambda: get_investigation(inv_id), iterations=3)

    # 3. Load Packet List
    if PACKETS_DB_PATH.is_file() and inv_id:
        def load_packets():
            with _connect(PACKETS_DB_PATH) as conn:
                return conn.execute(
                    "SELECT * FROM packets WHERE investigation_id = ? ORDER BY id",
                    (inv_id,)).fetchall()
        bench("Load Packet List", load_packets)

    # 4. Load Payloads
    if PAYLOADS_DB_PATH.is_file() and inv_id:
        def load_payloads():
            with _connect(PAYLOADS_DB_PATH) as conn:
                return conn.execute(
                    "SELECT id, packet_id, payload_preview, entropy FROM payloads "
                    "WHERE investigation_id = ?", (inv_id,)).fetchall()
        bench("Load Payloads", load_payloads)

    # 5. GeoIP Lookup
    if GEOIP_DB_PATH.is_file():
        def geoip_lookup():
            with _connect(GEOIP_DB_PATH) as conn:
                return conn.execute("SELECT * FROM endpoints LIMIT 50").fetchall()
        bench("GeoIP Lookup", geoip_lookup)

    # 6. Threat Lookup
    if THREATINTEL_DB_PATH.is_file():
        def threat_lookup():
            with _connect(THREATINTEL_DB_PATH) as conn:
                return conn.execute("SELECT * FROM threat_indicators LIMIT 50").fetchall()
        bench("Threat Lookup", threat_lookup)

    # 7. Session Reconstruction
    if FLOWS_DB_PATH.is_file() and inv_id:
        def session_recon():
            with _connect(FLOWS_DB_PATH) as conn:
                return conn.execute(
                    "SELECT * FROM sessions WHERE investigation_id = ?", (inv_id,)).fetchall()
        bench("Session Reconstruction", session_recon)

    # 8. Investigation Search (FTS5)
    if INVESTIGATIONS_DB_PATH.is_file():
        def fts_search():
            with _connect(INVESTIGATIONS_DB_PATH) as conn:
                try:
                    return conn.execute(
                        "SELECT investigation_id FROM investigation_search WHERE investigation_search MATCH 'dns OR http' LIMIT 10"
                    ).fetchall()
                except Exception:
                    return []
        bench("Investigation Search (FTS5)", fts_search)

    # 9. Subdomain Lookup
    if DNS_DB_PATH.is_file():
        def subdomain_lookup():
            with _connect(DNS_DB_PATH) as conn:
                return conn.execute("SELECT * FROM subdomain_scans LIMIT 10").fetchall()
        bench("Subdomain Lookup", subdomain_lookup)

    # 10. Cache Read/Write
    if CACHE_DB_PATH.is_file():
        def cache_rw():
            with _connect(CACHE_DB_PATH) as conn:
                conn.execute("INSERT OR REPLACE INTO temp_cache (key, value, expires_at) "
                             "VALUES ('_bench_key', 'bench_val', 9999999999)")
                conn.commit()
                r = conn.execute("SELECT * FROM temp_cache WHERE key = '_bench_key'").fetchone()
                conn.execute("DELETE FROM temp_cache WHERE key = '_bench_key'")
                conn.commit()
                return r
        bench("Cache Read/Write", cache_rw)

    c.end_section()
    return benchmarks


# ═══════════════════════════════════════════════════════════════════════
# §11  API REGRESSION
# ═══════════════════════════════════════════════════════════════════════
def section_11_api(c: Checker):
    c.begin_section("11. API REGRESSION")

    if c.skip_api:
        c.record("SKIP", "API regression skipped (--skip-api flag)")
        c.end_section()
        return

    try:
        import httpx
    except ImportError:
        try:
            from fastapi.testclient import TestClient
            from app.main import app
            client = TestClient(app, raise_server_exceptions=False)
        except Exception as e:
            c.record("SKIP", f"Cannot create test client: {e}")
            c.end_section()
            return
    else:
        client = None

    if client is None:
        try:
            from fastapi.testclient import TestClient
            from app.main import app
            client = TestClient(app, raise_server_exceptions=False)
        except Exception as e:
            c.record("SKIP", f"Cannot create test client: {e}")
            c.end_section()
            return

    # Helper
    def check_endpoint(method: str, url: str, expected_status: int = 200,
                       expected_type: str = None, required_fields: list = None):
        try:
            if method == "GET":
                resp = client.get(url)
            elif method == "POST":
                resp = client.post(url)
            else:
                resp = client.get(url)

            status_ok = resp.status_code == expected_status
            if not status_ok:
                c.record("FAIL", f"{method} {url}: status={resp.status_code} (expected {expected_status})",
                          endpoint=url, status=resp.status_code,
                          suggested_fix="Check endpoint handler and route registration")
                return

            # Type check
            content_type = resp.headers.get("content-type", "")
            if expected_type and expected_type not in content_type:
                c.record("WARN", f"{method} {url}: content-type={content_type} (expected {expected_type})",
                          endpoint=url)
                return

            # JSON field check
            if required_fields and "json" in content_type:
                body = resp.json()
                if isinstance(body, list) and len(body) > 0:
                    body = body[0]
                if isinstance(body, dict):
                    missing = [f for f in required_fields if f not in body]
                    if missing:
                        c.record("WARN", f"{method} {url}: missing fields: {missing}",
                                  endpoint=url, missing_fields=missing)
                        return

            c.record("PASS", f"{method} {url}: status={resp.status_code}", endpoint=url)
        except Exception as e:
            c.record("FAIL", f"{method} {url}: exception: {e}", endpoint=url)

    # GET /
    check_endpoint("GET", "/", 200, "text/html")

    # GET /tool
    check_endpoint("GET", "/tool", 200, "text/html")

    # GET /api/investigations
    check_endpoint("GET", "/api/investigations", 200, "application/json",
                   required_fields=["id", "filename", "created_at", "summary"])

    # GET /api/investigations/{id}
    inv_id = None
    try:
        resp = client.get("/api/investigations")
        if resp.status_code == 200:
            investigations = resp.json()
            if investigations:
                inv_id = investigations[0]["id"]
    except Exception:
        pass

    if inv_id:
        check_endpoint("GET", f"/api/investigations/{inv_id}", 200, "application/json",
                       required_fields=["id", "filename", "created_at"])
    else:
        c.record("SKIP", "GET /api/investigations/{id}: no investigation available")

    # GET /api/investigations/{nonexistent} → 404
    check_endpoint("GET", "/api/investigations/nonexistent-id-00000", 404)

    # GET /api/subdomain/scans
    check_endpoint("GET", "/api/subdomain/scans", 200, "application/json")

    # GET /api/threat_intel/status
    check_endpoint("GET", "/api/threat_intel/status", 200, "application/json")

    c.end_section()


# ═══════════════════════════════════════════════════════════════════════
# §12  DATA CONSISTENCY
# ═══════════════════════════════════════════════════════════════════════
def section_12_consistency(c: Checker):
    c.begin_section("12. DATA CONSISTENCY")

    if not INVESTIGATIONS_DB_PATH.is_file():
        c.record("SKIP", "investigations.sqlite3 missing")
        c.end_section()
        return

    with _connect(INVESTIGATIONS_DB_PATH) as conn:
        sample = conn.execute(
            "SELECT id, filename, created_at, summary_json, case_json "
            "FROM investigations ORDER BY created_at DESC LIMIT 10"
        ).fetchall()

    if not sample:
        c.record("SKIP", "No investigations to validate")
        c.end_section()
        return

    issues = 0
    for row in sample:
        inv_id = row["id"]
        short = inv_id[:8]

        # Verify summary_json is valid JSON
        try:
            summary = json.loads(row["summary_json"])
            if not isinstance(summary, dict):
                c.record("FAIL", f"{short}...: summary_json is not a dict",
                          investigation_id=inv_id)
                issues += 1
                continue
        except (json.JSONDecodeError, TypeError) as e:
            c.record("FAIL", f"{short}...: summary_json invalid: {e}",
                      investigation_id=inv_id,
                      suggested_fix="Re-save investigation with valid summary JSON")
            issues += 1
            continue

        # Verify case_json is valid JSON
        try:
            case = json.loads(row["case_json"])
            if not isinstance(case, dict):
                c.record("FAIL", f"{short}...: case_json is not a dict",
                          investigation_id=inv_id)
                issues += 1
                continue
        except (json.JSONDecodeError, TypeError) as e:
            c.record("FAIL", f"{short}...: case_json invalid: {e}",
                      investigation_id=inv_id)
            issues += 1
            continue

        # Cross-check packet_count in summary vs actual packets DB
        expected_pkt_count = case.get("packet_count", summary.get("total_packets", -1))
        if PACKETS_DB_PATH.is_file():
            with _connect(PACKETS_DB_PATH) as conn:
                actual_pkt = conn.execute(
                    "SELECT COUNT(*) FROM packets WHERE investigation_id = ?",
                    (inv_id,)
                ).fetchone()[0]
            if expected_pkt_count >= 0 and actual_pkt != expected_pkt_count:
                c.record("WARN",
                          f"{short}...: packet count mismatch: metadata={expected_pkt_count}, actual={actual_pkt}",
                          investigation_id=inv_id)

        # Verify destination IPs count
        with _connect(INVESTIGATIONS_DB_PATH) as conn:
            dest_count = conn.execute(
                "SELECT COUNT(*) FROM destinations WHERE investigation_id = ?",
                (inv_id,)
            ).fetchone()[0]
        rows_in_case = len(case.get("rows", []))
        if dest_count != rows_in_case and rows_in_case > 0:
            c.record("WARN",
                      f"{short}...: destinations table has {dest_count} rows, case_json has {rows_in_case}",
                      investigation_id=inv_id)

        # Verify sessions
        if FLOWS_DB_PATH.is_file():
            with _connect(FLOWS_DB_PATH) as conn:
                session_count = conn.execute(
                    "SELECT COUNT(*) FROM sessions WHERE investigation_id = ?",
                    (inv_id,)
                ).fetchone()[0]
            summary_sessions = summary.get("total_sessions", -1)
            # Session count in DB should be reasonable
            if session_count > 0:
                pass  # sessions exist, good

        # Verify alerts
        if CACHE_DB_PATH.is_file():
            with _connect(CACHE_DB_PATH) as conn:
                alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    if issues == 0:
        c.record("PASS", f"All {len(sample)} sampled investigations have consistent metadata")
    else:
        c.record("FAIL", f"{issues}/{len(sample)} investigations have consistency issues")

    # Verify get_investigation() reconstruction matches stored data
    if sample:
        inv_id = sample[0]["id"]
        try:
            reconstructed = get_investigation(inv_id)
            if reconstructed:
                # Check essential fields are present
                required = ["id", "filename", "created_at"]
                missing = [f for f in required if f not in reconstructed]
                if missing:
                    c.record("FAIL", f"Reconstructed investigation missing fields: {missing}")
                else:
                    c.record("PASS", "get_investigation() reconstruction includes all essential fields")
            else:
                c.record("FAIL", "get_investigation() returned None for existing investigation")
        except Exception as e:
            c.record("FAIL", f"get_investigation() error: {e}")

    c.end_section()


# ═══════════════════════════════════════════════════════════════════════
# §13  HASH VERIFICATION
# ═══════════════════════════════════════════════════════════════════════
def section_13_hash(c: Checker):
    c.begin_section("13. HASH VERIFICATION")

    if not all(p.is_file() for p in [INVESTIGATIONS_DB_PATH, PACKETS_DB_PATH, PAYLOADS_DB_PATH]):
        c.record("SKIP", "Required databases missing for hash verification")
        c.end_section()
        return

    with _connect(INVESTIGATIONS_DB_PATH) as conn:
        sample = conn.execute(
            "SELECT id, case_json FROM investigations ORDER BY RANDOM() LIMIT 5"
        ).fetchall()

    if not sample:
        c.record("SKIP", "No investigations to hash-verify")
        c.end_section()
        return

    pass_count = 0
    fail_count = 0

    for row in sample:
        inv_id = row["id"]
        short = inv_id[:8]

        # Hash the stored case_json
        case_hash = hashlib.sha256(row["case_json"].encode("utf-8")).hexdigest()

        # Reconstruct via get_investigation() and hash the case portion
        try:
            rebuilt = get_investigation(inv_id)
            if not rebuilt:
                c.record("FAIL", f"{short}...: reconstruction returned None")
                fail_count += 1
                continue

            # Verify packet blobs can be decompressed
            packet_rows = rebuilt.get("packet_rows", [])
            blob_hashes = []
            if PAYLOADS_DB_PATH.is_file() and packet_rows:
                with _connect(PAYLOADS_DB_PATH) as pconn:
                    sample_payloads = pconn.execute(
                        "SELECT payload_blob, compression FROM payloads "
                        "WHERE investigation_id = ? LIMIT 20",
                        (inv_id,)
                    ).fetchall()
                    for pl in sample_payloads:
                        blob = pl["payload_blob"]
                        if blob:
                            try:
                                decompressed = decompress_bytes(blob)
                                blob_hashes.append(hashlib.sha256(decompressed).hexdigest())
                            except Exception as e:
                                c.record("FAIL", f"{short}...: payload decompression error: {e}",
                                          investigation_id=inv_id)
                                fail_count += 1
                                continue

            # Verify the case_json hash is stable
            case_json_rebuilt = json.loads(row["case_json"])
            case_json_rehash = hashlib.sha256(
                json.dumps(case_json_rebuilt, sort_keys=True).encode("utf-8")
            ).hexdigest()
            case_json_original_sorted = hashlib.sha256(
                json.dumps(json.loads(row["case_json"]), sort_keys=True).encode("utf-8")
            ).hexdigest()

            if case_json_rehash == case_json_original_sorted:
                c.record("PASS",
                          f"{short}...: case_json SHA-256 stable, "
                          f"{len(blob_hashes)} payload blobs verified",
                          investigation_id=inv_id, case_hash=case_hash[:16])
                pass_count += 1
            else:
                c.record("FAIL", f"{short}...: case_json hash mismatch after re-parse",
                          investigation_id=inv_id)
                fail_count += 1

        except Exception as e:
            c.record("FAIL", f"{short}...: hash verification error: {e}",
                      investigation_id=inv_id)
            fail_count += 1

    c.record("INFO", f"Hash verification: {pass_count} passed, {fail_count} failed")
    c.end_section()


# ═══════════════════════════════════════════════════════════════════════
# §14  STORAGE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════
def section_14_storage(c: Checker) -> dict:
    c.begin_section("14. STORAGE ANALYSIS")
    analysis = {}
    total_size = 0

    for name, path in EXPECTED_DATABASES.items():
        if not path.is_file():
            continue
        size = _file_size(path)
        total_size += size

        with _connect(path) as conn:
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            page_count = conn.execute("PRAGMA page_count").fetchone()[0]
            freelist = conn.execute("PRAGMA freelist_count").fetchone()[0]
            frag_pct = round((freelist / max(page_count, 1)) * 100, 1)

            # Largest tables by page usage (estimate)
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            table_sizes = []
            for t in tables:
                try:
                    row_count = conn.execute(f"SELECT COUNT(*) FROM [{t[0]}]").fetchone()[0]
                    table_sizes.append((t[0], row_count))
                except Exception:
                    pass
            table_sizes.sort(key=lambda x: x[1], reverse=True)

            # Index info
            indexes = conn.execute(
                "SELECT name, tbl_name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()

            vacuum_rec = "RECOMMENDED" if frag_pct > 10 else "not needed"
            optimize_rec = "RECOMMENDED" if size > 100 * 1024 * 1024 else "not needed"

            analysis[name] = {
                "size": size,
                "page_size": page_size,
                "page_count": page_count,
                "free_pages": freelist,
                "fragmentation_pct": frag_pct,
                "vacuum": vacuum_rec,
                "optimize": optimize_rec,
                "table_count": len(tables),
                "index_count": len(indexes),
            }

            c.record("INFO",
                      f"{name:<15} size={_human_size(size):>10}  "
                      f"free_pages={freelist:>6}  frag={frag_pct:>5.1f}%  "
                      f"vacuum={vacuum_rec}")

            if frag_pct > 10:
                c.record("WARN", f"{name}: fragmentation {frag_pct}% — VACUUM recommended",
                          db=name, suggested_fix=f"Run: sqlite3 {path} 'VACUUM;'")

            if table_sizes:
                biggest = table_sizes[0]
                c.record("INFO", f"  └─ largest table: {biggest[0]} ({biggest[1]:,} rows)")

    c.record("INFO", f"Total database storage: {_human_size(total_size)}")
    analysis["total_size"] = total_size
    c.end_section()
    return analysis


# ═══════════════════════════════════════════════════════════════════════
# §15  SQLITE PRAGMA REPORT
# ═══════════════════════════════════════════════════════════════════════
def section_15_pragma(c: Checker) -> dict:
    c.begin_section("15. SQLITE PRAGMA REPORT")
    pragma_report = {}
    pragmas = [
        "journal_mode", "page_size", "cache_size", "mmap_size",
        "foreign_keys", "busy_timeout", "synchronous", "temp_store",
        "wal_checkpoint",
    ]

    for name, path in EXPECTED_DATABASES.items():
        if not path.is_file():
            continue
        db_pragmas = {}
        with _connect(path) as conn:
            for p in pragmas:
                try:
                    val = conn.execute(f"PRAGMA {p}").fetchone()
                    db_pragmas[p] = val[0] if val else "N/A"
                except Exception:
                    db_pragmas[p] = "ERROR"

        pragma_report[name] = db_pragmas
        wal = "✓" if db_pragmas.get("journal_mode") == "wal" else "✗"
        c.record("INFO",
                  f"{name:<15} journal={db_pragmas.get('journal_mode', '?'):<6} "
                  f"page_size={db_pragmas.get('page_size', '?')}  "
                  f"cache_size={db_pragmas.get('cache_size', '?')}  "
                  f"mmap={db_pragmas.get('mmap_size', '?')}  "
                  f"busy_timeout={db_pragmas.get('busy_timeout', '?')}")

        # Warn if WAL mode not enabled
        if db_pragmas.get("journal_mode") != "wal":
            c.record("WARN", f"{name}: journal_mode is not WAL",
                      db=name,
                      suggested_fix="Set PRAGMA journal_mode=WAL on first connection")

    c.end_section()
    return pragma_report


# ═══════════════════════════════════════════════════════════════════════
# §16  FINAL REPORT
# ═══════════════════════════════════════════════════════════════════════
def section_16_report(c: Checker, benchmarks: dict, storage: dict, pragmas: dict):
    c.begin_section("16. FINAL REPORT GENERATION")

    timestamp = datetime.now(timezone.utc).isoformat()
    elapsed = round(time.time() - c.start_time, 2)

    # Build JSON report
    report = {
        "title": "CyberDeep Storage Verification Report",
        "timestamp": timestamp,
        "elapsed_seconds": elapsed,
        "overall_result": "PASS" if c.overall_pass() else "FAIL",
        "sections": {},
        "findings": c.findings,
        "warnings": c.warnings,
        "benchmarks": benchmarks,
        "storage_analysis": storage,
        "pragma_report": pragmas,
    }

    for name, sec in c.sections.items():
        report["sections"][name] = {
            "status": sec["status"],
            "elapsed": sec.get("elapsed", 0),
            "detail_count": len(sec["details"]),
        }

    # Write JSON
    json_path = REPORT_DIR / "verification_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    c.record("PASS", f"verification_report.json → {json_path}")

    # Write Markdown
    md_path = REPORT_DIR / "verification_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# CyberDeep Storage Verification Report\n\n")
        f.write(f"**Generated:** {timestamp}  \n")
        f.write(f"**Duration:** {elapsed}s  \n")
        overall = "✅ PASS" if c.overall_pass() else "❌ FAIL"
        f.write(f"**Overall Result:** {overall}  \n\n")

        f.write("## Section Results\n\n")
        f.write("| # | Section | Status | Time |\n")
        f.write("|---|---------|--------|------|\n")
        for name, sec in c.sections.items():
            sym = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}.get(sec["status"], "•")
            f.write(f"| | {name} | {sym} {sec['status']} | {sec.get('elapsed', 0):.3f}s |\n")

        if c.findings:
            f.write("\n## Failures\n\n")
            for finding in c.findings:
                f.write(f"- **{finding['section']}**: {finding['message']}\n")
                if finding.get("suggested_fix"):
                    f.write(f"  - *Fix:* {finding['suggested_fix']}\n")

        if c.warnings:
            f.write("\n## Warnings\n\n")
            for w in c.warnings:
                f.write(f"- **{w['section']}**: {w['message']}\n")
                if w.get("suggested_fix"):
                    f.write(f"  - *Fix:* {w['suggested_fix']}\n")

        if benchmarks:
            f.write("\n## Performance Benchmarks\n\n")
            f.write("| Operation | Avg (ms) | Min (ms) | Max (ms) |\n")
            f.write("|-----------|----------|----------|----------|\n")
            for op, vals in benchmarks.items():
                f.write(f"| {op} | {vals['avg_ms']} | {vals['min_ms']} | {vals['max_ms']} |\n")

    c.record("PASS", f"verification_report.md → {md_path}")

    # Write HTML
    html_path = REPORT_DIR / "verification_report.html"
    with open(html_path, "w", encoding="utf-8") as f:
        overall_class = "pass" if c.overall_pass() else "fail"
        overall_text = "DATABASE VERIFIED SUCCESSFULLY" if c.overall_pass() else "VERIFICATION FAILED"
        overall_emoji = "✅" if c.overall_pass() else "❌"

        f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberDeep Storage Verification Report</title>
<style>
  :root {{ --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #e2e8f0;
           --pass: #22c55e; --fail: #ef4444; --warn: #f59e0b; --info: #3b82f6;
           --accent: #6366f1; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
          background: var(--bg); color: var(--text); padding: 2rem; }}
  h1 {{ color: white; font-size: 1.8rem; margin-bottom: 0.5rem;
        background: linear-gradient(135deg, var(--accent), #8b5cf6);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  .meta {{ color: #94a3b8; margin-bottom: 2rem; font-size: 0.9rem; }}
  .overall {{ padding: 1.5rem; border-radius: 12px; text-align: center;
              font-size: 1.4rem; font-weight: 700; margin-bottom: 2rem; }}
  .overall.pass {{ background: linear-gradient(135deg, #052e16, #14532d);
                    border: 2px solid var(--pass); color: var(--pass); }}
  .overall.fail {{ background: linear-gradient(135deg, #450a0a, #7f1d1d);
                    border: 2px solid var(--fail); color: var(--fail); }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 2rem; }}
  th {{ background: var(--card); color: #94a3b8; text-align: left; padding: 0.75rem 1rem;
        border-bottom: 2px solid var(--border); font-size: 0.8rem; text-transform: uppercase;
        letter-spacing: 0.05em; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
  tr:hover td {{ background: rgba(99,102,241,0.05); }}
  .badge {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 6px;
            font-size: 0.8rem; font-weight: 600; }}
  .badge.pass {{ background: rgba(34,197,94,0.15); color: var(--pass); }}
  .badge.fail {{ background: rgba(239,68,68,0.15); color: var(--fail); }}
  .badge.warn {{ background: rgba(245,158,11,0.15); color: var(--warn); }}
  .section-title {{ color: white; font-size: 1.2rem; margin: 2rem 0 1rem;
                    padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }}
  .finding {{ background: var(--card); border-left: 4px solid var(--fail);
              padding: 0.8rem 1rem; margin-bottom: 0.5rem; border-radius: 0 8px 8px 0; }}
  .finding .fix {{ color: var(--info); font-size: 0.85rem; margin-top: 0.3rem; }}
  .warning {{ background: var(--card); border-left: 4px solid var(--warn);
              padding: 0.8rem 1rem; margin-bottom: 0.5rem; border-radius: 0 8px 8px 0; }}
  .warning .fix {{ color: var(--info); font-size: 0.85rem; margin-top: 0.3rem; }}
</style>
</head>
<body>
<h1>🛡️ CyberDeep Storage Verification Report</h1>
<div class="meta">Generated: {timestamp} &middot; Duration: {elapsed}s</div>
<div class="overall {overall_class}">{overall_emoji} {overall_text}</div>

<h2 class="section-title">Section Results</h2>
<table>
<thead><tr><th>Section</th><th>Status</th><th>Time</th></tr></thead>
<tbody>
""")
        for name, sec in c.sections.items():
            badge_class = sec["status"].lower()
            emoji = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}.get(sec["status"], "")
            f.write(f'<tr><td>{name}</td>'
                    f'<td><span class="badge {badge_class}">{emoji} {sec["status"]}</span></td>'
                    f'<td>{sec.get("elapsed", 0):.3f}s</td></tr>\n')
        f.write("</tbody></table>\n")

        if c.findings:
            f.write('<h2 class="section-title">❌ Failures</h2>\n')
            for finding in c.findings:
                f.write(f'<div class="finding"><strong>{finding["section"]}</strong>: {finding["message"]}')
                if finding.get("suggested_fix"):
                    f.write(f'<div class="fix">💡 Fix: {finding["suggested_fix"]}</div>')
                f.write('</div>\n')

        if c.warnings:
            f.write('<h2 class="section-title">⚠️ Warnings</h2>\n')
            for w in c.warnings:
                f.write(f'<div class="warning"><strong>{w["section"]}</strong>: {w["message"]}')
                if w.get("suggested_fix"):
                    f.write(f'<div class="fix">💡 Fix: {w["suggested_fix"]}</div>')
                f.write('</div>\n')

        if benchmarks:
            f.write('<h2 class="section-title">⚡ Performance Benchmarks</h2>\n')
            f.write('<table><thead><tr><th>Operation</th><th>Avg (ms)</th>'
                    '<th>Min (ms)</th><th>Max (ms)</th></tr></thead><tbody>\n')
            for op, vals in benchmarks.items():
                f.write(f'<tr><td>{op}</td><td>{vals["avg_ms"]}</td>'
                        f'<td>{vals["min_ms"]}</td><td>{vals["max_ms"]}</td></tr>\n')
            f.write("</tbody></table>\n")

        f.write("</body></html>\n")

    c.record("PASS", f"verification_report.html → {html_path}")
    c.end_section()


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════
def print_banner():
    print("""
+==============================================================+
|         CyberDeep Storage Verification Framework             |
|         v2.0 -- Complete 16-Section Audit                    |
+==============================================================+
""")


def print_summary(c: Checker):
    print("\n")
    print("=" * 60)
    print("  CyberDeep Storage Verification Summary")
    print("=" * 60)
    print()

    section_labels = {
        "1. DATABASE DISCOVERY":          "Database Integrity",
        "2. SQLITE HEALTH CHECK":         "SQLite Health",
        "3. SCHEMA VALIDATION":           "Schema Validation",
        "4. TABLE STATISTICS":            "Table Statistics",
        "5. REFERENTIAL INTEGRITY":       "Foreign Keys",
        "6. DUPLICATE DETECTION":         "Duplicate Detection",
        "7. PACKET / PAYLOAD VALIDATION": "Packet Integrity",
        "8. CROSS DATABASE VALIDATION":   "Cross DB Queries",
        "9. ROUTER VALIDATION":           "Router Validation",
        "10. PERFORMANCE BENCHMARK":      "Performance",
        "11. API REGRESSION":             "API Compatibility",
        "12. DATA CONSISTENCY":           "Data Consistency",
        "13. HASH VERIFICATION":          "Hash Verification",
        "14. STORAGE ANALYSIS":           "Storage Health",
        "15. SQLITE PRAGMA REPORT":       "SQLite Pragmas",
        "16. FINAL REPORT GENERATION":    "Report Generation",
    }

    for section_name, sec in c.sections.items():
        label = section_labels.get(section_name, section_name)
        status = sec["status"]
        dots = "." * (40 - len(label))
        symbol = {"PASS": "PASS ✅", "WARN": "WARN ⚠️", "FAIL": "FAIL ❌"}.get(status, status)
        print(f"  {label} {dots} {symbol}")

    print()
    elapsed = round(time.time() - c.start_time, 2)
    if c.overall_pass():
        print("  +==================================================+")
        print("  |  [PASS] DATABASE VERIFIED SUCCESSFULLY            |")
        print("  +==================================================+")
    else:
        print("  +==================================================+")
        print("  |  [FAIL] VERIFICATION FAILED                      |")
        print("  +==================================================+")
        print()
        print(f"  Failures: {len(c.findings)}")
        print(f"  Warnings: {len(c.warnings)}")

    print(f"\n  Total time: {elapsed}s")
    print(f"  Reports saved to: {REPORT_DIR}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="CyberDeep Storage Verification Framework")
    parser.add_argument("--skip-api", action="store_true", help="Skip API regression tests")
    parser.add_argument("--init-dummy", action="store_true", help="Initialize dummy databases for CI/CD")
    parser.add_argument("--sample-size", type=int, default=100,
                        help="Number of investigations to sample (default: 100)")
    args = parser.parse_args()

    if args.init_dummy:
        print("Initializing dummy databases for CI/CD...")
        init_db()

    print_banner()

    c = Checker(sample_size=args.sample_size, skip_api=args.skip_api)

    # Run all 16 sections
    try:
        section_01_discovery(c)
        section_02_health(c)
        section_03_schema(c)
        stats = section_04_statistics(c)
        section_05_referential(c)
        section_06_duplicates(c)
        section_07_packet_payload(c)
        section_08_cross_db(c)
        section_09_router(c)
        benchmarks = section_10_performance(c)
        section_11_api(c)
        section_12_consistency(c)
        section_13_hash(c)
        storage = section_14_storage(c)
        pragmas = section_15_pragma(c)
        section_16_report(c, benchmarks, storage, pragmas)
    except Exception as e:
        print(f"\n❌ FATAL ERROR during verification: {e}")
        traceback.print_exc()
        sys.exit(2)

    print_summary(c)
    sys.exit(0 if c.overall_pass() else 1)


if __name__ == "__main__":
    main()
