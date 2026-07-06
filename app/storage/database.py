import json
import sqlite3
import uuid
import logging
import zlib
import math
from pathlib import Path
from datetime import datetime, timezone

from app.core.config import DATA_DIR

logger = logging.getLogger(__name__)

# Paths for the specialized databases
INVESTIGATIONS_DB_PATH = DATA_DIR / "investigations.sqlite3"
PACKETS_DB_PATH = DATA_DIR / "packets.sqlite3"
PAYLOADS_DB_PATH = DATA_DIR / "payloads.sqlite3"
LIVE_CAPTURE_DB_PATH = DATA_DIR / "live_capture.sqlite3"
TELECOM_DB_PATH = DATA_DIR / "telecom.sqlite3"
GEOIP_DB_PATH = DATA_DIR / "geoip.sqlite3"
THREATINTEL_DB_PATH = DATA_DIR / "threatintel.sqlite3"
DNS_DB_PATH = DATA_DIR / "dns.sqlite3"
USERS_DB_PATH = DATA_DIR / "users.sqlite3"
CACHE_DB_PATH = DATA_DIR / "cache.sqlite3"
FLOWS_DB_PATH = DATA_DIR / "flows.sqlite3"

# Backward compatibility aliases
SESSIONS_DB_PATH = FLOWS_DB_PATH
ALERTS_DB_PATH = CACHE_DB_PATH

TABLE_MAP = {
    "investigations": INVESTIGATIONS_DB_PATH,
    "destinations": INVESTIGATIONS_DB_PATH,
    "investigation_search": INVESTIGATIONS_DB_PATH,
    "packets": PACKETS_DB_PATH,
    "payloads": PAYLOADS_DB_PATH,
    "live_capture_packets": LIVE_CAPTURE_DB_PATH,
    "capture_statistics": LIVE_CAPTURE_DB_PATH,
    "cdr_records": TELECOM_DB_PATH,
    "operator_lookup": TELECOM_DB_PATH,
    "endpoints": GEOIP_DB_PATH,
    "geoip_lookup": GEOIP_DB_PATH,
    "threat_indicators": THREATINTEL_DB_PATH,
    "dns_cache": DNS_DB_PATH,
    "subdomain_scans": DNS_DB_PATH,
    "user_preferences": USERS_DB_PATH,
    "saved_filters": USERS_DB_PATH,
    "temp_cache": CACHE_DB_PATH,
    "sessions": FLOWS_DB_PATH,
    "rtp_streams": FLOWS_DB_PATH,
    "sip_dialogs": FLOWS_DB_PATH,
    "ice_sessions": FLOWS_DB_PATH,
    "alerts": CACHE_DB_PATH
}

# Base schema for versioning
SCHEMA_INFO_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER PRIMARY KEY,
    created_at TEXT,
    last_migration TEXT
);
"""

# --- Core Schemas ---
SCHEMAS = {
    INVESTIGATIONS_DB_PATH: SCHEMA_INFO_SCHEMA + """
        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            created_at TEXT NOT NULL,
            summary_json TEXT NOT NULL,
            case_json TEXT
        );
        CREATE TABLE IF NOT EXISTS destinations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            row_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_destinations_investigation ON destinations(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_destinations_ip ON destinations(destination_ip);
        
        CREATE VIRTUAL TABLE IF NOT EXISTS investigation_search USING fts5(
            investigation_id UNINDEXED,
            filename,
            notes,
            dns_queries,
            http_headers,
            sip_messages,
            payload_previews
        );
    """,
    PACKETS_DB_PATH: SCHEMA_INFO_SCHEMA + """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id TEXT NOT NULL,
            packet_index INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            length INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            src_endpoint_id INTEGER NOT NULL,
            dst_endpoint_id INTEGER NOT NULL,
            source_port INTEGER,
            destination_port INTEGER,
            tcp_flags TEXT,
            flow_id TEXT,
            summary TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_packets_investigation ON packets(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_packets_index ON packets(packet_index);
        CREATE INDEX IF NOT EXISTS idx_packets_flow ON packets(flow_id);
    """,
    PAYLOADS_DB_PATH: SCHEMA_INFO_SCHEMA + """
        CREATE TABLE IF NOT EXISTS payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            packet_id INTEGER NOT NULL,
            investigation_id TEXT NOT NULL,
            packet_index INTEGER NOT NULL,
            payload_blob BLOB,
            payload_preview TEXT,
            mime_type TEXT,
            decoded_json TEXT,
            compression TEXT,
            entropy REAL
        );
        CREATE INDEX IF NOT EXISTS idx_payloads_investigation ON payloads(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_payloads_packet_id ON payloads(packet_id);
    """,
    LIVE_CAPTURE_DB_PATH: SCHEMA_INFO_SCHEMA + """
        CREATE TABLE IF NOT EXISTS live_capture_packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            packet_index INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            length INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            src_endpoint_id INTEGER NOT NULL,
            dst_endpoint_id INTEGER NOT NULL,
            source_port INTEGER,
            destination_port INTEGER,
            tcp_flags TEXT,
            flow_id TEXT,
            summary TEXT NOT NULL,
            payload_blob BLOB,
            payload_preview TEXT,
            compression TEXT
        );
        CREATE TABLE IF NOT EXISTS capture_statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            packet_count INTEGER NOT NULL,
            dropped_packets INTEGER NOT NULL,
            packets_per_second REAL,
            bytes_per_second REAL
        );
    """,
    TELECOM_DB_PATH: SCHEMA_INFO_SCHEMA + """
        CREATE TABLE IF NOT EXISTS cdr_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            imsi TEXT,
            imei TEXT,
            calling_number TEXT,
            called_number TEXT,
            duration_seconds INTEGER,
            cell_id TEXT,
            bts_id TEXT
        );
        CREATE TABLE IF NOT EXISTS operator_lookup (
            mcc TEXT NOT NULL,
            mnc TEXT NOT NULL,
            operator_name TEXT NOT NULL,
            country TEXT NOT NULL,
            PRIMARY KEY (mcc, mnc)
        );
    """,
    GEOIP_DB_PATH: SCHEMA_INFO_SCHEMA + """
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            mac TEXT,
            hostname TEXT,
            vendor TEXT,
            country TEXT,
            asn TEXT
        );
        CREATE TABLE IF NOT EXISTS geoip_lookup (
            ip TEXT PRIMARY KEY,
            country TEXT,
            city TEXT,
            asn TEXT,
            latitude REAL,
            longitude REAL,
            updated_at TEXT NOT NULL,
            ttl INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_geoip_country ON geoip_lookup(country);
    """,
    THREATINTEL_DB_PATH: SCHEMA_INFO_SCHEMA + """
        CREATE TABLE IF NOT EXISTS threat_indicators (
            indicator TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            source TEXT,
            source_url TEXT,
            feed_name TEXT,
            confidence REAL,
            ioc_type TEXT,
            stix_id TEXT,
            tags TEXT,
            reference TEXT,
            expires_at TEXT
        );
    """,
    DNS_DB_PATH: SCHEMA_INFO_SCHEMA + """
        CREATE TABLE IF NOT EXISTS dns_cache (
            query TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            answers TEXT NOT NULL,
            resolved_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subdomain_scans (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            engines TEXT,
            total_found INTEGER DEFAULT 0,
            error TEXT,
            progress TEXT,
            engines_status_json TEXT,
            subdomains_json TEXT,
            resolved_json TEXT
        );
    """,
    USERS_DB_PATH: SCHEMA_INFO_SCHEMA + """
        CREATE TABLE IF NOT EXISTS user_preferences (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS saved_filters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            expression TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """,
    CACHE_DB_PATH: SCHEMA_INFO_SCHEMA + """
        CREATE TABLE IF NOT EXISTS temp_cache (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            flow_id TEXT NOT NULL,
            packet_id INTEGER,
            severity TEXT NOT NULL,
            rule TEXT NOT NULL,
            confidence REAL DEFAULT 1.0,
            timestamp TEXT NOT NULL,
            status TEXT DEFAULT 'New',
            resolved INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_flow ON alerts(flow_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
    """,
    FLOWS_DB_PATH: SCHEMA_INFO_SCHEMA + """
        CREATE TABLE IF NOT EXISTS sessions (
            flow_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            protocol TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            bytes INTEGER DEFAULT 0,
            packets INTEGER DEFAULT 0,
            jitter REAL DEFAULT 0.0,
            loss REAL DEFAULT 0.0,
            mos REAL DEFAULT 0.0,
            classification TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_investigation ON sessions(investigation_id);
        CREATE TABLE IF NOT EXISTS rtp_streams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_flow_id TEXT NOT NULL,
            ssrc INTEGER,
            payload_type INTEGER,
            packet_count INTEGER DEFAULT 0,
            jitter REAL DEFAULT 0.0,
            loss REAL DEFAULT 0.0,
            mos REAL DEFAULT 0.0
        );
        CREATE TABLE IF NOT EXISTS sip_dialogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            call_id TEXT NOT NULL,
            from_uri TEXT,
            to_uri TEXT,
            method TEXT,
            status_code TEXT,
            user_agent TEXT,
            sdp_media_ip TEXT,
            sdp_media_port INTEGER
        );
        CREATE TABLE IF NOT EXISTS ice_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_flow_id TEXT NOT NULL,
            ufrag TEXT,
            state TEXT,
            candidate_type TEXT,
            relay_server TEXT,
            nat_type_guess TEXT
        );
    """
}

# --- Compression & Entropy Helpers ---
def compress_bytes(data: bytes) -> bytes:
    return zlib.compress(data) if data else b""

def decompress_bytes(data: bytes) -> bytes:
    return zlib.decompress(data) if data else b""

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 3)

# --- Database Router Implementation ---
class DatabaseRouter:
    def __init__(self):
        self.table_map = TABLE_MAP

    def _get_connection(self, db_path: Path) -> sqlite3.Connection:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        # Enable write-ahead logging (WAL) and memory mapping optimization
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA page_size=4096")
        conn.execute("PRAGMA mmap_size=268435456")  # 256 MB memory map
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def execute(self, table: str, query: str, params: tuple = ()) -> list[dict]:
        """Execute a query routed dynamically to the correct database file."""
        db_path = self.table_map.get(table, INVESTIGATIONS_DB_PATH)
        with self._get_connection(db_path) as conn:
            cursor = conn.execute(query, params)
            if query.strip().upper().startswith(("SELECT", "PRAGMA")):
                return [dict(row) for row in cursor.fetchall()]
            conn.commit()
            return []

    def executemany(self, table: str, query: str, params_list: list) -> None:
        """Execute a batch query routed dynamically."""
        db_path = self.table_map.get(table, INVESTIGATIONS_DB_PATH)
        with self._get_connection(db_path) as conn:
            conn.executemany(query, params_list)
            conn.commit()

    def execute_cross_db(self, query: str, params: tuple = ()) -> list[dict]:
        """Execute joins across multiple databases using SQLite ATTACH statements dynamically."""
        with self._get_connection(INVESTIGATIONS_DB_PATH) as conn:
            # Map of database aliases to their paths
            db_attachments = {
                "packets_db": PACKETS_DB_PATH,
                "payloads_db": PAYLOADS_DB_PATH,
                "live_capture_db": LIVE_CAPTURE_DB_PATH,
                "telecom_db": TELECOM_DB_PATH,
                "geoip_db": GEOIP_DB_PATH,
                "threatintel_db": THREATINTEL_DB_PATH,
                "dns_db": DNS_DB_PATH,
                "users_db": USERS_DB_PATH,
                "cache_db": CACHE_DB_PATH,
                "flows_db": FLOWS_DB_PATH,
                "sessions_db": FLOWS_DB_PATH,
                "alerts_db": CACHE_DB_PATH
            }
            
            # Attach only databases referenced in the query
            for alias, path in db_attachments.items():
                if alias in query:
                    conn.execute(f"ATTACH DATABASE '{path}' AS {alias}")
                    
            cursor = conn.execute(query, params)
            if query.strip().upper().startswith(("SELECT", "PRAGMA")):
                return [dict(row) for row in cursor.fetchall()]
            conn.commit()
            return []

# Singleton instance
router = DatabaseRouter()

# --- Public API Implementations ---

def init_db() -> None:
    """Initialize standard tables in all global databases and write schema version."""
    for db_path, schema in SCHEMAS.items():
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db_path, timeout=10) as conn:
            conn.executescript(schema)
            # Insert default schema version info if empty
            cursor = conn.execute("SELECT COUNT(*) FROM schema_info")
            if cursor.fetchone()[0] == 0:
                conn.execute(
                    "INSERT INTO schema_info (version, created_at, last_migration) VALUES (?, ?, ?)",
                    (1, datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat())
                )
            conn.commit()
    logger.info("Modular database layout schemas initialized successfully.")

_endpoint_cache = {}

def get_endpoint_id(ip: str, mac: str = None) -> int:
    """Resolve an IP/MAC endpoint record to its normalized ID to prevent string repetitions."""
    global _endpoint_cache
    if ip in _endpoint_cache:
        return _endpoint_cache[ip]
        
    with router._get_connection(GEOIP_DB_PATH) as conn:
        cursor = conn.execute("SELECT id FROM endpoints WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if row:
            _endpoint_cache[ip] = row["id"]
            return row["id"]
        
        # Determine basic properties (hostname, vendor or local LAN mapping)
        vendor = "LAN Vendor" if ip.startswith(("192.168.", "10.", "172.16.")) else "Internet"
        country = "LAN" if ip.startswith(("192.168.", "10.", "172.16.")) else "Unknown"
        
        cursor = conn.execute(
            "INSERT INTO endpoints (ip, mac, hostname, vendor, country, asn) VALUES (?, ?, ?, ?, ?, ?)",
            (ip, mac, ip, vendor, country, "Private Network" if country == "LAN" else "")
        )
        conn.commit()
        endpoint_id = cursor.lastrowid
        _endpoint_cache[ip] = endpoint_id
        return endpoint_id

def save_investigation(filename: str, analysis: dict) -> str:
    """Extract packet arrays, compress payloads, normalize endpoints, and write to partitioned databases."""
    investigation_id = str(uuid.uuid4())
    created_at_str = datetime.now(timezone.utc).isoformat()
    
    # 1. Extract and split packets/payloads from analysis dict
    packet_rows = analysis.pop("packet_rows", [])
    
    # Store clean metadata in investigations table
    analysis["packet_count"] = len(packet_rows)
    analysis["timeline"] = analysis.get("timeline", [])
    analysis["statistics"] = analysis.get("summary", {})
    
    # Save base investigation
    db_path = router.table_map["investigations"]
    with router._get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO investigations (id, filename, created_at, summary_json, case_json) VALUES (?, ?, ?, ?, ?)",
            (
                investigation_id,
                filename,
                created_at_str,
                json.dumps(analysis.get("summary", {})),
                json.dumps(analysis),
            ),
        )
        conn.executemany(
            "INSERT INTO destinations (investigation_id, destination_ip, row_json) VALUES (?, ?, ?)",
            [
                (investigation_id, row["destination_ip"], json.dumps(row))
                for row in analysis.get("rows", [])
            ],
        )

    # 2. Extract and write sessions (conversations) to cache.sqlite3
    flows_seen = {}
    for pkt in packet_rows:
        flow_id = pkt.get("flow_id")
        if flow_id and flow_id not in flows_seen:
            flows_seen[flow_id] = {
                "flow_id": flow_id,
                "investigation_id": investigation_id,
                "protocol": pkt["protocol"],
                "start_time": pkt["timestamp"],
                "end_time": pkt["timestamp"],
                "bytes": pkt["length"],
                "packets": 1
            }
        elif flow_id:
            flows_seen[flow_id]["end_time"] = pkt["timestamp"]
            flows_seen[flow_id]["bytes"] += pkt["length"]
            flows_seen[flow_id]["packets"] += 1

    with router._get_connection(FLOWS_DB_PATH) as conn:
        conn.executemany(
            """INSERT OR IGNORE INTO sessions 
            (flow_id, investigation_id, protocol, start_time, end_time, bytes, packets, jitter, loss, mos, classification)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    f["flow_id"], f["investigation_id"], f["protocol"], f["start_time"], f["end_time"],
                    f["bytes"], f["packets"], 0.0, 0.0, 4.0, "Dynamic Flow"
                )
                for f in flows_seen.values()
            ]
        )

    # 3. Write alerts to cache.sqlite3
    alerts_to_insert = []
    for anomaly in analysis.get("anomalies", []):
        alert_id = str(uuid.uuid4())[:8]
        alerts_to_insert.append((
            alert_id,
            anomaly.get("flow_id") or "global",
            anomaly.get("packet_index"),
            anomaly.get("severity", "Medium"),
            anomaly.get("name", "Unknown Alert"),
            anomaly.get("confidence", 1.0),
            created_at_str,
            "New",
            0
        ))
    if alerts_to_insert:
        with router._get_connection(CACHE_DB_PATH) as conn:
            conn.executemany(
                "INSERT INTO alerts (alert_id, flow_id, packet_id, severity, rule, confidence, timestamp, status, resolved) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                alerts_to_insert
            )

    # 4. Save packets and compressed payloads
    packets_to_insert = []
    payloads_to_insert = []
    
    # Collect index content for FTS5 full-text queries
    dns_list = []
    http_list = []
    sip_list = []
    previews_list = []

    for pkt in packet_rows:
        ts = pkt["timestamp"]
        
        # Get endpoint IDs (propagate MAC addresses)
        src_id = get_endpoint_id(pkt["source_ip"], pkt.get("source_mac"))
        dst_id = get_endpoint_id(pkt["destination_ip"], pkt.get("destination_mac"))
        
        packet_data = (
            investigation_id,
            pkt["packet_index"],
            ts,
            pkt["length"],
            pkt["protocol"],
            src_id,
            dst_id,
            pkt.get("source_port"),
            pkt.get("destination_port"),
            pkt.get("tcp_flags"),
            pkt.get("flow_id"),
            pkt["summary"]
        )
        packets_to_insert.append(packet_data)
        
        # Extract payload bytes and compress
        raw_text = pkt.get("payload_hex") or pkt.get("payload_ascii") or ""
        payload_bytes = bytes.fromhex(pkt.get("payload_hex")) if pkt.get("payload_hex") else raw_text.encode("utf-8", errors="ignore")
        compressed = compress_bytes(payload_bytes)
        entropy = calculate_entropy(payload_bytes)
        
        payloads_to_insert.append((
            investigation_id,
            pkt["packet_index"],
            compressed,
            pkt.get("payload_preview") or "",
            pkt.get("payload_kind") or "plaintext",
            json.dumps(pkt.get("decoded_fields", {})),
            "zlib",
            entropy
        ))
        
        # Collect terms for FTS search
        prev = pkt.get("payload_preview") or ""
        if prev:
            previews_list.append(prev)
        if pkt["protocol"] == "DNS" and prev:
            dns_list.append(prev)
        if "HTTP" in pkt["protocol"] and prev:
            http_list.append(prev)
        if pkt["protocol"] == "SIP" and prev:
            sip_list.append(prev)

    # Perform batch writes to packets database and capture starting ID
    with router._get_connection(PACKETS_DB_PATH) as conn:
        cursor = conn.execute("SELECT COALESCE(MAX(id), 0) FROM packets")
        base_packet_id = cursor.fetchone()[0] + 1
        conn.executemany(
            "INSERT INTO packets (investigation_id, packet_index, timestamp, length, protocol, src_endpoint_id, dst_endpoint_id, source_port, destination_port, tcp_flags, flow_id, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            packets_to_insert
        )
        
    # Write payloads with explicit packet_id FK
    with router._get_connection(PAYLOADS_DB_PATH) as conn:
        conn.executemany(
            "INSERT INTO payloads (packet_id, investigation_id, packet_index, payload_blob, payload_preview, mime_type, decoded_json, compression, entropy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (base_packet_id + i, *pl)
                for i, pl in enumerate(payloads_to_insert)
            ]
        )

    # 5. Populate Full-Text Search Table
    with router._get_connection(INVESTIGATIONS_DB_PATH) as conn:
        conn.execute(
            """INSERT INTO investigation_search 
            (investigation_id, filename, notes, dns_queries, http_headers, sip_messages, payload_previews)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                investigation_id,
                filename,
                "Case created from forensic upload",
                " ".join(dns_list)[:20000],
                " ".join(http_list)[:20000],
                " ".join(sip_list)[:20000],
                " ".join(previews_list)[:50000]
            )
        )

    logger.info(f"Saved investigation {investigation_id} with {len(packet_rows)} packets mapped across partitioned files.")
    return investigation_id

def get_investigation(investigation_id: str) -> dict | None:
    """Retrieve investigation metadata and rebuild the packet_rows array dynamically using cross-db attachments."""
    # 1. Fetch metadata
    with router._get_connection(INVESTIGATIONS_DB_PATH) as conn:
        inv = conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        if not inv:
            return None
            
        dest_rows = conn.execute("SELECT row_json FROM destinations WHERE investigation_id = ?", (investigation_id,)).fetchall()
        rows = [json.loads(r["row_json"]) for r in dest_rows]

    case = json.loads(inv["case_json"])
    
    # 2. Read packets and payloads using cross-db query
    packet_rows = []
    if PACKETS_DB_PATH.is_file() and PAYLOADS_DB_PATH.is_file():
        try:
            with router._get_connection(PACKETS_DB_PATH) as conn:
                conn.execute(f"ATTACH DATABASE '{PAYLOADS_DB_PATH}' AS payloads_db")
                conn.execute(f"ATTACH DATABASE '{GEOIP_DB_PATH}' AS geoip_db")
                
                # Fetch joined packets and payloads
                query = """
                    SELECT 
                        p.packet_index, p.timestamp, p.length, p.protocol,
                        p.source_port, p.destination_port, p.tcp_flags, p.flow_id, p.summary,
                        src.ip as source_ip, src.mac as source_mac,
                        dst.ip as destination_ip, dst.mac as destination_mac,
                        pl.payload_blob, pl.payload_preview, pl.mime_type as payload_kind, pl.decoded_json
                    FROM packets p
                    JOIN payloads_db.payloads pl ON p.id = pl.packet_id
                    JOIN geoip_db.endpoints src ON p.src_endpoint_id = src.id
                    JOIN geoip_db.endpoints dst ON p.dst_endpoint_id = dst.id
                    WHERE p.investigation_id = ?
                    ORDER BY p.id ASC
                """
                db_packets = conn.execute(query, (investigation_id,)).fetchall()
                
                # Decompress payload BLOBs on read
                for p in db_packets:
                    decompressed = decompress_bytes(p["payload_blob"])
                    
                    # Convert to hex representation or ascii for compatibility
                    payload_hex = decompressed.hex()
                    payload_ascii = decompressed.decode("utf-8", errors="ignore") if decompressed else ""
                    
                    packet_rows.append({
                        "packet_index": p["packet_index"],
                        "timestamp": p["timestamp"],
                        "length": p["length"],
                        "protocol": p["protocol"],
                        "source_port": p["source_port"],
                        "destination_port": p["destination_port"],
                        "tcp_flags": p["tcp_flags"],
                        "flow_id": p["flow_id"],
                        "summary": p["summary"],
                        "source_ip": p["source_ip"],
                        "source_mac": p["source_mac"],
                        "destination_ip": p["destination_ip"],
                        "destination_mac": p["destination_mac"],
                        "payload_preview": p["payload_preview"],
                        "payload_hex": payload_hex,
                        "payload_ascii": payload_ascii,
                        "payload_kind": p["payload_kind"],
                        "decoded_fields": json.loads(p["decoded_json"]) if p["decoded_json"] else {}
                    })
        except Exception as e:
            logger.error(f"Error fetching packets from partitioned databases: {e}")

    # Reassemble complete case dictionary
    case["packet_rows"] = packet_rows
    case["rows"] = rows
    
    return {
        "id": inv["id"],
        "filename": inv["filename"],
        "created_at": inv["created_at"],
        **case,
    }

def list_investigations() -> list[dict]:
    """Retrieve the sorted recent investigations list."""
    with router._get_connection(INVESTIGATIONS_DB_PATH) as conn:
        rows = conn.execute(
            "SELECT id, filename, created_at, summary_json FROM investigations ORDER BY created_at DESC LIMIT 25"
        ).fetchall()
    return [
        {
            "id": row["id"],
            "filename": row["filename"],
            "created_at": row["created_at"],
            "summary": json.loads(row["summary_json"]),
        }
        for row in rows
    ]
