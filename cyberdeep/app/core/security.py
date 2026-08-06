import time
import uuid
import logging
import asyncio
from collections import defaultdict
from app.storage.database import router
from app.core.bridge import broadcast_manager

logger = logging.getLogger(__name__)

class SecurityDetectionEngine:
    def __init__(self):
        # State for detection rules
        self.port_scan_tracker = defaultdict(set)  # src_ip -> set(dst_ports)
        self.arp_table = {}  # ip -> mac
        self.dns_query_count = defaultdict(int)  # src_ip -> count
        self.beacon_tracker = defaultdict(list)  # (src_ip, dst_ip) -> list of timestamps
        self.lateral_movement_tracker = defaultdict(set)  # src_ip -> set(dst_local_ips)
        self.last_clean = time.time()

    def process_packet(self, pkt_meta: dict, parsed_pkt: dict) -> list[dict]:
        """
        Processes a packet to detect security anomalies (disabled for VoIP focus).
        """
        return []

    def create_alert(self, flow_id: str, severity: str, rule: str, description: str) -> dict:
        return {
            "alert_id": str(uuid.uuid4())[:8],
            "flow_id": flow_id,
            "severity": severity.capitalize(),
            "rule": rule,
            "description": description,
            "confidence": 0.85,
            "timestamp": datetime_str()
        }

    def persist_alert(self, alert: dict):
        try:
            router.execute(
                "alerts",
                """INSERT INTO alerts (alert_id, flow_id, severity, rule, timestamp, confidence, status, resolved)
                VALUES (?, ?, ?, ?, ?, ?, 'New', 0)""",
                (
                    alert["alert_id"],
                    alert["flow_id"],
                    alert["severity"],
                    alert["rule"],
                    alert["timestamp"],
                    alert["confidence"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to persist alert in SQLite: {e}")

def datetime_str() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

def is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        p1 = int(parts[0])
        p2 = int(parts[1])
        if p1 == 10:
            return True
        if p1 == 192 and p2 == 168:
            return True
        if p1 == 172 and (16 <= p2 <= 31):
            return True
        return False
    except ValueError:
        return False

# Singleton
security_engine = SecurityDetectionEngine()
