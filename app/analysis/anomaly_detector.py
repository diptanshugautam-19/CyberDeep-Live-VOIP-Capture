"""
Behavioral Anomaly & Threat Detection Engine.
Detects C2 Beaconing, Port Scans, DNS Tunneling, and Data Exfiltration patterns.
"""

import math
import time
import logging
from collections import defaultdict
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy for string text."""
    if not text:
        return 0.0
    length = len(text)
    counts = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    return round(-sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values()), 2)

class AnomalyDetector:
    def __init__(self):
        # 1. Beaconing Tracker: src_ip -> dst_ip -> list of timestamps
        self.connection_timestamps: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        
        # 2. Port Scan Tracker: src_ip -> set of (dst_ip, dst_port)
        self.port_scan_attempts: Dict[str, set] = defaultdict(set)
        
        # 3. DNS Tunneling Tracker: domain -> list of query timestamps
        self.dns_subdomain_entropy: Dict[str, List[float]] = defaultdict(list)
        
        # Alerts history
        self.alerts: List[Dict[str, Any]] = []

    def analyze_flow(self, session: dict) -> List[Dict[str, Any]]:
        """
        Analyzes flow metrics to detect behavioral anomalies.
        """
        detected_alerts = []
        src_ip = session.get("source_ip") or ""
        dst_ip = session.get("destination_ip") or ""
        src_port = session.get("source_port") or 0
        dst_port = session.get("destination_port") or 0
        protocol = session.get("protocol") or ""
        now = time.time()

        if not src_ip or not dst_ip:
            return detected_alerts

        # --- A. C2 Beaconing Detection ---
        timestamps = self.connection_timestamps[src_ip][dst_ip]
        timestamps.append(now)
        if len(timestamps) > 50:
            timestamps.pop(0)

        if len(timestamps) >= 6:
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)

            # Low interval variance indicates regular periodic heartbeats (Beaconing)
            if avg_interval > 2.0 and std_dev < 1.0:
                alert = {
                    "type": "C2_BEACONING",
                    "severity": "HIGH",
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "avg_interval_sec": round(avg_interval, 2),
                    "variance": round(variance, 4),
                    "description": f"Potential C2 Beaconing detected from {src_ip} to {dst_ip} (Interval: {round(avg_interval, 1)}s, Low Variance)"
                }
                detected_alerts.append(alert)

        # --- B. Port Scanning Sweep Detection ---
        if session.get("tcp_state") == "SYN_SENT" or protocol == "TCP":
            self.port_scan_attempts[src_ip].add((dst_ip, dst_port))
            if len(self.port_scan_attempts[src_ip]) > 30:
                alert = {
                    "type": "PORT_SCAN",
                    "severity": "MEDIUM",
                    "source_ip": src_ip,
                    "distinct_targets": len(self.port_scan_attempts[src_ip]),
                    "description": f"Port Scanning / Network Sweep detected from {src_ip} targeting {len(self.port_scan_attempts[src_ip])} endpoints"
                }
                detected_alerts.append(alert)

        # --- C. Data Exfiltration Detection ---
        c2s_bytes = session.get("c2s_bytes", 0)
        s2c_bytes = session.get("s2c_bytes", 0)
        total_bytes = session.get("bytes", 0)

        if total_bytes > 5 * 1024 * 1024:  # > 5MB flow
            # Asymmetric egress (Outbound >> Inbound)
            if c2s_bytes > 10 * max(s2c_bytes, 1):
                alert = {
                    "type": "DATA_EXFILTRATION",
                    "severity": "HIGH",
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "uploaded_bytes": c2s_bytes,
                    "description": f"Large Asymmetric Outbound Exfiltration detected: {round(c2s_bytes / (1024*1024), 2)}MB sent to {dst_ip}"
                }
                detected_alerts.append(alert)

        for alert in detected_alerts:
            self.alerts.append(alert)

        return detected_alerts

    def analyze_dns_query(self, domain: str, client_ip: str) -> Optional[Dict[str, Any]]:
        """
        Analyzes DNS query strings for DNS Tunneling & Exfiltration patterns.
        """
        if not domain:
            return None

        # Calculate subdomain entropy
        subdomain = domain.split(".")[0]
        entropy = calculate_shannon_entropy(subdomain)

        if len(subdomain) > 25 and entropy > 4.2:
            alert = {
                "type": "DNS_TUNNELING",
                "severity": "CRITICAL",
                "source_ip": client_ip,
                "domain": domain,
                "entropy": entropy,
                "description": f"DNS Tunneling / Data Exfiltration query detected: '{domain}' (Entropy: {entropy})"
            }
            self.alerts.append(alert)
            return alert

        return None

anomaly_detector = AnomalyDetector()
