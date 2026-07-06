from datetime import datetime, timezone
from ipaddress import ip_address

from app.threat_intel.abuseipdb_feed import AbuseIPDBFeed
from app.threat_intel.cif_feed import CIFFeedManager
from app.threat_intel.local_feed import LocalThreatFeed
from app.threat_intel.scoring import calculate_risk_score


class ThreatIntelManager:
    def __init__(self) -> None:
        self.feeds = [LocalThreatFeed(), AbuseIPDBFeed()]
        self.cif = CIFFeedManager()

    def lookup(self, ip: str) -> dict:
        """Legacy lookup — returns the original format for backward compat."""
        try:
            if not ip_address(ip).is_global:
                return {
                    "reputation_score": 0,
                    "abuse_reports": 0,
                    "malicious": False,
                    "threat_category": "Not applicable (non-public IP)",
                    "last_reported": "",
                    "last_checked": datetime.now(timezone.utc).isoformat(),
                    "feeds_checked": "Local address classification",
                }
        except ValueError:
            pass

        results = [feed.lookup(ip) for feed in self.feeds]
        highest = max(results, key=lambda item: item.get("reputation_score", 0))
        return {
            "reputation_score": highest.get("reputation_score", 0),
            "abuse_reports": highest.get("abuse_reports", 0),
            "malicious": any(item.get("malicious", False) for item in results),
            "threat_category": highest.get("threat_category", "None"),
            "last_reported": highest.get("last_reported", ""),
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "feeds_checked": ", ".join(item.get("feed", "Unknown") for item in results),
        }

    def lookup_indicator(self, indicator: str) -> dict:
        """Multi-indicator lookup with CIF feeds + risk scoring."""
        cif_result = self.cif.lookup(indicator)

        # If it's an IP, also check legacy feeds
        legacy = {}
        if cif_result.get("indicator_type") == "ipv4":
            legacy = self.lookup(indicator)

        return {
            **cif_result,
            "legacy": legacy,
        }

    def get_cif_status(self) -> dict:
        """Return CIF feed sync status."""
        return self.cif.get_status()
