from __future__ import annotations

from functools import lru_cache

import httpx

from app.core.config import ABUSEIPDB_API_KEY, LIVE_LOOKUP_TIMEOUT_SECONDS, ONLINE_ENRICHMENT_ENABLED
from app.threat_intel.base import ThreatFeed


class AbuseIPDBFeed(ThreatFeed):
    name = "AbuseIPDB Live"

    def enabled(self) -> bool:
        return ONLINE_ENRICHMENT_ENABLED and bool(ABUSEIPDB_API_KEY)

    def lookup(self, ip: str) -> dict:
        if not self.enabled():
            return {
                "feed": self.name,
                "reputation_score": 0,
                "abuse_reports": 0,
                "malicious": False,
                "threat_category": "None",
                "last_reported": "",
            }

        data = _check_abuseipdb(ip, ABUSEIPDB_API_KEY, LIVE_LOOKUP_TIMEOUT_SECONDS)
        if not data:
            return {
                "feed": self.name,
                "reputation_score": 0,
                "abuse_reports": 0,
                "malicious": False,
                "threat_category": "None",
                "last_reported": "",
            }

        score = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        categories = data.get("reports") or []
        return {
            "feed": self.name,
            "reputation_score": score,
            "abuse_reports": reports,
            "malicious": score >= 75,
            "threat_category": "AbuseIPDB Reported" if reports else "None",
            "last_reported": data.get("lastReportedAt") or "",
        }


@lru_cache(maxsize=4096)
def _check_abuseipdb(ip: str, api_key: str, timeout: float) -> dict:
    try:
        response = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": api_key},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict):
            return payload.get("data", {}) or {}
    except Exception:
        return {}
    return {}
