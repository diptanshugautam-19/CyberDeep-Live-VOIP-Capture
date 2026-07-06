import json
from functools import lru_cache

from app.core.config import DATA_DIR
from app.threat_intel.base import ThreatFeed


class LocalThreatFeed(ThreatFeed):
    name = "Local Open Threat Feed"

    def lookup(self, ip: str) -> dict:
        record = _load_feed().get(ip)
        if not record:
            return {
                "feed": self.name,
                "reputation_score": 0,
                "abuse_reports": 0,
                "malicious": False,
                "threat_category": "None",
                "last_reported": "",
            }
        return {"feed": self.name, **record}


@lru_cache(maxsize=1)
def _load_feed() -> dict:
    path = DATA_DIR / "local_threat_feed.json"
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
