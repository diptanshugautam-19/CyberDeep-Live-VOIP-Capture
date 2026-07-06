from __future__ import annotations

FEED_WEIGHTS: dict[str, int] = {
    "spamhaus.org": 15,
    "feodotracker.abuse.ch": 14,
    "sslbl.abuse.ch": 13,
    "emergingthreats.net": 12,
    "urlhaus.abuse.ch": 13,
    "osint.bambenekconsulting.com": 12,
    "openphish.com": 11,
    "phishtank.com": 12,
    "torproject.org": 10,
    "dataplane.org": 11,
    "csirtg.io": 10,
    "abuseipdb.com": 10,
    "alienvault_otx": 10,
    "greynoise.io": 9,
    "darklist.de": 9,
    "normshield.com": 9,
    "sans.edu": 10,
    "stopforumspam.com": 8,
    "vxvault.net": 11,
    "danger.rulez.sk": 8,
    "sblam.com": 7,
    "mirc.com": 7,
    "default": 8,
}


def calculate_risk_score(matches: list[dict]) -> dict:
    if not matches:
        return {"score": 0, "level": "None", "confidence": 0, "feed_count": 0}

    total_weight = sum(
        FEED_WEIGHTS.get(m.get("provider", ""), FEED_WEIGHTS["default"])
        for m in matches
    )
    raw_score = min(100, total_weight)
    confidence = min(99, len(matches) * 15 + raw_score // 3)

    if raw_score >= 81:
        level = "Critical"
    elif raw_score >= 51:
        level = "High"
    elif raw_score >= 21:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": raw_score,
        "level": level,
        "confidence": confidence,
        "feed_count": len(matches),
    }
