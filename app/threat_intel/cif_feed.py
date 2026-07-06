"""CIF Feed Manager — parses bearded-avenger YAML rules and provides
multi-indicator lookups (IP, domain, URL, hash) with CIDR-aware matching."""

from __future__ import annotations

import hashlib
import logging
import random
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from app.threat_intel.cidr_index import CIDRIndex
from app.threat_intel.scoring import calculate_risk_score

logger = logging.getLogger(__name__)

_CIF_RULES_DIR = Path(__file__).resolve().parent.parent / "cif_rules"

# ── Regex patterns for auto-detecting indicator type ─────────────────
_RE_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_RE_CIDR = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}$"
)
_RE_HASH = re.compile(r"^[0-9a-fA-F]{32,128}$")
_RE_URL = re.compile(r"^https?://", re.IGNORECASE)
_RE_DOMAIN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

# ── Realistic sample bad-IP prefixes and domains ─────────────────────
_BAD_IP_PREFIXES = [
    "5.188.206", "5.188.210", "185.220.100", "185.220.101", "185.220.102",
    "45.155.205", "193.142.146", "194.26.29", "91.240.118", "77.247.181",
    "141.98.10", "45.95.169", "79.124.62", "45.134.26", "62.102.148",
    "45.148.10", "195.54.160", "80.82.77", "171.25.193", "109.70.100",
    "199.249.230", "51.15.43", "176.10.99", "23.129.64", "198.96.155",
    "209.141.32", "46.166.139", "94.102.49",
]

_KNOWN_MALICIOUS_IPS = [
    "5.188.206.10", "185.220.100.10", "185.220.101.5", "45.155.205.10",
    "193.142.146.10", "194.26.29.10", "91.240.118.10", "77.247.181.10",
    "141.98.10.10", "45.95.169.5", "79.124.62.10", "45.134.26.10",
    "62.102.148.5", "45.148.10.5", "195.54.160.5", "80.82.77.33",
]

_KNOWN_TOR_VPN_IPS = [
    "103.86.96.10", "89.187.160.10", "146.70.0.1",
    "169.150.196.5", "37.120.128.5",
]

_DGA_TLDS = [".com", ".net", ".org", ".info", ".xyz", ".top", ".ru", ".cn"]
_DGA_WORDS = [
    "xk3j9", "q7zt2m", "b9rx4", "nw5kp", "gh8vc", "t2fy6", "m4jx7",
    "r6wn3", "c8dp5", "v1hs9", "j3kq7", "p5tx2", "w7bn4", "f9mc6",
    "y2gr8", "s4lv1", "d6hp3", "a8ne5", "u1cw7", "e3it9",
]


class CIFFeedManager:
    """Manages CIF threat-intelligence feeds parsed from YAML rules."""

    def __init__(self) -> None:
        self.rules: list[dict] = []
        self._cidr_index = CIDRIndex()
        self._ip_set: dict[str, list[dict]] = {}
        self._domain_set: dict[str, list[dict]] = {}
        self._url_set: dict[str, list[dict]] = {}
        self._hash_set: dict[str, list[dict]] = {}
        self._feed_status: dict[str, dict] = {}
        self._loaded = False
        self._load()

    # ── Initialization ───────────────────────────────────────────────
    def _load(self) -> None:
        """Load YAML rules and populate indexes with demo data."""
        self._load_rules()
        self._generate_demo_data()
        self._cidr_index.build()
        self._loaded = True
        logger.info(
            "CIF Feed Manager loaded: %d rules, %d CIDR entries, %d IPs, "
            "%d domains, %d URLs, %d hashes",
            len(self.rules), self._cidr_index.size, len(self._ip_set),
            len(self._domain_set), len(self._url_set), len(self._hash_set),
        )

    def _load_rules(self) -> None:
        """Parse all YAML rule files from cif_rules/ directory."""
        if not _CIF_RULES_DIR.is_dir():
            logger.warning("CIF rules directory not found: %s", _CIF_RULES_DIR)
            return
        for yml_path in sorted(_CIF_RULES_DIR.glob("*.yml")):
            try:
                with yml_path.open("r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
                defaults = data.get("defaults", {})
                provider = defaults.get("provider", yml_path.stem)
                feeds = data.get("feeds", {})
                for feed_name, feed_cfg in feeds.items():
                    feed_cfg = feed_cfg or {}
                    feed_defaults = feed_cfg.get("defaults", {})
                    rule = {
                        "file": yml_path.name,
                        "provider": provider,
                        "feed_name": feed_name,
                        "remote": feed_cfg.get("remote", ""),
                        "confidence": feed_cfg.get(
                            "confidence",
                            feed_defaults.get("confidence", defaults.get("confidence", 7)),
                        ),
                        "tags": feed_defaults.get("tags", defaults.get("tags", [])),
                        "description": feed_defaults.get(
                            "description", defaults.get("description", "")
                        ),
                        "itype": feed_cfg.get("itype", ""),
                        "parser": feed_cfg.get("parser", data.get("parser", "pattern")),
                    }
                    # Normalize tags to list
                    if isinstance(rule["tags"], str):
                        rule["tags"] = [rule["tags"]]
                    self.rules.append(rule)
                    self._feed_status[f"{provider}/{feed_name}"] = {
                        "provider": provider,
                        "feed_name": feed_name,
                        "remote": rule["remote"],
                        "status": "demo",
                        "records": 0,
                        "last_sync": datetime.now(timezone.utc).isoformat(),
                    }
            except Exception:
                logger.exception("Failed to parse CIF rule: %s", yml_path)

    def _generate_demo_data(self) -> None:
        """Generate realistic demo IOC data from parsed rules."""
        rng = random.Random(42)  # deterministic seed for reproducibility

        for rule in self.rules:
            provider = rule["provider"]
            feed_name = rule["feed_name"]
            tags = rule["tags"]
            description = rule["description"]
            confidence = rule["confidence"]
            itype = rule.get("itype", "")
            status_key = f"{provider}/{feed_name}"
            count = 0

            meta_base = {
                "provider": provider,
                "feed_name": feed_name,
                "tags": tags,
                "description": description or feed_name,
                "confidence": confidence,
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }

            # Determine indicator type from rule metadata
            is_url_feed = itype == "url" or "url" in feed_name.lower() or "phish" in feed_name.lower()
            is_domain_feed = "domain" in feed_name.lower() or "dga" in feed_name.lower() or "dommasterlist" in feed_name.lower()
            is_hash_feed = "hash" in feed_name.lower() or "fingerprint" in feed_name.lower() or "ssl_fingerprints" in feed_name.lower()
            is_cidr_feed = "drop" in feed_name.lower() or "edrop" in feed_name.lower()

            if is_url_feed:
                # Generate sample malicious URLs
                for _ in range(rng.randint(15, 25)):
                    word = rng.choice(_DGA_WORDS)
                    tld = rng.choice(_DGA_TLDS)
                    path = rng.choice(["/payload.exe", "/mal.zip", "/login.php", "/update.bin", "/dl.js", "/index.html"])
                    url = f"http://{word}{rng.randint(1,99)}{tld}{path}"
                    meta = {**meta_base, "indicator": url, "indicator_type": "url"}
                    self._url_set.setdefault(url, []).append(meta)
                    count += 1

            elif is_domain_feed:
                # Generate DGA-style domains
                for _ in range(rng.randint(20, 30)):
                    word = rng.choice(_DGA_WORDS)
                    tld = rng.choice(_DGA_TLDS)
                    domain = f"{word}{rng.randint(1,999)}{tld}"
                    meta = {**meta_base, "indicator": domain, "indicator_type": "fqdn"}
                    self._domain_set.setdefault(domain, []).append(meta)
                    count += 1

            elif is_hash_feed:
                # Generate random SHA256 hashes
                for _ in range(rng.randint(15, 25)):
                    h = hashlib.sha256(f"{provider}-{feed_name}-{rng.random()}".encode()).hexdigest()
                    meta = {**meta_base, "indicator": h, "indicator_type": "hash"}
                    self._hash_set.setdefault(h, []).append(meta)
                    count += 1

            elif is_cidr_feed:
                # Generate CIDR ranges for Spamhaus-style feeds
                for prefix in rng.sample(_BAD_IP_PREFIXES, min(8, len(_BAD_IP_PREFIXES))):
                    cidr = f"{prefix}.0/24"
                    meta = {**meta_base, "indicator": cidr, "indicator_type": "cidr"}
                    self._cidr_index.add(cidr, meta)
                    count += 1

            else:
                # Default: IP-based feed — generate individual IPs
                for prefix in rng.sample(_BAD_IP_PREFIXES, min(6, len(_BAD_IP_PREFIXES))):
                    for _ in range(rng.randint(2, 4)):
                        ip = f"{prefix}.{rng.randint(1, 254)}"
                        meta = {**meta_base, "indicator": ip, "indicator_type": "ipv4"}
                        self._ip_set.setdefault(ip, []).append(meta)
                        self._cidr_index.add(f"{ip}/32", meta)
                        count += 1

            self._feed_status[status_key]["records"] = count

        # ── Inject known simulation IPs ──────────────────────────────
        # These IPs MUST match so the frontend demo shows real hits
        mal_providers = [
            ("emergingthreats.net", "compromised-ips", ["malware"], "compromised host"),
            ("spamhaus.org", "drop", ["hijacked"], "Spamhaus DROP list"),
            ("dataplane.org", "ssh", ["scanner", "bruteforce"], "SSH brute-force"),
        ]
        tor_providers = [
            ("torproject.org", "tor_exit_nodes", ["tor"], "Tor Exit Node"),
        ]
        vpn_providers = [
            ("dataplane.org", "sshclient", ["scanner"], "VPN/Proxy endpoint"),
        ]

        for ip in _KNOWN_MALICIOUS_IPS:
            for prov, fname, tags, desc in mal_providers:
                meta = {
                    "provider": prov, "feed_name": fname,
                    "tags": tags, "description": desc,
                    "confidence": 9, "indicator": ip,
                    "indicator_type": "ipv4",
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                }
                self._ip_set.setdefault(ip, []).append(meta)
                self._cidr_index.add(f"{ip}/32", meta)

        for ip in _KNOWN_TOR_VPN_IPS:
            for prov, fname, tags, desc in tor_providers + vpn_providers:
                meta = {
                    "provider": prov, "feed_name": fname,
                    "tags": tags, "description": desc,
                    "confidence": 8.5, "indicator": ip,
                    "indicator_type": "ipv4",
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                }
                self._ip_set.setdefault(ip, []).append(meta)
                self._cidr_index.add(f"{ip}/32", meta)

        self._cidr_index.build()

    # ── Public lookup API ────────────────────────────────────────────
    def lookup(self, indicator: str) -> dict:
        """Auto-detect indicator type and dispatch to the right lookup."""
        indicator = indicator.strip()
        if _RE_CIDR.match(indicator) or _RE_IPV4.match(indicator):
            return self.lookup_ip(indicator.split("/")[0])
        if _RE_URL.match(indicator):
            return self.lookup_url(indicator)
        if _RE_HASH.match(indicator):
            return self.lookup_hash(indicator)
        if _RE_DOMAIN.match(indicator):
            return self.lookup_domain(indicator)
        return self._build_result(indicator, "unknown", [])

    def lookup_ip(self, ip: str) -> dict:
        """IP lookup: exact hash + CIDR prefix match."""
        matches = []
        seen = set()
        # Exact IP match
        for m in self._ip_set.get(ip, []):
            key = (m["provider"], m["feed_name"])
            if key not in seen:
                seen.add(key)
                matches.append(m)
        # CIDR match
        for m in self._cidr_index.lookup(ip):
            key = (m["provider"], m["feed_name"])
            if key not in seen:
                seen.add(key)
                matches.append(m)
        return self._build_result(ip, "ipv4", matches)

    def lookup_domain(self, domain: str) -> dict:
        """Domain lookup: exact + suffix match."""
        domain = domain.lower().strip()
        matches = list(self._domain_set.get(domain, []))
        # Also try parent domain
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            matches.extend(self._domain_set.get(parent, []))
        return self._build_result(domain, "fqdn", matches)

    def lookup_url(self, url: str) -> dict:
        """URL lookup: exact match + domain extraction fallback."""
        matches = list(self._url_set.get(url, []))
        # Extract domain from URL and try domain lookup too
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname:
                domain_result = self.lookup_domain(parsed.hostname)
                if domain_result.get("cif_matches"):
                    matches.extend(domain_result["cif_matches"])
        except Exception:
            pass
        return self._build_result(url, "url", matches)

    def lookup_hash(self, hash_str: str) -> dict:
        """Hash lookup: exact match in hash set."""
        hash_str = hash_str.lower().strip()
        matches = list(self._hash_set.get(hash_str, []))
        return self._build_result(hash_str, "hash", matches)

    def get_status(self) -> dict:
        """Return feed sync status information."""
        total_records = sum(s["records"] for s in self._feed_status.values())
        return {
            "total_feeds": len(self._feed_status),
            "total_records": total_records,
            "cidr_index_size": self._cidr_index.size,
            "ip_index_size": len(self._ip_set),
            "domain_index_size": len(self._domain_set),
            "url_index_size": len(self._url_set),
            "hash_index_size": len(self._hash_set),
            "feeds": list(self._feed_status.values()),
        }

    # ── Internal helpers ─────────────────────────────────────────────
    def _build_result(self, indicator: str, itype: str, matches: list[dict]) -> dict:
        """Build a standardized result dict with risk scoring."""
        risk = calculate_risk_score(matches)
        all_tags = set()
        providers = []
        for m in matches:
            all_tags.update(m.get("tags", []))
            providers.append({
                "provider": m.get("provider", "unknown"),
                "feed_name": m.get("feed_name", ""),
                "confidence": m.get("confidence", 0),
                "description": m.get("description", ""),
                "tags": m.get("tags", []),
            })
        return {
            "indicator": indicator,
            "indicator_type": itype,
            "found": len(matches) > 0,
            "cif_matches": matches,
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "risk_confidence": risk["confidence"],
            "feed_count": risk["feed_count"],
            "tags": sorted(all_tags),
            "providers": providers,
            "last_seen": matches[0].get("last_seen", "") if matches else "",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
