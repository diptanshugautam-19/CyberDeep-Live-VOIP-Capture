"""
ASN Lookup Engine  (Offline-first, Online-fallback)
====================================================
1. OFFLINE — Binary search over DB-IP dataset (404k IPv4 + 73k IPv6 ranges)
             combined with RIPE ASN name registry (121k names).
             Sub-millisecond, no network call.

2. ONLINE FALLBACK — If offline finds no match, queries (in order):
     a. RIPE Stat  (https://stat.ripe.net/data/prefix-overview/data.json)
     b. Team Cymru DNS whois (whois.cymru.com:43)
     c. ipwhois.io  (https://ipwho.is/<ip>)
   The first successful response is cached (24 h) in an in-memory dict
   so the same IP is never fetched twice.

Data files expected at:
  data/geoip/asn_ipv4.json   - [[start_int, end_int, asn], ...]
  data/geoip/asn_ipv6.json   - [[start_int, end_int, asn], ...]
  data/geoip/asn_names.txt   - RIPE asn.txt: "<asn> <tag> - <org>, <cc>"
"""

from __future__ import annotations

import bisect
import json
import logging
import pathlib
import ipaddress
import re
import socket
import threading
import time
from functools import lru_cache
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────
_BASE      = pathlib.Path(__file__).resolve().parent.parent.parent  # repo root
_IPV4_JSON = _BASE / "data" / "geoip" / "asn_ipv4.json"
_IPV6_JSON = _BASE / "data" / "geoip" / "asn_ipv6.json"
_NAMES_TXT = _BASE / "data" / "geoip" / "asn_names.txt"

# ──────────────────────────────────────────────
# Thread-safe singleton loader
# ──────────────────────────────────────────────
_lock   = threading.Lock()
_loaded = False

_ipv4_starts: list[int] = []
_ipv4_ends:   list[int] = []
_ipv4_asns:   list[int] = []

_ipv6_starts: list[int] = []
_ipv6_ends:   list[int] = []
_ipv6_asns:   list[int] = []

_asn_names: dict[int, Tuple[str, str]] = {}   # asn_num -> (org, cc)

# Online-fallback in-memory cache: ip -> (result_dict, expires_at)
_online_cache: dict[str, Tuple[dict, float]] = {}
_ONLINE_TTL = 86400.0  # 24 hours

_RIPE_LINE = re.compile(r"^(\d+)\s+\S+\s+-\s+(.+?),\s*([A-Z]{2})$")


def _load() -> None:
    global _loaded, _ipv4_starts, _ipv4_ends, _ipv4_asns
    global _ipv6_starts, _ipv6_ends, _ipv6_asns, _asn_names

    with _lock:
        if _loaded:
            return

        if _IPV4_JSON.exists():
            logger.info("Loading IPv4 ASN ranges …")
            rows = json.loads(_IPV4_JSON.read_bytes())
            _ipv4_starts = [r[0] for r in rows]
            _ipv4_ends   = [r[1] for r in rows]
            _ipv4_asns   = [r[2] for r in rows]
            logger.info("  %d IPv4 ASN ranges loaded", len(_ipv4_starts))
        else:
            logger.warning("IPv4 ASN JSON not found: %s", _IPV4_JSON)

        if _IPV6_JSON.exists():
            logger.info("Loading IPv6 ASN ranges …")
            rows6 = json.loads(_IPV6_JSON.read_bytes())
            _ipv6_starts = [r[0] for r in rows6]
            _ipv6_ends   = [r[1] for r in rows6]
            _ipv6_asns   = [r[2] for r in rows6]
            logger.info("  %d IPv6 ASN ranges loaded", len(_ipv6_starts))
        else:
            logger.warning("IPv6 ASN JSON not found: %s", _IPV6_JSON)

        if _NAMES_TXT.exists():
            logger.info("Loading RIPE ASN names …")
            count = 0
            with _NAMES_TXT.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = _RIPE_LINE.match(line.strip())
                    if m:
                        _asn_names[int(m.group(1))] = (m.group(2).strip(), m.group(3).strip())
                        count += 1
            logger.info("  %d ASN names loaded", count)
        else:
            logger.warning("RIPE ASN names file not found: %s", _NAMES_TXT)

        _loaded = True


def _ensure_loaded() -> None:
    if not _loaded:
        _load()


# ──────────────────────────────────────────────
# Binary-search helpers
# ──────────────────────────────────────────────

def _search_ipv4(ip_int: int) -> Optional[int]:
    idx = bisect.bisect_right(_ipv4_starts, ip_int) - 1
    if idx >= 0 and ip_int <= _ipv4_ends[idx]:
        return _ipv4_asns[idx]
    return None


def _search_ipv6(ip_int: int) -> Optional[int]:
    idx = bisect.bisect_right(_ipv6_starts, ip_int) - 1
    if idx >= 0 and ip_int <= _ipv6_ends[idx]:
        return _ipv6_asns[idx]
    return None


# ──────────────────────────────────────────────
# Online fallback methods
# ──────────────────────────────────────────────

def _online_ripe_stat(ip: str) -> Optional[dict]:
    """Query RIPE Stat prefix-overview API."""
    try:
        import httpx
        url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}&sourceapp=cyberdeep"
        r = httpx.get(url, timeout=5.0)
        if r.status_code == 200:
            data = r.json().get("data", {})
            asns = data.get("asns", [])
            if asns:
                asn_num  = int(asns[0].get("asn", 0))
                asn_org  = asns[0].get("holder", "")
                prefix   = data.get("resource", "")
                return {
                    "asn_number": asn_num,
                    "asn": f"AS{asn_num}",
                    "asn_org": asn_org,
                    "asn_cc": "",
                    "network_prefix": prefix,
                    "source": "online-ripe-stat",
                }
    except Exception as e:
        logger.debug("RIPE Stat lookup failed for %s: %s", ip, e)
    return None


def _online_cymru_whois(ip: str) -> Optional[dict]:
    """Query Team Cymru whois.cymru.com:43 for ASN."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect(("whois.cymru.com", 43))
        # Cymru bulk query mode with verbose header
        s.sendall(f"begin\nverbose\n{ip}\nend\n".encode("utf-8"))
        raw = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw += chunk
        s.close()
        text = raw.decode("utf-8", errors="replace")
        # Format: ASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("AS") or (line and line[0].isdigit()):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 7:
                    try:
                        asn_num = int(parts[0].replace("AS", "").strip())
                        cc      = parts[3].strip() if len(parts) > 3 else ""
                        org     = parts[6].strip() if len(parts) > 6 else ""
                        # Strip registry suffix like ", ARIN"
                        if "," in org:
                            org = org.rsplit(",", 1)[0].strip()
                        if asn_num:
                            return {
                                "asn_number": asn_num,
                                "asn": f"AS{asn_num}",
                                "asn_org": org,
                                "asn_cc": cc,
                                "network_prefix": parts[2].strip() if len(parts) > 2 else "",
                                "source": "online-cymru-whois",
                            }
                    except (ValueError, IndexError):
                        continue
    except Exception as e:
        logger.debug("Cymru whois failed for %s: %s", ip, e)
    return None


def _online_ipwhois(ip: str) -> Optional[dict]:
    """Query ipwho.is as final online fallback."""
    try:
        import httpx
        r = httpx.get(f"https://ipwho.is/{ip}", timeout=5.0)
        if r.status_code == 200:
            data = r.json()
            if data.get("success") is True:
                conn = data.get("connection") or {}
                asn_num = int(conn.get("asn") or 0)
                org     = conn.get("org") or conn.get("isp") or ""
                cc      = data.get("country_code") or ""
                if asn_num:
                    return {
                        "asn_number": asn_num,
                        "asn": f"AS{asn_num}",
                        "asn_org": org,
                        "asn_cc": cc,
                        "network_prefix": "",
                        "source": "online-ipwhois",
                    }
    except Exception as e:
        logger.debug("ipwho.is lookup failed for %s: %s", ip, e)
    return None


def _lookup_online(ip: str) -> dict:
    """
    Try online sources in order: RIPE Stat → Cymru WHOIS → ipwho.is.
    Result is cached for 24 hours in _online_cache.
    """
    now = time.monotonic()

    # Check in-memory online cache first
    cached = _online_cache.get(ip)
    if cached:
        result, expires_at = cached
        if now < expires_at:
            return result

    result: dict = {
        "asn": "", "asn_number": 0, "asn_org": "",
        "asn_cc": "", "network_prefix": "", "source": "unknown",
    }

    for fetcher in (_online_ripe_stat, _online_cymru_whois, _online_ipwhois):
        try:
            r = fetcher(ip)
            if r and r.get("asn_number"):
                result = r
                # Also store name in _asn_names for future offline lookups this session
                asn_num = r["asn_number"]
                if asn_num and asn_num not in _asn_names and r.get("asn_org"):
                    _asn_names[asn_num] = (r["asn_org"], r.get("asn_cc", ""))
                break
        except Exception:
            continue

    _online_cache[ip] = (result, now + _ONLINE_TTL)
    return result


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

@lru_cache(maxsize=65536)
def lookup_asn(ip: str) -> dict:
    """
    ASN lookup with offline-first, online-fallback strategy.

    Returns dict with keys:
        asn          - e.g. "AS55836"
        asn_number   - int (0 if unknown)
        asn_org      - org name, e.g. "Reliance Jio Infocomm Limited"
        asn_cc       - ISO country code, e.g. "IN"
        network_prefix - CIDR prefix (online sources only)
        source       - "offline-db-ip" | "online-ripe-stat" |
                       "online-cymru-whois" | "online-ipwhois" | "unknown"
    """
    _ensure_loaded()

    empty = {
        "asn": "", "asn_number": 0, "asn_org": "",
        "asn_cc": "", "network_prefix": "", "source": "unknown",
    }

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return empty

    ip_int  = int(addr)
    asn_num: Optional[int] = None

    # ── 1. Offline binary search ──
    if addr.version == 4:
        asn_num = _search_ipv4(ip_int)
    else:
        asn_num = _search_ipv6(ip_int)

    if asn_num:
        org, cc = _asn_names.get(asn_num, ("", ""))
        return {
            "asn":            f"AS{asn_num}",
            "asn_number":     asn_num,
            "asn_org":        org,
            "asn_cc":         cc,
            "network_prefix": "",
            "source":         "offline-db-ip",
        }

    # ── 2. Online fallback ──
    logger.info("ASN offline miss for %s — querying online sources …", ip)
    result = _lookup_online(ip)

    if result.get("asn_number"):
        logger.info(
            "Online ASN resolved %s -> %s (%s) via %s",
            ip, result["asn"], result["asn_org"], result["source"],
        )
    else:
        logger.warning("ASN completely unknown for %s (offline + online miss)", ip)

    return result


def lookup_asn_number(ip: str) -> int:
    """Return just the ASN number (0 if unknown)."""
    return lookup_asn(ip)["asn_number"]


def lookup_asn_org(ip: str) -> str:
    """Return just the org name, e.g. 'Reliance Jio Infocomm Limited'."""
    return lookup_asn(ip)["asn_org"]


def get_asn_name(asn_number: int) -> Tuple[str, str]:
    """Return (org_name, country_code) for a known ASN, or ('', '')."""
    _ensure_loaded()
    return _asn_names.get(asn_number, ("", ""))
