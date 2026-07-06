from __future__ import annotations

from functools import lru_cache

import httpx

from app.core.config import IPINFO_TOKEN, LIVE_LOOKUP_TIMEOUT_SECONDS, ONLINE_ENRICHMENT_ENABLED


class OnlineIPInfoProvider:
    def __init__(self) -> None:
        self.token = IPINFO_TOKEN
        self.timeout = LIVE_LOOKUP_TIMEOUT_SECONDS

    def enabled(self) -> bool:
        return ONLINE_ENRICHMENT_ENABLED and bool(self.token)

    def lookup(self, ip: str) -> dict:
        if not self.enabled():
            free_result = _lookup_ip_api(ip, self.timeout)
            if free_result:
                return _parse_ip_api_result(free_result)
            return {}

        result = _lookup_ipinfo(ip, self.token, self.timeout)
        if not result:
            free_result = _lookup_ip_api(ip, self.timeout)
            if free_result:
                return _parse_ip_api_result(free_result)
            return {}

        asn_value = result.get("asn") or ""
        asn_number = _asn_number(asn_value)
        loc = result.get("loc", "")
        latitude, longitude = _parse_loc(loc)
        return {
            "isp": result.get("as_name") or result.get("org") or "",
            "asn": asn_value or ("AS" + str(asn_number) if asn_number else ""),
            "asn_number": asn_number,
            "asn_org": result.get("as_name") or result.get("org") or "",
            "network_prefix": result.get("network") or result.get("prefix") or "",
            "country": result.get("country") or result.get("country_name") or "",
            "region": result.get("region") or "",
            "city": result.get("city") or "",
            "latitude": latitude,
            "longitude": longitude,
            "hostname": result.get("hostname") or "",
            "ip_source": "IPinfo live",
        }


@lru_cache(maxsize=4096)
def _lookup_ipinfo(ip: str, token: str, timeout: float) -> dict:
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    urls = [
        f"https://api.ipinfo.io/lookup/{ip}",
        f"https://api.ipinfo.io/lite/{ip}",
    ]
    for url in urls:
        try:
            response = httpx.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict) and data:
                return data
        except Exception:
            continue
    return {}


def _asn_number(value: str) -> int:
    if not value:
        return 0
    try:
        return int(str(value).upper().replace("AS", ""))
    except ValueError:
        return 0


def _parse_loc(value: str) -> tuple[float | None, float | None]:
    if not value or "," not in value:
        return None, None
    lat, lon = value.split(",", 1)
    try:
        return float(lat), float(lon)
    except ValueError:
        return None, None


@lru_cache(maxsize=4096)
def _lookup_ip_api(ip: str, timeout: float) -> dict:
    # 1. Try free.freeipapi.com as primary since it supports HTTPS and allows burst queries
    try:
        response = httpx.get(f"https://free.freeipapi.com/api/json/{ip}", timeout=timeout)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict) and "ipAddress" in data:
            data["_source"] = "freeipapi"
            return data
    except Exception:
        pass

    # 2. Try ipapi.co as secondary
    try:
        response = httpx.get(f"https://ipapi.co/{ip}/json/", timeout=timeout)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict) and not data.get("error"):
            data["_source"] = "ipapi.co"
            return data
    except Exception:
        pass

    # 3. Try ip-api.com as tertiary
    try:
        response = httpx.get(f"http://ip-api.com/json/{ip}", timeout=timeout)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict) and data.get("status") == "success":
            data["_source"] = "ip-api.com"
            return data
    except Exception:
        pass
    
    return {}


def _parse_ip_api_result(result: dict) -> dict:
    source = result.get("_source", "live api")
    if source == "freeipapi":
        asn_val = result.get("asn") or ""
        asn_str = f"AS{asn_val}" if asn_val and not str(asn_val).upper().startswith("AS") else str(asn_val)
        return {
            "isp": result.get("asnOrganization") or "",
            "asn": asn_str,
            "asn_number": _asn_number(asn_str),
            "asn_org": result.get("asnOrganization") or "",
            "network_prefix": "",
            "country": result.get("countryName") or "",
            "region": result.get("regionName") or "",
            "city": result.get("cityName") or "",
            "latitude": result.get("latitude"),
            "longitude": result.get("longitude"),
            "hostname": "",
            "ip_source": "freeipapi live",
        }
    elif source == "ipapi.co":
        asn_value = result.get("asn") or ""
        return {
            "isp": result.get("org") or "",
            "asn": asn_value,
            "asn_number": _asn_number(asn_value),
            "asn_org": result.get("org") or "",
            "network_prefix": result.get("network") or "",
            "country": result.get("country_name") or result.get("country") or "",
            "region": result.get("region") or "",
            "city": result.get("city") or "",
            "latitude": result.get("latitude"),
            "longitude": result.get("longitude"),
            "hostname": "",
            "ip_source": "ipapi.co live",
        }
    else:
        asn_value = result.get("as") or ""
        return {
            "isp": result.get("isp") or "",
            "asn": asn_value.split(" ")[0] if asn_value else "",
            "asn_number": _asn_number(asn_value),
            "asn_org": result.get("org") or result.get("isp") or "",
            "network_prefix": "",
            "country": result.get("country") or "",
            "region": result.get("regionName") or "",
            "city": result.get("city") or "",
            "latitude": result.get("lat"),
            "longitude": result.get("lon"),
            "hostname": "",
            "ip_source": "ip-api.com live",
        }
