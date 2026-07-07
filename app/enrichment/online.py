from __future__ import annotations

from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def _geocode_city(city: str, region: str, country: str) -> tuple[float | None, float | None]:
    if not city or str(city).lower() in ("unknown", "lan", "local", "private", "n/a", "-"):
        return None, None
    try:
        parts = [city]
        if region and str(region).lower() not in ("unknown", "lan", "local", "private", "n/a", "-"):
            parts.append(region)
        if country and str(country).lower() not in ("unknown", "lan", "local", "private", "n/a", "-"):
            parts.append(country)
        q = ", ".join(parts)
        url = f"https://nominatim.openstreetmap.org/search?q={q}&format=json&limit=1"
        headers = {"User-Agent": "CyberDeep/1.0 (contact: info@cyberdeep.io)"}
        r = httpx.get(url, headers=headers, timeout=1.0)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list) and len(data) > 0:
                return float(data[0]["lat"]), float(data[0]["lon"])
    except Exception:
        pass
    return None, None


@lru_cache(maxsize=4096)
def _lookup_ip_api(ip: str, timeout: float) -> dict:
    def get_ipwhois():
        try:
            r = httpx.get(f"https://ipwho.is/{ip}", timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict) and data.get("success") is True:
                    data["_source"] = "ipwhois"
                    return data
        except Exception:
            pass
        return None

    def get_freeipapi():
        try:
            r = httpx.get(f"https://free.freeipapi.com/api/json/{ip}", timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict) and "ipAddress" in data:
                    data["_source"] = "freeipapi"
                    return data
        except Exception:
            pass
        return None

    def get_ipapi_com():
        try:
            r = httpx.get(
                f"https://api.ipapi.com/api/{ip}?access_key=aaa1119c0fa056fe2253d2034216f78a",
                timeout=timeout
            )
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict) and not data.get("error") and "latitude" in data:
                    data["_source"] = "ipapi_com"
                    return data
        except Exception:
            pass
        return None

    def get_ipapi_co():
        try:
            r = httpx.get(f"https://ipapi.co/{ip}/json/", timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict) and not data.get("error") and "country_name" in data:
                    data["_source"] = "ipapi.co"
                    return data
        except Exception:
            pass
        return None

    def get_ip_api_com():
        try:
            r = httpx.get(f"http://ip-api.com/json/{ip}", timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict) and data.get("status") == "success":
                    data["_source"] = "ip-api.com"
                    return data
        except Exception:
            pass
        return None

    workers = [get_ipwhois, get_freeipapi, get_ipapi_com, get_ipapi_co, get_ip_api_com]
    
    with ThreadPoolExecutor(max_workers=len(workers)) as executor:
        futures = [executor.submit(w) for w in workers]
        for fut in as_completed(futures):
            try:
                res = fut.result()
                if res:
                    return res
            except Exception:
                pass
    return {}

def _clean_org(org: str, isp: str) -> str:
    if not org:
        return isp or ""
    # If the org value looks like a physical street address, fall back to ISP
    org_lower = org.lower()
    address_indicators = ["plot no", "sector", "phase", "building", "road", "street", "floor", "highway", "p.o. box"]
    for indicator in address_indicators:
        if indicator in org_lower:
            return isp or org
    # If the org is extremely long and contains multiple commas (typical address structure)
    if len(org) > 50 and org.count(",") >= 2:
        return isp or org
    return org


def _parse_ip_api_result_raw(result: dict) -> dict:
    source = result.get("_source", "live api")
    if source == "ipwhois":
        conn_info = result.get("connection") or {}
        asn_val = conn_info.get("asn") or ""
        asn_str = f"AS{asn_val}" if asn_val and not str(asn_val).upper().startswith("AS") else str(asn_val)
        isp_name = conn_info.get("isp") or ""
        org_name = conn_info.get("org") or ""
        clean_org = _clean_org(org_name, isp_name)
        return {
            "isp": isp_name,
            "asn": asn_str,
            "asn_number": _asn_number(asn_str),
            "asn_org": clean_org,
            "network_prefix": "",
            "country": result.get("country") or "",
            "region": result.get("region") or "",
            "city": result.get("city") or "",
            "latitude": result.get("latitude"),
            "longitude": result.get("longitude"),
            "hostname": "",
            "ip_source": "ipwho.is live",
        }
    elif source == "freeipapi":
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
    elif source == "ipapi_com":
        conn_info = result.get("connection") or {}
        asn_val = conn_info.get("asn") or ""
        asn_str = f"AS{asn_val}" if asn_val and not str(asn_val).upper().startswith("AS") else str(asn_val)
        return {
            "isp": conn_info.get("isp") or "",
            "asn": asn_str,
            "asn_number": _asn_number(asn_str),
            "asn_org": conn_info.get("isp") or "",
            "network_prefix": "",
            "country": result.get("country_name") or "",
            "region": result.get("region_name") or "",
            "city": result.get("city") or "",
            "latitude": result.get("latitude"),
            "longitude": result.get("longitude"),
            "hostname": "",
            "ip_source": "api.ipapi.com live",
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


def _parse_ip_api_result(result: dict) -> dict:
    parsed = _parse_ip_api_result_raw(result)
    lat = parsed.get("latitude")
    lon = parsed.get("longitude")
    if (lat is None or lon is None or lat == 0.0 or lon == 0.0) and parsed.get("city"):
        lat_ref, lon_ref = _geocode_city(parsed["city"], parsed.get("region"), parsed.get("country"))
        if lat_ref is not None and lon_ref is not None:
            parsed["latitude"] = lat_ref
            parsed["longitude"] = lon_ref
    return parsed
