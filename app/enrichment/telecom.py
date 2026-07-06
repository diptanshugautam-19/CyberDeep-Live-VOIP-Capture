import ipaddress
import json
import socket
from functools import lru_cache

from app.core.config import GEOIP_DIR
from app.enrichment.online import OnlineIPInfoProvider


DEFAULT_NETWORKS = [
    {
        "prefix": "157.240.0.0/16",
        "asn": 32934,
        "asn_org": "Meta Platforms, Inc.",
        "isp": "Meta Platforms",
        "country": "India",
        "region": "Maharashtra",
        "city": "Mumbai",
        "latitude": 19.0760,
        "longitude": 72.8777,
    },
    {
        "prefix": "149.154.160.0/20",
        "asn": 62041,
        "asn_org": "Telegram Messenger LLP",
        "isp": "Telegram",
        "country": "Netherlands",
        "region": "North Holland",
        "city": "Amsterdam",
        "latitude": 52.3676,
        "longitude": 4.9041,
    },
    {
        "prefix": "35.190.0.0/17",
        "asn": 15169,
        "asn_org": "Google LLC",
        "isp": "Google Cloud",
        "country": "United States",
        "region": "Iowa",
        "city": "Council Bluffs",
        "latitude": 41.2619,
        "longitude": -95.8608,
    },
    {
        "prefix": "52.96.0.0/14",
        "asn": 8075,
        "asn_org": "Microsoft Corporation",
        "isp": "Microsoft Azure",
        "country": "United States",
        "region": "Washington",
        "city": "Redmond",
        "latitude": 47.6740,
        "longitude": -122.1215,
    },
    {
        "prefix": "162.159.0.0/16",
        "asn": 13335,
        "asn_org": "Cloudflare, Inc.",
        "isp": "Cloudflare",
        "country": "United States",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.7749,
        "longitude": -122.4194,
    },
    {
        "prefix": "13.224.0.0/14",
        "asn": 16509,
        "asn_org": "Amazon.com, Inc.",
        "isp": "AWS CloudFront",
        "country": "United States",
        "region": "Virginia",
        "city": "Ashburn",
        "latitude": 39.0438,
        "longitude": -77.4874,
    },
    {
        "prefix": "64.233.160.0/19",
        "asn": 15169,
        "asn_org": "Google LLC",
        "isp": "Google",
        "country": "United States",
        "region": "California",
        "city": "Mountain View",
        "latitude": 37.3861,
        "longitude": -122.0839,
    },
    {
        "prefix": "8.8.8.0/24",
        "asn": 15169,
        "asn_org": "Google LLC",
        "isp": "Google",
        "country": "United States",
        "region": "California",
        "city": "Mountain View",
        "latitude": 37.3861,
        "longitude": -122.0839,
    },
    {
        "prefix": "142.250.0.0/15",
        "asn": 15169,
        "asn_org": "Google LLC",
        "isp": "Google",
        "country": "India",
        "region": "Maharashtra",
        "city": "Mumbai",
        "latitude": 19.0760,
        "longitude": 72.8777,
    },
    {
        "prefix": "1.1.1.0/24",
        "asn": 13335,
        "asn_org": "Cloudflare, Inc.",
        "isp": "Cloudflare",
        "country": "Australia",
        "region": "Queensland",
        "city": "South Brisbane",
        "latitude": -27.4766,
        "longitude": 153.0166,
    },
    {
        "prefix": "104.16.0.0/12",
        "asn": 13335,
        "asn_org": "Cloudflare, Inc.",
        "isp": "Cloudflare",
        "country": "United States",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.7749,
        "longitude": -122.4194,
    },
]


@lru_cache(maxsize=1)
def _load_networks() -> list[dict]:
    path = GEOIP_DIR / "local_networks.json"
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    return DEFAULT_NETWORKS


def enrich_telecom(ip: str, resolve_hostname: bool = False) -> dict:
    address = ipaddress.ip_address(ip)
    local_result = _local_network_result(address, resolve_hostname)
    if local_result:
        return local_result

    online_provider = OnlineIPInfoProvider()
    online_result = online_provider.lookup(ip)
    for network in _load_networks():
        if address in ipaddress.ip_network(network["prefix"]):
            local_result = {
                "isp": network["isp"],
                "asn": f"AS{network['asn']}",
                "asn_number": network["asn"],
                "asn_org": network["asn_org"],
                "network_prefix": network["prefix"],
                "country": network["country"],
                "region": network["region"],
                "city": network["city"],
                "latitude": network.get("latitude"),
                "longitude": network.get("longitude"),
                "hostname": _reverse_dns(ip) if resolve_hostname else "",
                "ip_source": "Local GeoIP",
            }
            return _merge_enrichment(local_result, online_result, resolve_hostname, ip)

    unknown_result = {
        "isp": "Unknown Provider",
        "asn": "AS0",
        "asn_number": 0,
        "asn_org": "Unknown Organization",
        "network_prefix": "Unknown",
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "latitude": None,
        "longitude": None,
        "hostname": _reverse_dns(ip) if resolve_hostname else "",
        "ip_source": "Local GeoIP",
    }
    return _merge_enrichment(unknown_result, online_result, resolve_hostname, ip)


def _local_network_result(address, resolve_hostname: bool) -> dict:
    if not (address.is_private or address.is_loopback or address.is_link_local):
        return {}

    if address.is_loopback:
        network_prefix = "127.0.0.0/8" if address.version == 4 else "::1/128"
        organization = "Loopback Interface"
    elif address.is_link_local:
        network_prefix = "169.254.0.0/16" if address.version == 4 else "fe80::/10"
        organization = "Link-Local Network"
    else:
        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("fc00::/7"),
        )
        network = next((item for item in private_networks if address in item), None)
        network_prefix = str(network) if network else "Private address space"
        organization = "Private LAN"

    return {
        "isp": "Local Network",
        "asn": "AS0",
        "asn_number": 0,
        "asn_org": organization,
        "network_prefix": network_prefix,
        "country": "Local",
        "region": "Private Network",
        "city": "LAN",
        "latitude": None,
        "longitude": None,
        "hostname": _reverse_dns(str(address)) if resolve_hostname else "",
        "ip_source": "Packet Capture",
    }


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _merge_enrichment(local_result: dict, online_result: dict, resolve_hostname: bool, ip: str) -> dict:
    if not online_result:
        return local_result

    merged = local_result.copy()
    for key, value in online_result.items():
        if value not in ("", None, 0, "AS0"):
            merged[key] = value

    if resolve_hostname and not merged.get("hostname"):
        merged["hostname"] = _reverse_dns(ip)
    return merged
