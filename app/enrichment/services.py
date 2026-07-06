import ipaddress


SERVICE_RULES = [
    {
        "service": "WhatsApp/Facebook Infrastructure",
        "category": "WhatsApp",
        "asn_numbers": {32934},
        "prefixes": ["157.240.0.0/16", "31.13.64.0/18"],
        "ports": {443, 5222, 5223, 5228, 5229, 5230, 3478, 3479, 3480, 3481},
    },
    {
        "service": "Telegram Messaging",
        "category": "Telegram",
        "asn_numbers": {62041},
        "prefixes": ["149.154.160.0/20", "91.108.4.0/22"],
        "ports": {80, 443, 5222},
    },
    {
        "service": "Signal Messaging",
        "category": "Signal",
        "asn_numbers": {16509, 14618},
        "prefixes": ["13.224.0.0/14"],
        "ports": {443, 31337},
    },
    {
        "service": "Google Infrastructure",
        "category": "Google Infrastructure",
        "asn_numbers": {15169},
        "prefixes": ["8.8.8.0/24", "142.250.0.0/15", "142.251.0.0/16", "172.217.0.0/16", "64.233.160.0/19"],
        "ports": {53, 80, 443, 853, 7844},
    },
    {
        "service": "Google Meet / Google Services",
        "category": "Google Meet",
        "asn_numbers": {15169},
        "prefixes": ["35.190.0.0/17", "64.233.160.0/19"],
        "ports": {443, 19302, 19305, 3478, 5349},
    },
    {
        "service": "Microsoft Teams / Azure",
        "category": "Microsoft Teams",
        "asn_numbers": {8075},
        "prefixes": ["52.96.0.0/14"],
        "ports": {443, 3478, 3479, 3480, 3481},
    },
    {
        "service": "Cloudflare Edge",
        "category": "Cloudflare",
        "asn_numbers": {13335},
        "prefixes": ["1.1.1.0/24", "162.159.0.0/16", "104.16.0.0/12"],
        "ports": {53, 80, 443, 853, 7844},
    },
    {
        "service": "Amazon Web Services",
        "category": "AWS",
        "asn_numbers": {16509, 14618},
        "prefixes": ["13.224.0.0/14"],
        "ports": {80, 443, 5000, 8443},
    },
]


def identify_service(ip: str, asn_number: int, destination_port: int | None, asn_org: str) -> dict:
    best = {
        "service": "Unclassified Internet Service",
        "category": "Unknown",
        "confidence": 25,
        "matched_asn": False,
        "matched_prefix": "",
        "matched_port": False,
        "service_match_reasons": ["No high-confidence ASN, prefix, or port rule matched"],
    }
    address = ipaddress.ip_address(ip)

    for rule in SERVICE_RULES:
        confidence = 0
        reasons = []
        matched_prefix = ""
        if asn_number in rule["asn_numbers"]:
            confidence += 45
            reasons.append(f"Matched ASN: AS{asn_number}")
        for prefix in rule["prefixes"]:
            if address in ipaddress.ip_network(prefix):
                matched_prefix = prefix
                break
        if matched_prefix:
            confidence += 35
            reasons.append(f"Matched IP Range: {rule['category']} ({matched_prefix})")
        if destination_port in rule["ports"]:
            confidence += 15
            reasons.append(f"Port: {destination_port}")
        if rule["category"].lower().split()[0] in asn_org.lower():
            confidence += 10
            reasons.append(f"Matched Organization: {asn_org}")
        if confidence > best["confidence"]:
            best = {
                "service": rule["service"],
                "category": rule["category"],
                "confidence": min(confidence, 98),
                "matched_asn": asn_number in rule["asn_numbers"],
                "matched_prefix": matched_prefix,
                "matched_port": destination_port in rule["ports"],
                "service_match_reasons": reasons,
            }

    return best
