PORT_MAP = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    500: "IPSec/IKE",
    587: "SMTP Submission",
    853: "DNS over TLS",
    993: "IMAPS",
    1194: "OpenVPN",
    19302: "STUN",
    3478: "STUN/TURN",
    3479: "TURN",
    3480: "TURN",
    3481: "TURN",
    5004: "RTP",
    5005: "RTCP",
    5222: "XMPP Messaging",
    5223: "Apple/WhatsApp Push",
    5349: "TURN over TLS",
    7844: "QUIC/HTTP3",
    8443: "HTTPS Alternate",
}

VOIP_PORT_RANGES = [range(10000, 20001), range(49152, 65536)]
COMMON_PORTS = set(PORT_MAP) | {8080, 8888}


def port_intelligence(port: int | None, protocol: str) -> dict:
    if port is None:
        return {"name": "Port Unknown", "is_unusual": False, "notes": "Not observed in capture"}

    name = PORT_MAP.get(port)
    if not name and protocol.upper() == "UDP" and any(port in ports for ports in VOIP_PORT_RANGES):
        name = "RTP/RTCP Ephemeral Media"
    if not name:
        name = "Unregistered/Custom"

    unusual = port not in COMMON_PORTS and not any(port in ports for ports in VOIP_PORT_RANGES)
    return {
        "name": name,
        "is_unusual": unusual,
        "notes": "Review manually" if unusual else "Recognized service port",
    }
