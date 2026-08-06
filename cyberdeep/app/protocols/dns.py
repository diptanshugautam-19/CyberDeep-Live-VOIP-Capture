"""
High-Precision DNS Protocol Decoder.
Parses DNS header flags (QR, Opcode, AA, TC, RD, RA, RCODE) and resource records
(A, AAAA, CNAME, MX, TXT, SRV, PTR, SVCB/HTTPS).
"""

import logging
from typing import Dict, List, Any, Optional
from scapy.layers.dns import DNS

logger = logging.getLogger(__name__)

# DNS Record Type Mapping
DNS_TYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    64: "SVCB",
    65: "HTTPS",
}

# RCODE Map
DNS_RCODE_MAP = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

def parse_dns_payload(payload_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses a raw payload as a DNS packet and extracts questions, answers, and header flags.
    """
    try:
        if not payload_bytes or len(payload_bytes) < 12:
            return None

        dns_pkt = DNS(payload_bytes)

        if dns_pkt.qdcount == 0 and dns_pkt.ancount == 0:
            return None

        # 1. Header Flags
        qr = bool(dns_pkt.qr)
        opcode = dns_pkt.opcode
        aa = bool(dns_pkt.aa)
        tc = bool(dns_pkt.tc)
        rd = bool(dns_pkt.rd)
        ra = bool(dns_pkt.ra)
        rcode_val = dns_pkt.rcode
        rcode_str = DNS_RCODE_MAP.get(rcode_val, f"RCODE_{rcode_val}")

        flags_summary = f"{'RESP' if qr else 'QUERY'} | {rcode_str}"

        queries: List[Dict[str, Any]] = []
        answers: List[Dict[str, Any]] = []

        # 2. Extract Questions
        if dns_pkt.qdcount > 0 and dns_pkt.qd:
            qd_layer = dns_pkt.qd
            while qd_layer:
                qname = qd_layer.qname.decode("utf-8", errors="ignore").rstrip(".") if getattr(qd_layer, "qname", None) else ""
                qtype_val = getattr(qd_layer, "qtype", 1)
                qtype_str = DNS_TYPE_MAP.get(qtype_val, f"TYPE_{qtype_val}")

                if qname:
                    queries.append({
                        "name": qname,
                        "type": qtype_str,
                        "type_id": qtype_val
                    })

                qd_layer = getattr(qd_layer, "payload", None)
                if not hasattr(qd_layer, "qtype"):
                    break

        # 3. Extract Answers (A, AAAA, CNAME, MX, TXT, SRV, PTR, HTTPS)
        if dns_pkt.ancount > 0 and dns_pkt.an:
            an_layer = dns_pkt.an
            while an_layer:
                atype_val = getattr(an_layer, "type", 1)
                atype_str = DNS_TYPE_MAP.get(atype_val, f"TYPE_{atype_val}")
                aname = an_layer.rrname.decode("utf-8", errors="ignore").rstrip(".") if getattr(an_layer, "rrname", None) else ""
                ttl = getattr(an_layer, "ttl", 0)

                rdata = getattr(an_layer, "rdata", "")
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("utf-8", errors="ignore")
                elif isinstance(rdata, list):
                    rdata = " ".join(x.decode("utf-8", errors="ignore") if isinstance(x, bytes) else str(x) for x in rdata)

                answers.append({
                    "name": aname,
                    "type": atype_str,
                    "ttl": ttl,
                    "data": str(rdata)
                })

                an_layer = getattr(an_layer, "payload", None)
                if not hasattr(an_layer, "type"):
                    break

        if not queries and not answers:
            return None

        return {
            "transaction_id": dns_pkt.id,
            "is_response": qr,
            "flags": {
                "qr": qr,
                "opcode": opcode,
                "aa": aa,
                "tc": tc,
                "rd": rd,
                "ra": ra,
                "rcode": rcode_str
            },
            "flags_summary": flags_summary,
            "queries": queries,
            "answers": answers
        }

    except Exception as e:
        logger.debug(f"DNS parsing error: {e}")
        return None
