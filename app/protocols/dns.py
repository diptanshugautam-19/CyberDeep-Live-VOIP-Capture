import logging
from scapy.layers.dns import DNS

logger = logging.getLogger(__name__)

def parse_dns_payload(payload_bytes: bytes) -> dict | None:
    """
    Port-independent DNS parser using Scapy's DNS layer.
    Extracts query and A/AAAA answers to associate IPs with server hostnames.
    """
    try:
        # Avoid parsing extremely short payloads
        if len(payload_bytes) < 12:
            return None

        dns_pkt = DNS(payload_bytes)
        
        # Scapy might successfully load non-DNS packets; verify basic counts
        if dns_pkt.qdcount == 0 and dns_pkt.ancount == 0:
            return None

        queries = []
        answers = []

        # 1. Extract Queries
        if dns_pkt.qdcount > 0:
            # Handle both single items and list layer structures from Scapy
            qd_layer = dns_pkt.qd
            while qd_layer:
                qname = qd_layer.qname.decode("utf-8", errors="ignore").rstrip(".") if qd_layer.qname else ""
                qtype_val = qd_layer.qtype
                qtype_map = {1: "A", 28: "AAAA", 33: "SRV", 35: "NAPTR"}
                qtype = qtype_map.get(qtype_val, f"TYPE_{qtype_val}")
                
                queries.append({
                    "name": qname,
                    "type": qtype
                })
                # Check for additional stacked questions (rare but possible in standard DNS)
                qd_layer = qd_layer.payload if hasattr(qd_layer, "payload") and isinstance(qd_layer.payload, DNS) else None

        # 2. Extract Answers (A / AAAA records only)
        if dns_pkt.ancount > 0:
            an_layer = dns_pkt.an
            while an_layer:
                # We check the record type to extract host mapping
                atype_val = an_layer.type
                atype_map = {1: "A", 28: "AAAA", 33: "SRV", 35: "NAPTR"}
                atype = atype_map.get(atype_val, f"TYPE_{atype_val}")
                
                # Only keep A and AAAA mappings for mapping IP back to domain names
                if atype in ("A", "AAAA"):
                    aname = an_layer.rrname.decode("utf-8", errors="ignore").rstrip(".") if an_layer.rrname else ""
                    rdata = getattr(an_layer, "rdata", "")
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode("utf-8", errors="ignore")
                    
                    answers.append({
                        "name": aname,
                        "type": atype,
                        "ttl": getattr(an_layer, "ttl", 0),
                        "data": str(rdata)
                    })
                
                # Iterate through stacked answers in Scapy
                an_layer = an_layer.payload if hasattr(an_layer, "payload") and getattr(an_layer.payload, "type", None) is not None else None

        if not queries and not answers:
            return None

        return {
            "transaction_id": dns_pkt.id,
            "queries": queries,
            "answers": answers
        }
    except Exception:
        return None
