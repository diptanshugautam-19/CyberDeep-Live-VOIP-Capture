import os
import yaml
import re
import ipaddress
import logging
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set

logger = logging.getLogger(__name__)

class EndpointRole(Enum):
    # TIER 1 - CAPTURE-INTERNAL (never a participant, never enriched)
    VPN_INTERFACE = "VPN_INTERFACE"
    LOCAL_DEVICE = "LOCAL_DEVICE"

    # TIER 2 - INFRASTRUCTURE (network-visible, but not a call party)
    PRIVATE_NETWORK = "PRIVATE_NETWORK"
    PUBLIC_NAT = "PUBLIC_NAT"
    STUN_SERVER = "STUN_SERVER"
    TURN_SERVER = "TURN_SERVER"
    MEDIA_RELAY = "MEDIA_RELAY"
    DNS_SERVER = "DNS_SERVER"
    SIP_SERVER = "SIP_SERVER"
    ICE_CANDIDATE = "ICE_CANDIDATE"

    # TIER 3 - CALL-BEARING (eligible for participant reconstruction)
    RTP_ENDPOINT = "RTP_ENDPOINT"
    RTCP_ENDPOINT = "RTCP_ENDPOINT"
    REMOTE_PARTICIPANT = "REMOTE_PARTICIPANT"
    WEB_SERVER = "WEB_SERVER"

    # UNRESOLVED
    UNKNOWN = "UNKNOWN"


ROLE_TIERS = {
    EndpointRole.VPN_INTERFACE: 1,
    EndpointRole.LOCAL_DEVICE: 1,

    EndpointRole.PRIVATE_NETWORK: 2,
    EndpointRole.PUBLIC_NAT: 2,
    EndpointRole.STUN_SERVER: 2,
    EndpointRole.TURN_SERVER: 2,
    EndpointRole.MEDIA_RELAY: 2,
    EndpointRole.DNS_SERVER: 2,
    EndpointRole.SIP_SERVER: 2,
    EndpointRole.ICE_CANDIDATE: 2,

    EndpointRole.RTP_ENDPOINT: 3,
    EndpointRole.RTCP_ENDPOINT: 3,
    EndpointRole.REMOTE_PARTICIPANT: 3,
    EndpointRole.WEB_SERVER: 3,

    EndpointRole.UNKNOWN: 4,  # Unresolved / excluded
}


def is_rfc1918(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_link_local:
            return True
        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("fc00::/7"),
        )
        return any(addr in net for net in private_networks)
    except Exception:
        return False


class DetectionResult:
    def __init__(self, signature_id: str, role: EndpointRole, confidence: float, evidence: List[str], paired_address: Optional[str] = None):
        self.signature_id = signature_id
        self.role = role
        self.confidence = confidence
        self.evidence = evidence
        self.paired_address = paired_address


class WeightedCondition:
    def __init__(self, cond_dict: Dict[str, Any]):
        self.id = cond_dict.get("id")
        self.weight = float(cond_dict.get("weight", 0.0))
        self.test = cond_dict.get("test")
        self.threshold = cond_dict.get("threshold")


class InterfaceSignature:
    def __init__(self, config_path: Path):
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.id = data.get("id")
        self.display_name = data.get("display_name")
        self.role_on_match = EndpointRole(data.get("role_on_match", "UNKNOWN"))
        self.icon = data.get("icon", "network")
        self.color = data.get("color", "#7A7F8C")
        self.capture_source_hints = data.get("capture_source_hints", [])
        self.address_spaces = data.get("address_spaces", [])
        self.conditions = [WeightedCondition(c) for c in data.get("conditions", [])]

    def score(self, ip: str, all_records: List[Dict[str, Any]], filename: str = "") -> DetectionResult:
        # Fast-fail: VPN interfaces must be private/RFC1918 IPs
        if self.role_on_match == EndpointRole.VPN_INTERFACE and not is_rfc1918(ip):
            return DetectionResult(self.id, self.role_on_match, 0.0, [], None)

        # Dynamic address space constraint check:
        # If the interface signature specifies allowed address spaces, the target IP must belong to one of them.
        if self.address_spaces:
            matched_space = False
            try:
                addr = ipaddress.ip_address(ip)
                for space in self.address_spaces:
                    if addr in ipaddress.ip_network(space):
                        matched_space = True
                        break
            except Exception:
                pass
            if not matched_space:
                return DetectionResult(self.id, self.role_on_match, 0.0, [], None)

        # Find potential peer IP that forms a pair with the target IP
        # We look for the peer IP (must be RFC1918) that shares the most traffic with the target IP
        traffic_by_peer = {}
        for r in all_records:
            src = r.get("source_ip")
            dst = r.get("destination_ip")
            pkts = int(r.get("packet_count") or 1)
            if src == ip and dst and is_rfc1918(dst):
                traffic_by_peer[dst] = traffic_by_peer.get(dst, 0) + pkts
            elif dst == ip and src and is_rfc1918(src):
                traffic_by_peer[src] = traffic_by_peer.get(src, 0) + pkts
        
        paired_address = None
        if traffic_by_peer:
            paired_address = max(traffic_by_peer, key=traffic_by_peer.get)

        evidence = []
        total_score = 0.0

        for cond in self.conditions:
            cond_score = 0.0
            cond_evidence = ""

            if cond.test == "both_endpoints_rfc1918":
                if is_rfc1918(ip) and paired_address and is_rfc1918(paired_address):
                    cond_score = 1.0
                    cond_evidence = "RFC1918 address pair"

            elif cond.test == "traffic_concentration_between_pair":
                if paired_address:
                    # Sum only private-to-private traffic
                    total_pkts = sum(
                        int(r.get("packet_count") or 1) for r in all_records
                        if is_rfc1918(r.get("source_ip")) and is_rfc1918(r.get("destination_ip"))
                    )
                    pair_pkts = sum(
                        int(r.get("packet_count") or 1) for r in all_records
                        if (r.get("source_ip") == ip and r.get("destination_ip") == paired_address)
                        or (r.get("source_ip") == paired_address and r.get("destination_ip") == ip)
                    )
                    ratio = (pair_pkts / total_pkts) if total_pkts > 0 else 0.0
                    thresh = float(cond.threshold or 0.95)
                    if ratio >= thresh:
                        cond_score = 1.0
                        cond_evidence = f"Observed in dominant traffic pair ({ratio:.1%} of private session traffic)"
                    elif ratio > 0.5:
                        cond_score = ratio
                        cond_evidence = f"Observed in highly concentrated traffic pair ({ratio:.1%} of private session traffic)"

            elif cond.test == "dns_queries_only_between_pair":
                dns_records = [r for r in all_records if str(r.get("protocol") or "").upper() == "DNS" or r.get("destination_port") == 53]
                if dns_records:
                    contained = True
                    for r in dns_records:
                        src, dst = r.get("source_ip"), r.get("destination_ip")
                        if paired_address:
                            if src not in (ip, paired_address) or dst not in (ip, paired_address):
                                contained = False
                                break
                        else:
                            contained = False
                            break
                    if contained:
                        cond_score = 1.0
                        cond_evidence = "DNS queries strictly contained to pair"
                else:
                    # If no DNS records exist, we shouldn't fail the check completely if it is typical
                    cond_score = 0.5
                    cond_evidence = "No DNS queries observed"

            elif cond.test == "stun_turn_source_is_pair":
                stun_records = [r for r in all_records if str(r.get("protocol") or "").upper() in ("STUN", "TURN")]
                if stun_records:
                    is_pair = True
                    for r in stun_records:
                        src, dst = r.get("source_ip"), r.get("destination_ip")
                        # Must originate or terminate on the pair
                        if ip not in (src, dst) and (not paired_address or paired_address not in (src, dst)):
                            is_pair = False
                            break
                    if is_pair:
                        cond_score = 1.0
                        cond_evidence = "STUN/TURN traffic originates or terminates on the pair"
                else:
                    cond_score = 0.5
                    cond_evidence = "No STUN/TURN traffic observed"

            elif cond.test == "no_arp_no_mac_no_route_advertisement":
                arp_exists = any(str(r.get("protocol") or "").upper() == "ARP" for r in all_records)
                macs_exist = any(
                    (r.get("source_mac") and r.get("source_mac") != "00:00:00:00:00:00")
                    or (r.get("destination_mac") and r.get("destination_mac") != "00:00:00:00:00:00")
                    for r in all_records
                )
                if not arp_exists and not macs_exist:
                    cond_score = 1.0
                    cond_evidence = "No ARP or link layer evidence (virtual interface signature)"

            elif cond.test == "capture_metadata_matches_hints":
                matched = False
                for hint in self.capture_source_hints:
                    if filename and hint.lower() in filename.lower():
                        matched = True
                        break
                if not matched:
                    # Fallback to checking data/uploads directory files
                    upload_dir = Path("data/uploads")
                    if upload_dir.exists():
                        for f in upload_dir.glob("*"):
                            for hint in self.capture_source_hints:
                                if hint.lower() in f.name.lower():
                                    matched = True
                                    break
                            if matched:
                                break
                if matched:
                    cond_score = 1.0
                    cond_evidence = "Capture source metadata matches hints"

            total_score += cond.weight * cond_score
            if cond_score > 0.0 and cond_evidence:
                evidence.append(cond_evidence)

        # Capped confidence model: limit to 99%
        confidence = min(0.99, total_score)
        return DetectionResult(
            signature_id=self.id,
            role=self.role_on_match,
            confidence=confidence,
            evidence=evidence,
            paired_address=paired_address
        )


class ClassificationEngine:
    def __init__(self, registry_dir: Path):
        self.registry: List[InterfaceSignature] = []
        if registry_dir.exists():
            for f in registry_dir.glob("*.yaml"):
                try:
                    self.registry.append(InterfaceSignature(f))
                except Exception as e:
                    logger.error(f"Failed to load signature {f}: {e}")

    def classify(self, ip: str, all_records: List[Dict[str, Any]], filename: str = "") -> Tuple[EndpointRole, float, str, Optional[str], List[str]]:
        results = [sig.score(ip, all_records, filename) for sig in self.registry]
        best = max(results, key=lambda r: r.confidence, default=None)
        
        # Confidence bands check
        if best is None or best.confidence < 0.50:
            # Fall back to checking standard roles
            if is_rfc1918(ip):
                return EndpointRole.PRIVATE_NETWORK, 0.90, "", None, ["RFC1918 Private Range"]
            else:
                return EndpointRole.REMOTE_PARTICIPANT, 0.90, "", None, ["Public IP Endpoint"]
        
        return best.role, best.confidence, best.signature_id, best.paired_address, best.evidence
