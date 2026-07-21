"""
ICE data models, state machine, and IP extraction engine.
Integrates Production WebRTC Capture Engine v3 dataclasses and enums.
"""

import socket
import struct
import ipaddress
import hashlib
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Union, Literal

# ---------------------------------------------------------------------------
# Type aliases kept for backward compatibility
# ---------------------------------------------------------------------------
AttributionConfidence = Literal["direct", "relay_only", "unresolved"]
NatTypeGuess = Literal["unknown", "symmetric", "full_cone", "restricted", "port_restricted"]
IceStateStr = Literal["NEW", "GATHERING", "CHECKING", "CONNECTED", "COMPLETED", "FAILED", "RELAYED"]


# ---------------------------------------------------------------------------
# Enums (from Production WebRTC Capture Engine v3)
# ---------------------------------------------------------------------------
from enum import Enum, auto


class ICEState(Enum):
    """Full ICE lifecycle states per RFC 8445."""
    GATHERING = auto()
    CHECKING = auto()
    CONNECTED = auto()
    COMPLETED = auto()
    FAILED = auto()


class CandidateType(Enum):
    """ICE candidate type labels."""
    HOST = "host"
    SRFLX = "srflx"
    PRFLX = "prflx"
    RELAY = "relay"


# ---------------------------------------------------------------------------
# Dataclasses (from Production WebRTC Capture Engine v3)
# ---------------------------------------------------------------------------

@dataclass
class ICECandidate:
    """Full ICE candidate parsed from SDP a=candidate line or learned via STUN."""
    foundation: str
    component: int
    transport: str          # "UDP" or "TCP"
    priority: int
    ip: str
    port: int
    candidate_type: str     # host | srflx | prflx | relay
    related_addr: Optional[str] = None
    related_port: Optional[int] = None
    ip_version: int = 4


@dataclass
class ICECheck:
    """A candidate pair connectivity check (RFC 8445 §6.1.4)."""
    local_candidate: ICECandidate
    remote_candidate: ICECandidate
    nominated: bool = False          # True when USE-CANDIDATE was seen
    succeeded: bool = False          # True when binding response received
    use_candidate_seen: bool = False  # Raw flag from STUN attribute


@dataclass
class TURNAllocation:
    """A TURN relay allocation tracking real client ↔ relay IP mapping."""
    relay_addr: str
    relay_port: int
    client_addr: str
    client_port: int
    lifetime: int
    realm: Optional[str] = None
    nonce: Optional[str] = None
    # channel_number -> (peer_ip, peer_port)
    channels: Dict[int, Tuple[str, int]] = field(default_factory=dict)


@dataclass
class ExtractedIP:
    """A de-duplicated IP observation with attribution metadata."""
    source: str                         # Parser that produced this (e.g. 'ice_candidate_srflx')
    ip: str
    port: Optional[int]
    ip_version: Union[int, str]         # 4 or 6
    timestamp: str                      # ISO-8601
    context: str                        # Human-readable description
    confidence: str                     # 'high' | 'medium' | 'low'
    session_id: Optional[str] = None
    stream_id: Optional[str] = None
    is_nominated: bool = False          # Was this the selected ICE candidate pair?


# ---------------------------------------------------------------------------
# Legacy EndpointIdentity kept for voip_manager.py backward compatibility
# ---------------------------------------------------------------------------

@dataclass
class IceCandidate:
    """Legacy candidate model (kept for attribution engine compatibility)."""
    ufrag: str
    candidate_type: str   # host | srflx | relay | prflx
    ip: str
    port: int
    priority: int
    foundation: str
    source_packet_ts: float


@dataclass
class EndpointIdentity:
    """Resolved endpoint profile built from all ICE candidates for a ufrag."""
    ufrag: str
    private_ip: Optional[str] = None   # from 'host' candidate
    public_ip: Optional[str] = None    # from 'srflx' XOR-MAPPED-ADDRESS
    relay_ip: Optional[str] = None     # from 'relay' XOR-RELAYED-ADDRESS
    attribution_confidence: AttributionConfidence = "unresolved"
    nat_type_guess: NatTypeGuess = "unknown"
    ip: Optional[str] = None
    port: Optional[int] = None


# ---------------------------------------------------------------------------
# ICE State Machine (enhanced with nomination tracking)
# ---------------------------------------------------------------------------

class IceStateMachine:
    """
    Tracks ICE session state transitions per RFC 8445.
    Now includes nominated pair tracking from Production WebRTC Capture Engine v3.
    """

    def __init__(self):
        self.state: IceStateStr = "NEW"
        self.ice_state: ICEState = ICEState.GATHERING

        # All checks collected during the session
        self.checks: List[ICECheck] = []

        # The winning pair after USE-CANDIDATE + successful response
        self.nominated_pair: Optional[ICECheck] = None

        # Whether this endpoint is the ICE controlling agent
        self.is_controlling: bool = False

        # Session ufrag for logging
        self.ufrag: Optional[str] = None

    def transition_to(self, new_state: IceStateStr):
        """Advance legacy string-based state (kept for DB persistence compat)."""
        valid_transitions = {
            "NEW":       {"GATHERING", "FAILED"},
            "GATHERING": {"CHECKING", "FAILED"},
            "CHECKING":  {"CONNECTED", "FAILED"},
            "CONNECTED": {"COMPLETED", "RELAYED", "FAILED"},
            "COMPLETED": {"CONNECTED", "FAILED"},
            "RELAYED":   {"COMPLETED", "FAILED"},
            "FAILED":    {"NEW"},
        }
        if new_state in valid_transitions.get(self.state, set()) or new_state == "NEW":
            self.state = new_state

    def on_binding_request(self, check: ICECheck):
        """
        Process an incoming STUN Binding Request.
        If USE-CANDIDATE is set, mark check as nominated and advance to CHECKING.
        """
        self.checks.append(check)
        if check.use_candidate_seen:
            self.ice_state = ICEState.CHECKING
            self.transition_to("CHECKING")

    def on_binding_response(self, check: ICECheck):
        """
        Mark check as succeeded. If this check was nominated, transition to COMPLETED.
        """
        check.succeeded = True
        if check.nominated and self.nominated_pair is None:
            self.nominated_pair = check
            self.ice_state = ICEState.COMPLETED
            self.transition_to("COMPLETED")
        elif self.state == "CHECKING":
            self.ice_state = ICEState.CONNECTED
            self.transition_to("CONNECTED")

    @property
    def nomination_confirmed(self) -> bool:
        return self.nominated_pair is not None


# ---------------------------------------------------------------------------
# IP Extraction Helper (from ProductionWebRTCCaptureEngine._add_ip)
# ---------------------------------------------------------------------------

class IPExtractionStore:
    """
    Central de-duplicated store of all IPs observed in WebRTC sessions.
    Mirrors the _add_ip / seen_ips logic from ProductionWebRTCCaptureEngine.
    """

    # Source-to-output category mapping (mirrors print_report categories)
    CATEGORIES = {
        "SIP Via":  ["sip_via"],
        "Contact":  ["sip_contact"],
        "SDP IP":   ["sdp_c_line", "sdp_origin"],
        "SRFLX":    [
            "ice_candidate_srflx", "ice_candidate_prflx",
            "ice_binding_response", "turn_xor_mapped_client", "turn_client_real"
        ],
        "RTP":      ["rtp_udp", "rtp_over_tcp", "rtp_validated"],
    }

    def __init__(self, filter_private: bool = False):
        self.filter_private = filter_private
        self.extracted_ips: List[ExtractedIP] = []
        self.seen_ips: Set[str] = set()

    def add_ip(self, source: str, ip: str, port: Optional[int],
               ip_version: int, context: str, confidence: str,
               session_id: Optional[str] = None,
               is_nominated: bool = False) -> bool:
        """
        Add an observed IP with de-duplication by (ip, port, source, session_id).
        Returns True if the entry was newly added, False if duplicate.
        """
        if self.filter_private:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    return False
            except ValueError:
                pass

        ip_key = f"{ip}:{port}:{source}:{session_id}"
        if ip_key in self.seen_ips:
            return False

        self.seen_ips.add(ip_key)
        self.extracted_ips.append(ExtractedIP(
            source=source,
            ip=ip,
            port=port,
            ip_version=ip_version,
            timestamp=datetime.now().isoformat(),
            context=context,
            confidence=confidence,
            session_id=session_id,
            is_nominated=is_nominated
        ))
        return True

    def get_by_category(self) -> Dict[str, Optional[str]]:
        """
        Returns first IP seen for each output category, mirroring print_report().
        """
        found: Dict[str, Optional[str]] = {}
        for ip_obj in self.extracted_ips:
            for label, sources in self.CATEGORIES.items():
                if ip_obj.source in sources and label not in found:
                    found[label] = ip_obj.ip
        return found

    def get_nominated_ips(self) -> List[ExtractedIP]:
        """Return only IPs from nominated candidate pairs."""
        return [e for e in self.extracted_ips if e.is_nominated]


# ---------------------------------------------------------------------------
# Candidate priority lookup helper (from _find_candidate_by_priority)
# ---------------------------------------------------------------------------

def find_candidate_by_priority(
    candidates: Dict[str, ICECandidate],
    priority_bytes: bytes
) -> Optional[ICECandidate]:
    """
    Find a local ICECandidate whose priority matches the STUN PRIORITY attribute bytes.
    Mirrors ProductionWebRTCCaptureEngine._find_candidate_by_priority().
    """
    try:
        pri_val = struct.unpack('!I', priority_bytes[:4])[0] if len(priority_bytes) >= 4 else 0
        for cand in candidates.values():
            if cand.priority == pri_val:
                return cand
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Endpoint resolution (existing logic, unchanged)
# ---------------------------------------------------------------------------

def resolve_endpoint_identity(ufrag: str, candidates: list) -> EndpointIdentity:
    """Correlate all candidates matching a specific ufrag into a single EndpointIdentity."""
    identity = EndpointIdentity(ufrag=ufrag)

    for c in candidates:
        if c.candidate_type == "host":
            identity.private_ip = c.ip
        elif c.candidate_type == "srflx":
            identity.public_ip = c.ip
        elif c.candidate_type == "relay":
            identity.relay_ip = c.ip

    if identity.public_ip:
        identity.attribution_confidence = "direct"
    elif identity.relay_ip:
        identity.attribution_confidence = "relay_only"
    else:
        identity.attribution_confidence = "unresolved"

    if identity.private_ip and identity.public_ip:
        if identity.private_ip == identity.public_ip:
            identity.nat_type_guess = "full_cone"
        elif identity.relay_ip:
            identity.nat_type_guess = "symmetric"
        else:
            identity.nat_type_guess = "restricted"
    elif identity.relay_ip and not identity.public_ip:
        identity.nat_type_guess = "symmetric"

    return identity
