from dataclasses import dataclass, field
from typing import Literal

# NAT and attribution confidence definitions
AttributionConfidence = Literal["direct", "relay_only", "unresolved"]
NatTypeGuess = Literal["unknown", "symmetric", "full_cone", "restricted", "port_restricted"]
IceState = Literal["NEW", "GATHERING", "CHECKING", "CONNECTED", "COMPLETED", "FAILED", "RELAYED"]


@dataclass
class IceCandidate:
    ufrag: str
    candidate_type: str  # host | srflx | relay | prflx
    ip: str
    port: int
    priority: int
    foundation: str
    source_packet_ts: float


@dataclass
class EndpointIdentity:
    ufrag: str
    private_ip: str | None = None  # from 'host' candidate
    public_ip: str | None = None   # from 'srflx' XOR-MAPPED-ADDRESS
    relay_ip: str | None = None    # from 'relay' XOR-RELAYED-ADDRESS
    attribution_confidence: AttributionConfidence = "unresolved"
    nat_type_guess: NatTypeGuess = "unknown"


class IceStateMachine:
    """Tracks the state transitions of an ICE session."""

    def __init__(self):
        self.state: IceState = "NEW"

    def transition_to(self, new_state: IceState):
        valid_transitions = {
            "NEW": {"GATHERING", "FAILED"},
            "GATHERING": {"CHECKING", "FAILED"},
            "CHECKING": {"CONNECTED", "FAILED"},
            "CONNECTED": {"COMPLETED", "RELAYED", "FAILED"},
            "COMPLETED": {"CONNECTED", "FAILED"},
            "RELAYED": {"COMPLETED", "FAILED"},
            "FAILED": {"NEW"},
        }
        # Allow transition if defined or if resetting to NEW
        if new_state in valid_transitions.get(self.state, set()) or new_state == "NEW":
            self.state = new_state


def resolve_endpoint_identity(ufrag: str, candidates: list[IceCandidate]) -> EndpointIdentity:
    """Correlate all candidates matching a specific ufrag into a single EndpointIdentity."""
    identity = EndpointIdentity(ufrag=ufrag)

    # Walk all collected candidates to build up the IP profile
    for c in candidates:
        if c.candidate_type == "host":
            identity.private_ip = c.ip
        elif c.candidate_type == "srflx":
            identity.public_ip = c.ip
        elif c.candidate_type == "relay":
            identity.relay_ip = c.ip

    # Set attribution confidence
    if identity.public_ip:
        identity.attribution_confidence = "direct"
    elif identity.relay_ip:
        identity.attribution_confidence = "relay_only"
    else:
        identity.attribution_confidence = "unresolved"

    # Nat type guess
    if identity.private_ip and identity.public_ip:
        # If public IP matches private IP, no NAT (full open or direct)
        if identity.private_ip == identity.public_ip:
            identity.nat_type_guess = "full_cone"
        elif identity.relay_ip:
            # If a relay was required, it indicates more restrictive NAT environment
            identity.nat_type_guess = "symmetric"
        else:
            identity.nat_type_guess = "restricted"
    elif identity.relay_ip and not identity.public_ip:
        identity.nat_type_guess = "symmetric"

    return identity
