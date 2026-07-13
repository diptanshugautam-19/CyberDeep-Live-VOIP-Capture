from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class Packet(BaseModel):
    id: str
    index: int
    timestamp: float
    source_ip: str
    dest_ip: str
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: str
    length: int
    summary: str
    raw_hex: Optional[str] = None
    layers: Dict[str, Any] = Field(default_factory=dict)

class Endpoint(BaseModel):
    ip: str
    port: int
    protocol: str
    packets_sent: int
    packets_received: int
    bytes_sent: int
    bytes_received: int

class Conversation(BaseModel):
    id: str
    endpoint_a: str
    endpoint_b: str
    protocol: str
    packets: int
    bytes: int
    duration: float

class SIPCall(BaseModel):
    call_id: str
    caller: str
    callee: str
    status: str
    start_time: float
    end_time: Optional[float] = None
    packets_count: int
    sdp_media_ports: List[int] = Field(default_factory=list)

class RTPSession(BaseModel):
    ssrc: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    packet_count: int
    expected_packets: Optional[int] = None
    lost_packets: int = 0
    jitter: float = 0.0
    mos: float = 4.5
    duration: float

class ICESession(BaseModel):
    session_id: str
    caller_ufrag: str
    callee_ufrag: str
    state: str
    candidates: List[Dict[str, Any]] = Field(default_factory=list)

class TURNAllocation(BaseModel):
    allocation_id: str
    client_ip: str
    client_port: int
    relay_ip: str
    relay_port: int
    peer_ip: Optional[str] = None
    peer_port: Optional[int] = None
    lifetime: int

class STUNTransaction(BaseModel):
    transaction_id: str
    method: str
    class_type: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    result: str

class DNSQuery(BaseModel):
    name: str
    query_type: str
    response_code: str
    resolved_ips: List[str] = Field(default_factory=list)

class TLSHandshake(BaseModel):
    session_id: str
    sni: Optional[str] = None
    cipher_suite: Optional[str] = None
    version: str

class GeoEndpoint(BaseModel):
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

class InvestigationSession(BaseModel):
    session_id: str
    sip_calls: List[SIPCall] = Field(default_factory=list)
    rtp_sessions: List[RTPSession] = Field(default_factory=list)
    ice_sessions: List[ICESession] = Field(default_factory=list)
    stun_transactions: List[STUNTransaction] = Field(default_factory=list)
    turn_allocations: List[TURNAllocation] = Field(default_factory=list)
    dns_queries: List[DNSQuery] = Field(default_factory=list)
    tls_handshakes: List[TLSHandshake] = Field(default_factory=list)
    endpoints: List[Endpoint] = Field(default_factory=list)
    conversations: List[Conversation] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
