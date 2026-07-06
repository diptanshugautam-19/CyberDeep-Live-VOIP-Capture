from dataclasses import dataclass, field
from .ice import EndpointIdentity, IceCandidate


@dataclass
class RtpStream:
    ssrc: int
    payload_type: int
    packets_count: int = 0
    bytes_count: int = 0
    jitter_history: list[float] = field(default_factory=list)
    seq_history: list[int] = field(default_factory=list)
    ts_history: list[int] = field(default_factory=list)
    arr_history: list[float] = field(default_factory=list)


@dataclass
class QosMetrics:
    jitter_ms: float = 0.0
    packet_loss_pct: float = 0.0
    mos_score: float = 4.5
    mos_label: str = "Excellent"


@dataclass
class VoipSession:
    call_id: str | None = None
    ufrag_key: str | None = None
    caller: EndpointIdentity = field(default_factory=lambda: EndpointIdentity(ufrag="caller"))
    callee: EndpointIdentity = field(default_factory=lambda: EndpointIdentity(ufrag="callee"))
    candidates: list[IceCandidate] = field(default_factory=list)
    turn_servers: list[str] = field(default_factory=list)  # Unique relay socket strings: IP:port
    media_streams: list[RtpStream] = field(default_factory=list)
    qos: QosMetrics = field(default_factory=QosMetrics)
    warnings: list[str] = field(default_factory=list)
    confidence_score: float = 100.0
    confidence_reasons: list[str] = field(default_factory=list)
    start_time: str | None = None
    end_time: str | None = None
    protocol: str = "VoIP"
