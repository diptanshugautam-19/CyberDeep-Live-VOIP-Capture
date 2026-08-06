from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


@dataclass
class ConnectionRecord:
    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str = "UNKNOWN"
    timestamp: str | None = None
    packet_count: int = 1
    bytes_transferred: int = 0
    source_mac: str | None = None
    destination_mac: str | None = None
    tcp_flags: str | None = None
    dns_query: str | None = None
    payload_preview: str | None = None
    payload_hex: str | None = None
    payload_kind: str | None = None
    packet_details: list[dict] | None = None

    def to_dict(self) -> dict:
        row = asdict(self)
        if not row["timestamp"]:
            row["timestamp"] = datetime.now(timezone.utc).isoformat()
        return row


class ParserError(Exception):
    """Raised when evidence cannot be parsed."""


class EvidenceParser:
    supported_extensions: tuple[str, ...] = ()

    def can_parse(self, path: Path) -> bool:
        name = path.name.lower()
        return any(name.endswith(extension) for extension in self.supported_extensions)

    def parse(self, path: Path) -> Iterable[ConnectionRecord]:
        raise NotImplementedError
