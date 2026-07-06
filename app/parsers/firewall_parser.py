import re
from pathlib import Path
from typing import Iterable

from app.parsers.base import ConnectionRecord, EvidenceParser


KEY_VALUE_PATTERN = re.compile(r"(?P<key>src|dst|spt|dpt|proto|bytes|packets|time)=?(?P<value>[^\s,]+)", re.I)
IP_PAIR_PATTERN = re.compile(
    r"(?P<src>\b(?:\d{1,3}\.){3}\d{1,3}\b).*?(?P<dst>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
)


class FirewallLogParser(EvidenceParser):
    supported_extensions = (".log", ".txt")

    def parse(self, path: Path) -> Iterable[ConnectionRecord]:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                values = {m.group("key").lower(): m.group("value") for m in KEY_VALUE_PATTERN.finditer(line)}
                if "src" in values and "dst" in values:
                    yield ConnectionRecord(
                        source_ip=values["src"],
                        destination_ip=values["dst"],
                        source_port=_to_int(values.get("spt")),
                        destination_port=_to_int(values.get("dpt")),
                        protocol=(values.get("proto") or "UNKNOWN").upper(),
                        timestamp=values.get("time"),
                        packet_count=_to_int(values.get("packets")) or 1,
                        bytes_transferred=_to_int(values.get("bytes")) or 0,
                    )
                    continue

                match = IP_PAIR_PATTERN.search(line)
                if match:
                    yield ConnectionRecord(
                        source_ip=match.group("src"),
                        destination_ip=match.group("dst"),
                    )


def _to_int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None
