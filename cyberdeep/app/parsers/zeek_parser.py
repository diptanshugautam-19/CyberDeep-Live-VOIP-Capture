from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from app.parsers.base import ConnectionRecord, EvidenceParser, ParserError


class ZeekConnLogParser(EvidenceParser):
    supported_extensions = (".log", ".txt")

    def parse(self, path: Path) -> Iterable[ConnectionRecord]:
        fields = []
        records = []
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if not fields or not line or line.startswith("#"):
                    continue
                values = line.split("\t")
                if len(values) != len(fields):
                    continue
                row = dict(zip(fields, values))
                if "id.orig_h" not in row or "id.resp_h" not in row:
                    continue
                records.append(
                    ConnectionRecord(
                        source_ip=row["id.orig_h"],
                        destination_ip=row["id.resp_h"],
                        source_port=_to_int(row.get("id.orig_p")),
                        destination_port=_to_int(row.get("id.resp_p")),
                        protocol=(row.get("proto") or "UNKNOWN").upper(),
                        timestamp=_ts(row.get("ts")),
                        packet_count=_to_int(row.get("orig_pkts")) or 1,
                        bytes_transferred=(_to_int(row.get("orig_bytes")) or 0) + (_to_int(row.get("resp_bytes")) or 0),
                    )
                )
        if not records:
            raise ParserError("No Zeek conn.log records found.")
        return records


def _to_int(value: str | None) -> int | None:
    if not value or value == "-":
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def _ts(value: str | None) -> str | None:
    if not value or value == "-":
        return None
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    except ValueError:
        return value
