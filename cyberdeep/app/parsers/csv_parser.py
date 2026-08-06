from pathlib import Path
from typing import Iterable

import pandas as pd

from app.parsers.base import ConnectionRecord, EvidenceParser, ParserError


COLUMN_ALIASES = {
    "source_ip": ["source_ip", "src_ip", "src", "ip.src", "source", "source address"],
    "destination_ip": ["destination_ip", "dst_ip", "dest_ip", "dst", "ip.dst", "destination", "destination address"],
    "source_port": ["source_port", "src_port", "tcp.srcport", "udp.srcport", "sport", "source port"],
    "destination_port": ["destination_port", "dst_port", "dest_port", "tcp.dstport", "udp.dstport", "dport", "destination port"],
    "protocol": ["protocol", "_ws.col.protocol", "proto", "ip.proto"],
    "timestamp": ["timestamp", "time", "_ws.col.time", "frame.time", "first_seen", "start_time"],
    "packet_count": ["packet_count", "packets", "packet", "pkts", "frames"],
    "bytes_transferred": ["bytes_transferred", "bytes", "octets", "length", "frame.len"],
    "source_mac": ["source_mac", "src_mac", "eth.src"],
    "destination_mac": ["destination_mac", "dst_mac", "eth.dst"],
    "tcp_flags": ["tcp_flags", "flags", "tcp.flags"],
    "dns_query": ["dns_query", "query", "qname"],
    "payload_preview": ["payload_preview", "payload", "preview"],
    "payload_hex": ["payload_hex", "hex"],
    "payload_kind": ["payload_kind", "kind"],
}


def _column_lookup(columns: list[str]) -> dict[str, str]:
    normalized = {column.strip().lower(): column for column in columns}
    result: dict[str, str] = {}
    for canonical, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in normalized:
                result[canonical] = normalized[alias]
                break
    return result


def _safe_int(value) -> int | None:
    if pd.isna(value) or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


class CsvConnectionParser(EvidenceParser):
    supported_extensions = (".csv", ".tsv")

    def parse(self, path: Path) -> Iterable[ConnectionRecord]:
        try:
            sep = "\t" if path.suffix.lower() == ".tsv" else None
            frame = pd.read_csv(path, sep=sep, engine="python")
        except Exception as exc:  # pragma: no cover - pandas provides the detail
            raise ParserError(f"Unable to read CSV evidence: {exc}") from exc

        lookup = _column_lookup(list(frame.columns))
        if "source_ip" not in lookup or "destination_ip" not in lookup:
            raise ParserError("CSV must include recognizable source and destination IP columns.")

        for _, row in frame.iterrows():
            src = str(row.get(lookup["source_ip"], "")).strip()
            dst = str(row.get(lookup["destination_ip"], "")).strip()
            if not src or not dst or src.lower() == "nan" or dst.lower() == "nan":
                continue

            yield ConnectionRecord(
                source_ip=src,
                destination_ip=dst,
                source_port=_safe_int(row.get(lookup.get("source_port", ""))),
                destination_port=_safe_int(row.get(lookup.get("destination_port", ""))),
                protocol=str(row.get(lookup.get("protocol", ""), "UNKNOWN")).upper(),
                timestamp=str(row.get(lookup.get("timestamp", ""), "") or None),
                packet_count=_safe_int(row.get(lookup.get("packet_count", ""))) or 1,
                bytes_transferred=_safe_int(row.get(lookup.get("bytes_transferred", ""))) or 0,
                source_mac=str(row.get(lookup.get("source_mac", ""), "") or None),
                destination_mac=str(row.get(lookup.get("destination_mac", ""), "") or None),
                tcp_flags=str(row.get(lookup.get("tcp_flags", ""), "") or None),
                dns_query=str(row.get(lookup.get("dns_query", ""), "") or None),
                payload_preview=str(row.get(lookup.get("payload_preview", ""), "") or None),
                payload_hex=str(row.get(lookup.get("payload_hex", ""), "") or None),
                payload_kind=str(row.get(lookup.get("payload_kind", ""), "") or None),
            )
