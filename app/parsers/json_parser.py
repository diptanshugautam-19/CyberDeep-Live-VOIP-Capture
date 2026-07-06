import json
from pathlib import Path
from typing import Iterable

from app.parsers.base import ConnectionRecord, EvidenceParser, ParserError


FIELD_ALIASES = {
    "source_ip": ["source_ip", "src_ip", "src", "ip.src", "source", "source_address"],
    "destination_ip": ["destination_ip", "dst_ip", "dest_ip", "dst", "ip.dst", "destination", "destination_address"],
    "source_port": ["source_port", "src_port", "sport", "tcp_srcport", "udp_srcport"],
    "destination_port": ["destination_port", "dst_port", "dport", "tcp_dstport", "udp_dstport"],
    "protocol": ["protocol", "proto", "_ws.col.protocol"],
    "timestamp": ["timestamp", "time", "ts", "first_seen", "start_time"],
    "packet_count": ["packet_count", "packets", "frames", "packet"],
    "bytes_transferred": ["bytes_transferred", "bytes", "octets", "length", "frame_len"],
    "source_mac": ["source_mac", "src_mac", "mac_src"],
    "destination_mac": ["destination_mac", "dst_mac", "mac_dst"],
    "tcp_flags": ["tcp_flags", "flags"],
    "dns_query": ["dns_query", "query", "qname"],
    "payload_preview": ["payload_preview", "payload", "preview"],
    "payload_hex": ["payload_hex", "hex"],
    "payload_kind": ["payload_kind", "kind"],
}


class JsonNetworkLogParser(EvidenceParser):
    supported_extensions = (".json", ".jsonl", ".ndjson")

    def parse(self, path: Path) -> Iterable[ConnectionRecord]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").strip()
        except Exception as exc:  # pragma: no cover - filesystem specific
            raise ParserError(f"Unable to read JSON evidence: {exc}") from exc

        records = []
        payload = _load_json(text)
        for item in _iter_items(payload, text):
            record = _build_record(item)
            if record:
                records.append(record)

        if not records:
            raise ParserError("No network records were found in the JSON evidence.")
        return records


def _load_json(text: str):
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _iter_items(payload, text: str):
    if isinstance(payload, list):
        yield from payload
        return
    if isinstance(payload, dict):
        for key in ("records", "flows", "connections", "packets", "events", "results", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                yield from value
                return
        yield payload
        return

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            yield item


def _build_record(item: dict) -> ConnectionRecord | None:
    source_ip = _lookup(item, FIELD_ALIASES["source_ip"])
    destination_ip = _lookup(item, FIELD_ALIASES["destination_ip"])
    if not source_ip or not destination_ip:
        return None
    return ConnectionRecord(
        source_ip=str(source_ip),
        destination_ip=str(destination_ip),
        source_port=_safe_int(_lookup(item, FIELD_ALIASES["source_port"])),
        destination_port=_safe_int(_lookup(item, FIELD_ALIASES["destination_port"])),
        protocol=str(_lookup(item, FIELD_ALIASES["protocol"]) or "UNKNOWN").upper(),
        timestamp=str(_lookup(item, FIELD_ALIASES["timestamp"]) or "") or None,
        packet_count=_safe_int(_lookup(item, FIELD_ALIASES["packet_count"])) or 1,
        bytes_transferred=_safe_int(_lookup(item, FIELD_ALIASES["bytes_transferred"])) or 0,
        source_mac=str(_lookup(item, FIELD_ALIASES["source_mac"]) or "") or None,
        destination_mac=str(_lookup(item, FIELD_ALIASES["destination_mac"]) or "") or None,
        tcp_flags=str(_lookup(item, FIELD_ALIASES["tcp_flags"]) or "") or None,
        dns_query=str(_lookup(item, FIELD_ALIASES["dns_query"]) or "") or None,
        payload_preview=str(_lookup(item, FIELD_ALIASES["payload_preview"]) or "") or None,
        payload_hex=str(_lookup(item, FIELD_ALIASES["payload_hex"]) or "") or None,
        payload_kind=str(_lookup(item, FIELD_ALIASES["payload_kind"]) or "") or None,
        packet_details=item.get("packet_details") if isinstance(item.get("packet_details"), list) else None,
    )


def _lookup(item: dict, aliases: list[str]):
    lower = {str(key).lower(): value for key, value in item.items()}
    for alias in aliases:
        if alias.lower() in lower:
            return lower[alias.lower()]
    return None


def _safe_int(value) -> int | None:
    if value in ("", None):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None
