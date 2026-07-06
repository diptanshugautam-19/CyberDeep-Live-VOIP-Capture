from pathlib import Path
from typing import Iterable

from app.parsers.base import ConnectionRecord, ParserError
from app.parsers.csv_parser import CsvConnectionParser
from app.parsers.firewall_parser import FirewallLogParser
from app.parsers.json_parser import JsonNetworkLogParser
from app.parsers.pcap_parser import PcapParser
from app.parsers.zeek_parser import ZeekConnLogParser


PARSERS = [JsonNetworkLogParser(), CsvConnectionParser(), PcapParser(), ZeekConnLogParser(), FirewallLogParser()]


def parse_evidence(path: Path) -> list[ConnectionRecord]:
    last_error: ParserError | None = None
    for parser in PARSERS:
        if parser.can_parse(path):
            try:
                records = list(parser.parse(path))
            except ParserError as exc:
                last_error = exc
                continue
            if not records:
                last_error = ParserError("No network connections were extracted from this evidence file.")
                continue
            return records
    if last_error:
        raise last_error
    raise ParserError(f"Unsupported file type: {path.name}")


def supports_evidence(path: Path) -> bool:
    return any(parser.can_parse(path) for parser in PARSERS)
