import re
from dataclasses import asdict, dataclass
from pathlib import Path

from dateutil import parser as date_parser


FIELD_ALIASES = {
    "subscriber": ["subscriber", "msisdn", "mobile", "phone", "a_party"],
    "imsi": ["imsi"],
    "imei": ["imei"],
    "called_number": ["called_number", "b_party", "called", "destination_number"],
    "called_ip": ["called_ip", "destination_ip", "dst_ip", "remote_ip"],
    "assigned_ip": ["assigned_ip", "device_ip", "source_ip", "src_ip", "ip_address"],
    "apn": ["apn"],
    "cell_tower": ["cell_tower", "cell_id", "tower", "cgi", "enodeb"],
    "session_start": ["session_start", "start_time", "login_time", "start"],
    "session_end": ["session_end", "end_time", "logout_time", "end"],
    "timestamp": ["timestamp", "time", "event_time"],
}


@dataclass
class TelecomEvidenceRecord:
    subscriber: str = ""
    imsi: str = ""
    imei: str = ""
    called_number: str = ""
    called_ip: str = ""
    assigned_ip: str = ""
    apn: str = ""
    cell_tower: str = ""
    session_start: str = ""
    session_end: str = ""
    timestamp: str = ""
    source_file: str = ""
    raw_text: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


KEY_VALUE_RE = re.compile(r"(?P<key>[A-Za-z_ /-]+)\s*[:=]\s*(?P<value>[^,\n\r;]+)")
PHONE_RE = re.compile(r"\+?\d{10,15}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_telecom_evidence(path: Path) -> list[TelecomEvidenceRecord]:
    if path.suffix.lower() not in {".txt", ".log", ".csv", ".tsv"}:
        return []

    text = path.read_text(encoding="utf-8", errors="ignore")
    if not _looks_like_telecom_evidence(text):
        return []
    chunks = [chunk.strip() for chunk in re.split(r"\n\s*\n", text) if chunk.strip()]
    if len(chunks) == 1:
        chunks = [line.strip() for line in text.splitlines() if line.strip()]

    records = []
    for chunk in chunks:
        values = _extract_fields(chunk)
        if not any(values.get(field) for field in ("subscriber", "imsi", "imei", "assigned_ip", "called_ip", "session_start", "timestamp")):
            continue
        records.append(TelecomEvidenceRecord(source_file=path.name, raw_text=chunk, **values))
    return records


def _extract_fields(text: str) -> dict:
    found = {field: "" for field in FIELD_ALIASES}
    for match in KEY_VALUE_RE.finditer(text):
        normalized_key = _normalize(match.group("key"))
        value = match.group("value").strip()
        for canonical, aliases in FIELD_ALIASES.items():
            if normalized_key in aliases:
                found[canonical] = _normalize_timestamp(value) if "time" in normalized_key or canonical in {"session_start", "session_end", "timestamp"} else value

    ips = IP_RE.findall(text)
    if ips and not found["assigned_ip"]:
        found["assigned_ip"] = ips[0]
    if len(ips) > 1 and not found["called_ip"]:
        found["called_ip"] = ips[1]

    phones = PHONE_RE.findall(text)
    if phones and not found["subscriber"]:
        found["subscriber"] = phones[0]

    if not found["timestamp"]:
        found["timestamp"] = found["session_start"]
    return found


def _normalize(value: str) -> str:
    return value.strip().lower().replace(" ", "_").replace("-", "_").replace("/", "_")


def _normalize_timestamp(value: str) -> str:
    try:
        return date_parser.parse(value, fuzzy=True).isoformat()
    except Exception:
        return value


def _looks_like_telecom_evidence(text: str) -> bool:
    normalized = text.lower()
    indicators = [
        "subscriber",
        "msisdn",
        "imsi",
        "imei",
        "assigned ip",
        "assigned_ip",
        "apn",
        "cell tower",
        "cell_id",
        "session start",
        "session_start",
    ]
    return any(indicator in normalized for indicator in indicators)
