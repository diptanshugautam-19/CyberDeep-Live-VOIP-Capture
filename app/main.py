import logging
import hashlib
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from app.api.exports import export_investigation
from app.correlation.engine import correlate_evidence
from app.core.config import APP_NAME, BASE_DIR, UPLOAD_DIR
from app.core.logging import configure_logging
from app.enrichment.pipeline import analyze_records
from app.parsers.base import ParserError
from app.parsers.manager import parse_evidence
from app.parsers.telecom_parser import parse_telecom_evidence
from app.storage.database import get_investigation, init_db, list_investigations, save_investigation

configure_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="CyberDeep Dashboard", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount IP Intel's own static assets at /static (CSS/JS for /tool page)
app.mount("/static", StaticFiles(directory=BASE_DIR / "app" / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "app" / "templates")


@app.on_event("startup")
def startup() -> None:
    init_db()


# ── CyberDeep Dashboard (homepage) ──────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def cyberdeep_dashboard():
    """Serve the CyberDeep dashboard as the homepage."""
    return FileResponse(BASE_DIR / "index.html", media_type="text/html")


# ── Original IP Intel standalone page ───────────────────────────────
@app.get("/tool", response_class=HTMLResponse)
async def ip_intel_tool(request: Request):
    """Serve the original IP Intel tool interface."""
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "app_name": APP_NAME, "api_base_url": ""},
    )


@app.post("/api/upload")
async def upload_evidence(request: Request):
    form = await request.form()
    files = [item for item in form.getlist("files") or form.getlist("file") if getattr(item, "filename", None)]
    if not files:
        raise HTTPException(status_code=400, detail="No evidence files provided")

    try:
        analysis = _analyze_uploaded_files(files)
        filename = ", ".join(item["filename"] for item in analysis["evidence_files"])
        investigation_id = save_investigation(filename, analysis)
    except Exception as exc:
        logger.exception("Unexpected multi-evidence analysis failure")
        raise HTTPException(status_code=500, detail="Analysis failed. Check application.log for details.") from exc

    return {"id": investigation_id, **analysis}

@app.get("/api/investigations")
async def investigations():
    return list_investigations()


@app.get("/api/investigations/{investigation_id}")
async def investigation(investigation_id: str):
    result = get_investigation(investigation_id)
    if not result:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return result


@app.get("/api/export/{investigation_id}.{file_format}")
async def export(investigation_id: str, file_format: str):
    return export_investigation(investigation_id, file_format.lower())


def _analyze_uploaded_files(files: list[UploadFile]) -> dict:
    batch_id = str(uuid.uuid4())
    paths = []
    for upload in files:
        if not upload.filename:
            continue
        extension = Path(upload.filename).suffix.lower()
        if extension not in {".pcap", ".pcapng", ".csv", ".tsv", ".log", ".txt", ".json", ".zeek"}:
            raise HTTPException(status_code=400, detail=f"Unsupported evidence type: {upload.filename}")
        safe_name = Path(upload.filename).name
        target = UPLOAD_DIR / f"{batch_id}_{safe_name}"
        with target.open("wb") as handle:
            shutil.copyfileobj(upload.file, handle)
        paths.append(target)
    result = _analyze_paths(paths)
    _cleanup_uploads(keep=5)
    return result


def _cleanup_uploads(keep: int = 5) -> None:
    """Keep only the most recent `keep` files in UPLOAD_DIR, delete the rest."""
    try:
        all_files = sorted(UPLOAD_DIR.iterdir(), key=lambda f: f.stat().st_mtime, reverse=True)
        for old_file in all_files[keep:]:
            if old_file.is_file():
                old_file.unlink(missing_ok=True)
    except Exception:
        pass  # Non-critical; don't break the upload if cleanup fails


def _analyze_paths(paths: list[Path]) -> dict:
    all_records = []
    telecom_records = []
    evidence_files = []

    for path in paths:
        metadata = _evidence_metadata(path)
        try:
            records = parse_evidence(path)
            all_records.extend(records)
            metadata["network_records"] = len(records)
            metadata["parser_status"] = "Network evidence parsed"
        except ParserError as exc:
            metadata["network_records"] = 0
            metadata["parser_status"] = f"No network records: {exc}"

        extracted_telecom = [record.to_dict() for record in parse_telecom_evidence(path)]
        telecom_records.extend(extracted_telecom)
        metadata["telecom_records"] = len(extracted_telecom)
        evidence_files.append(metadata)

    analysis = analyze_records(all_records)
    correlation = correlate_evidence(analysis, telecom_records, evidence_files)

    def shorten_ip(ip: str) -> str:
        if not ip:
            return ""
        if ":" in ip:
            parts = ip.split(":")
            if len(parts) > 3:
                return f"{parts[0]}:{parts[1]}:::{parts[-1]}"
        return ip

    def clean_org_name(name: str) -> str:
        if not name or "Unknown Organization" in name:
            return ""
        import re
        # Remove ASXXXXX prefix
        name = re.sub(r'^AS\d+\s+', '', name)
        # Remove (Country) suffix
        name = re.sub(r'\s*\([^)]*\)$', '', name)
        # Common replacements/cleanup
        name = name.replace("Bharti Airtel Ltd.", "Airtel")
        name = name.replace("Bharti Airtel Ltd., Telemedia Services", "Airtel")
        name = name.replace("Bharti Airtel", "Airtel")
        name = name.replace("Facebook, Inc.", "Facebook")
        name = name.replace("Google LLC", "Google")
        name = name.replace("Microsoft Corporation", "Microsoft")
        name = name.replace("Private LAN", "LAN")
        name = name.replace("Telegram Messenger LLP", "Telegram")
        name = name.replace("Cloudflare, Inc.", "Cloudflare")
        name = name.replace("Amazon.com, Inc.", "Amazon")
        name = name.replace("Reliance Jio Infocomm Limited", "Jio")
        name = name.replace("Reliance Jio Infocomm Ltd", "Jio")
        name = name.replace("Reliance Jio", "Jio")
        # Strip common suffixes
        name = re.sub(r'\s+(LLC|Inc\.?|LTD\.?|Corp\.?|Corporation|LLP|e\.V\.)', '', name, flags=re.IGNORECASE)
        return name.strip()

    voip_sessions = []
    for call in analysis.get("voip_analysis", []):
        mos = call.get("mos_estimate")
        mos_val = float(mos) if mos is not None else 0.0
        if mos_val >= 4.0:
            mos_lbl = "Excellent"
        elif mos_val >= 3.0:
            mos_lbl = "Good"
        elif mos_val >= 2.0:
            mos_lbl = "Fair"
        else:
            mos_lbl = "Poor"

        route = call.get("route", [])
        hops_formatted = []
        for hop in route:
            role = hop.get("role", "hop").upper()
            ip_str = shorten_ip(hop.get("ip"))
            port = hop.get("port")
            if port:
                ip_str = f"{ip_str}:{port}"
            org = clean_org_name(hop.get("name"))
            if org:
                hops_formatted.append(f"[{role}] {ip_str} ({org})")
            else:
                hops_formatted.append(f"[{role}] {ip_str}")
        route_str = " → ".join(hops_formatted)
        status_text = f"{route_str}" if route_str else "Completed"

        voip_sessions.append({
            "session_id": call.get("call_id") or f"session-{uuid.uuid4().hex[:8]}",
            "caller": shorten_ip(call.get("caller")) or "Unknown",
            "callee": shorten_ip(call.get("remote_peer")) or "Unknown",
            "protocol": call.get("call_type") or "VoIP",
            "jitter_ms": round(call.get("jitter_ms") or 0.0, 2),
            "mos_score": mos_val,
            "mos_label": mos_lbl,
            "status": status_text,
            "route": route
        })
    correlation["voip_sessions"] = voip_sessions

    analysis["evidence_files"] = evidence_files
    analysis["telecom_records"] = telecom_records
    analysis["correlation"] = correlation
    analysis["summary"].update(
        {
            "uploaded_files": correlation["case_summary"]["uploaded_files"],
            "correlated_events": correlation["case_summary"]["correlated_events"],
            "matched_sessions": correlation["case_summary"]["matched_sessions"],
            "correlation_confidence": correlation["case_summary"]["confidence"],
            "correlation_confidence_label": correlation["case_summary"]["confidence_label"],
            "associated_subscribers": correlation["case_summary"]["associated_subscribers"],
            "associated_devices": correlation["case_summary"]["associated_devices"],
            "likely_services": correlation["case_summary"]["likely_services"],
        }
    )

    # Enrich packet_rows with decoded protocol labels (pipeline already built the list)
    for pkt_row in analysis.get("packet_rows", []):
        pkt_row["decoded_type"] = _decode_packet_type(pkt_row)
        pkt_row["decoded_summary"] = _decode_packet_summary(pkt_row)
        pkt_row["decoded_detail"] = _decode_packet_detail(pkt_row)
        pkt_row["decoded_fields"] = _decode_packet_fields(pkt_row)

    analysis["summary"]["total_packets"] = analysis.get("raw_packet_count", 0)
    return analysis


def _evidence_metadata(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "filename": _display_filename(path),
        "stored_name": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "evidence_type": path.suffix.lower().lstrip("."),
        "chain_of_custody": "Original evidence preserved in data/uploads; SHA-256 computed at ingestion.",
    }


def _display_filename(path: Path) -> str:
    parts = path.name.split("_", 1)
    if len(parts) == 2 and len(parts[0]) == 36:
        return parts[1]
    return path.name


def _parse_sip_text(text: str) -> dict | None:
    if not text:
        return None
    lines = text.splitlines()
    if not lines:
        return None
    first_line = lines[0].strip()

    is_request = False
    is_response = False
    method = ""
    status_code = ""
    reason = ""

    if first_line.startswith("SIP/2.0 "):
        is_response = True
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            status_code = parts[1]
        if len(parts) >= 3:
            reason = parts[2]
    elif " SIP/2.0" in first_line:
        is_request = True
        parts = first_line.split(" ", 2)
        if len(parts) >= 1:
            method = parts[0]
    else:
        return None

    headers = {}
    vias = []
    record_routes = []
    contact = ""
    from_uri = ""
    to_uri = ""
    user_agent = ""
    body_lines = []
    in_body = False

    for line in lines[1:]:
        if in_body:
            body_lines.append(line)
            continue
        if not line.strip():
            in_body = True
            continue

        if ":" in line:
            name, val = line.split(":", 1)
            name = name.strip().lower()
            val = val.strip()
            headers[name] = val

            if name in ("via", "v"):
                vias.append(val)
            elif name == "record-route":
                record_routes.append(val)
            elif name in ("contact", "m"):
                contact = val
            elif name in ("from", "f"):
                from_uri = val
            elif name in ("to", "t"):
                to_uri = val
            elif name in ("user-agent", "server"):
                user_agent = val

    sdp_media_ip = ""
    sdp_media_port = None
    for sdp_line in body_lines:
        sdp_line = sdp_line.strip()
        if sdp_line.startswith("c=IN IP4 "):
            sdp_media_ip = sdp_line.replace("c=IN IP4 ", "").strip()
        elif sdp_line.startswith("m=audio "):
            m_parts = sdp_line.split(" ")
            if len(m_parts) >= 2:
                try:
                    sdp_media_port = int(m_parts[1])
                except ValueError:
                    pass

    call_id = headers.get("call-id", headers.get("i", "")).strip()
    if not call_id:
        return None

    return {
        "is_request": is_request,
        "is_response": is_response,
        "method": method,
        "status_code": status_code,
        "reason": reason,
        "call_id": call_id,
        "vias": vias,
        "record_routes": record_routes,
        "contact": contact,
        "from_uri": from_uri,
        "to_uri": to_uri,
        "user_agent": user_agent,
        "sdp_media_ip": sdp_media_ip,
        "sdp_media_port": sdp_media_port,
    }


def _decode_packet_type(pkt: dict) -> str:
    """Determine the decoded type label for a packet."""
    kind = (pkt.get("payload_kind") or "").lower()
    preview = pkt.get("payload_preview") or ""
    protocol = str(pkt.get("protocol") or "").upper()

    if protocol == "SIP":
        if "SIP/2.0" in preview:
            first_line = preview.split("\n", 1)[0].strip()
            if first_line.startswith("SIP/2.0 "):
                return "SIP Response"
            return "SIP Request"
        return "SIP Message"
    if protocol == "SDP":
        return "SDP Session Description"
    if protocol in ("RTP", "SRTP"):
        return f"{protocol} Media"
    if protocol in ("RTCP", "SRTCP"):
        return f"{protocol} Control"

    if kind == "dns" or "DNS" in preview:
        if "answer" in preview.lower():
            return "DNS Response"
        return "DNS Query"
    if kind == "plaintext":
        lower = preview.lower()
        if any(lower.startswith(m) for m in ("get ", "post ", "put ", "delete ", "head ", "patch ", "options ")):
            return "HTTP Request"
        if lower.startswith("http/"):
            return "HTTP Response"
        return "Plaintext"
    if kind == "encrypted":
        return "Encrypted Payload"
    if kind == "binary":
        return "Binary"
    return "No Payload"


def _decode_packet_summary(pkt: dict) -> str:
    """Build a short human-readable decoding summary."""
    dtype = _decode_packet_type(pkt)
    preview = pkt.get("payload_preview") or ""
    protocol = str(pkt.get("protocol") or "").upper()

    if dtype.startswith("SIP"):
        first_line = preview.split("\n", 1)[0].strip()
        call_id = ""
        for line in preview.split("\n"):
            if line.lower().startswith("call-id:") or line.lower().startswith("i:"):
                call_id = line.split(":", 1)[1].strip()
                break
        suffix = f" | Call-ID: {call_id[:12]}..." if call_id else ""
        return f"{first_line}{suffix}"

    if dtype == "SDP Session Description":
        owner = ""
        for line in preview.split("\n"):
            if line.startswith("o="):
                owner = line.replace("o=", "").strip()
                break
        suffix = f" | Owner: {owner}" if owner else ""
        return f"SDP Description{suffix}"

    if protocol in ("RTP", "SRTP", "RTCP", "SRTCP"):
        return pkt.get("summary") or f"{protocol} Packet"

    if dtype.startswith("DNS"):
        return preview[:120]
    if dtype == "HTTP Request":
        parts = preview.split("\r\n", 1) if "\r\n" in preview else preview.split("\n", 1)
        return parts[0][:100] if parts else preview[:100]
    if dtype == "HTTP Response":
        parts = preview.split("\r\n", 1) if "\r\n" in preview else preview.split("\n", 1)
        return parts[0][:100] if parts else preview[:100]
    if dtype == "Encrypted Payload":
        return "TLS/SSL encrypted traffic"
    return preview[:80] if preview else "No protocol-specific decoding"


def _decode_packet_detail(pkt: dict) -> str:
    """Longer detail string for the decoding panel."""
    return _decode_packet_summary(pkt)


def _decode_packet_fields(pkt: dict) -> dict:
    """Extract structured decoded fields from a packet."""
    dtype = _decode_packet_type(pkt)
    preview = pkt.get("payload_preview") or ""
    protocol = str(pkt.get("protocol") or "").upper()
    fields = {}

    if dtype.startswith("SIP") or protocol == "SIP" or dtype == "SDP Session Description" or protocol == "SDP":
        parsed = _parse_sip_text(preview)
        if parsed:
            fields.update(parsed)
        return fields

    if protocol in ("RTP", "SRTP", "RTCP", "SRTCP"):
        summary = pkt.get("summary") or ""
        if "Seq:" in summary:
            try:
                parts = summary.split(" | ")
                for part in parts:
                    if part.startswith("Seq:"):
                        fields["sequence_number"] = int(part.split(":")[1].strip())
                    elif part.startswith("SSRC:"):
                        fields["ssrc"] = int(part.split(":")[1].strip())
                    elif part.startswith("Payload:"):
                        fields["payload_type_name"] = part.split(":")[1].strip()
            except Exception:
                pass
        return fields

    if dtype.startswith("DNS"):
        for part in preview.split(" | "):
            if part.startswith("DNS query:"):
                fields["questions"] = [q.strip() for q in part.replace("DNS query:", "").split(",")]
            if part.startswith("DNS answer:"):
                fields["answers"] = [a.strip() for a in part.replace("DNS answer:", "").split(";")]
        return fields
    if dtype == "HTTP Request":
        lines = preview.replace("\r\n", "\n").split("\n")
        if lines:
            req_parts = lines[0].split(" ", 2)
            fields["method"] = req_parts[0] if len(req_parts) > 0 else "?"
            fields["path"] = req_parts[1] if len(req_parts) > 1 else "/"
            fields["version"] = req_parts[2] if len(req_parts) > 2 else "HTTP/1.1"
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k] = v
                if k.lower() == "host":
                    fields["host"] = v
        fields["headers"] = headers
        return fields
    if dtype == "HTTP Response":
        lines = preview.replace("\r\n", "\n").split("\n")
        if lines:
            resp_parts = lines[0].split(" ", 2)
            fields["version"] = resp_parts[0] if len(resp_parts) > 0 else "?"
            fields["status_code"] = resp_parts[1] if len(resp_parts) > 1 else "?"
            fields["reason"] = resp_parts[2] if len(resp_parts) > 2 else ""
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k] = v
        fields["headers"] = headers
        return fields
    if dtype == "Encrypted Payload":
        fields["ciphertext_preview"] = pkt.get("payload_hex") or "n/a"
        return fields
    return fields


# ── CIF Threat Intelligence API ─────────────────────────────────────
from app.threat_intel.manager import ThreatIntelManager

_threat_mgr = ThreatIntelManager()


@app.get("/api/threat_intel/lookup")
async def threat_intel_lookup(indicator: str):
    """Multi-indicator threat intelligence lookup (IP, domain, URL, hash).
    Auto-detects indicator type and queries all CIF feeds."""
    return _threat_mgr.lookup_indicator(indicator)


@app.get("/api/threat_intel/lookup/ip")
async def threat_intel_lookup_ip(ip: str):
    """IP-specific threat intelligence lookup."""
    return _threat_mgr.cif.lookup_ip(ip)


@app.get("/api/threat_intel/lookup/domain")
async def threat_intel_lookup_domain(domain: str):
    """Domain-specific threat intelligence lookup."""
    return _threat_mgr.cif.lookup_domain(domain)


@app.get("/api/threat_intel/lookup/url")
async def threat_intel_lookup_url(url: str):
    """URL-specific threat intelligence lookup."""
    return _threat_mgr.cif.lookup_url(url)


@app.get("/api/threat_intel/lookup/hash")
async def threat_intel_lookup_hash(hash: str):
    """Hash-specific threat intelligence lookup (MD5/SHA256)."""
    return _threat_mgr.cif.lookup_hash(hash)


@app.get("/api/threat_intel/status")
async def threat_intel_status():
    """CIF feed sync status and health dashboard data."""
    return _threat_mgr.get_cif_status()


# ── Subdomain Scanner (Sublist3r) API ───────────────────────────────
from app.subdomain_scanner import SubdomainScanner

_subdomain_scanner = SubdomainScanner()


@app.post("/api/subdomain/scan")
async def subdomain_scan_start(domain: str, engines: str = None, demo: bool = False):
    """Start a new subdomain enumeration scan."""
    scan_id = _subdomain_scanner.start_scan(domain, engines=engines, use_demo=demo)
    return {"scan_id": scan_id, "status": "running", "domain": domain}


@app.get("/api/subdomain/scan/{scan_id}")
async def subdomain_scan_status(scan_id: str):
    """Get scan status and results."""
    scan = _subdomain_scanner.get_scan(scan_id)
    if not scan:
        return {"error": "Scan not found"}
    return scan


@app.get("/api/subdomain/scans")
async def subdomain_scan_list():
    """List all scans."""
    return _subdomain_scanner.list_scans()


@app.get("/api/subdomain/engines")
async def subdomain_engines():
    """Get available enumeration engines."""
    return SubdomainScanner.get_engines()


# ── Static file mounts (MUST be after all route definitions) ────────
# Serve data/ directory (police_stations_master.csv, etc.)
app.mount("/data", StaticFiles(directory=BASE_DIR / "data"), name="data")

# Serve police_station_finder/ directory
_police_dir = BASE_DIR / "police_station_finder"
if _police_dir.is_dir():
    app.mount("/police_station_finder", StaticFiles(directory=_police_dir), name="police_station_finder")

# Serve docs/ directory
_docs_dir = BASE_DIR / "docs"
if _docs_dir.is_dir():
    app.mount("/docs_static", StaticFiles(directory=_docs_dir), name="docs_static")

# Catch-all: serve root project directory for JS, CSS, and data files
# This serves app.js, style.css, ip_data.js, mcc_data.js, sms_company_data.js, etc.
# Because it's mounted last, explicit API routes above always take priority.
app.mount("/", StaticFiles(directory=BASE_DIR, html=True), name="root")
