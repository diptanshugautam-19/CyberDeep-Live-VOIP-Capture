import io
import json

import pandas as pd
from fastapi import HTTPException
from fastapi.responses import Response, StreamingResponse

from app.storage.database import get_investigation


EXPORT_COLUMNS = [
    "destination_ip",
    "role",
    "role_confidence",
    "role_reasons",
    "secondary_roles",
    "mac_address",
    "host_sessions",
    "host_peers",
    "source_ip",
    "destination_port",
    "protocol",
    "isp",
    "ip_source",
    "asn",
    "asn_org",
    "network_prefix",
    "country",
    "region",
    "city",
    "service",
    "category",
    "confidence",
    "matched_asn",
    "matched_prefix",
    "matched_port",
    "service_match_reasons",
    "port_name",
    "unusual_port",
    "reputation_score",
    "abuse_reports",
    "malicious",
    "threat_category",
    "last_reported",
    "last_checked",
    "feeds_checked",
    "first_seen",
    "last_seen",
    "connection_count",
    "packet_count",
    "bytes_transferred",
    "payload_kind",
    "payload_preview",
    "payload_hex",
]


def export_investigation(investigation_id: str, file_format: str):
    investigation = get_investigation(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return export_investigation_data(investigation, file_format)

def export_investigation_data(investigation: dict, file_format: str):
    rows = investigation.get("rows", [])
    frame = pd.DataFrame(rows)
    if not frame.empty:
        frame = frame[[column for column in EXPORT_COLUMNS if column in frame.columns]]

    if file_format == "json":
        content = json.dumps(investigation, indent=2)
        return Response(content, media_type="application/json")

    if file_format == "csv":
        stream = io.StringIO()
        frame.to_csv(stream, index=False)
        return Response(stream.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={investigation.get('id', 'export')}.csv"})

    if file_format == "xlsx":
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            frame.to_excel(writer, sheet_name="Destinations", index=False)
            pd.DataFrame([investigation.get("summary", {})]).to_excel(writer, sheet_name="Summary", index=False)
            pd.DataFrame(investigation.get("hosts", [])).to_excel(writer, sheet_name="Hosts", index=False)
            pd.DataFrame(investigation.get("sessions", [])).to_excel(writer, sheet_name="Sessions", index=False)
            pd.DataFrame(investigation.get("communication_matrix", [])).to_excel(writer, sheet_name="Matrix", index=False)
            pd.DataFrame(investigation.get("timeline", [])).to_excel(writer, sheet_name="Timeline", index=False)
            pd.DataFrame(investigation.get("protocol_summary", [])).to_excel(writer, sheet_name="Protocols", index=False)
            pd.DataFrame(investigation.get("voip_analysis", [])).to_excel(writer, sheet_name="VoIP Analysis", index=False)
            flow_diagram = investigation.get("flow_diagram", {})
            pd.DataFrame(flow_diagram.get("nodes", [])).to_excel(writer, sheet_name="Flow Nodes", index=False)
            pd.DataFrame(flow_diagram.get("edges", [])).to_excel(writer, sheet_name="Flow Edges", index=False)
            pd.DataFrame(investigation.get("correlation", {}).get("events", [])).to_excel(writer, sheet_name="Correlation", index=False)
            pd.DataFrame(investigation.get("evidence_files", [])).to_excel(writer, sheet_name="Chain of Custody", index=False)
            pd.DataFrame(investigation.get("telecom_records", [])).to_excel(writer, sheet_name="Telecom Evidence", index=False)
            packet_rows = pd.DataFrame(investigation.get("packet_rows", []))
            if not packet_rows.empty:
                packet_rows.to_excel(writer, sheet_name="Packets", index=False)
        output.seek(0)
        return StreamingResponse(
            output,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={investigation.get('id', 'export')}.xlsx"},
        )

    if file_format == "pdf":
        return _pdf_report(investigation, frame)

    if file_format == "html":
        rows_html = "".join([
            f"<tr><td>{r.get('destination_ip', 'unknown')}</td><td>{r.get('protocol', 'unknown')}</td><td>{'Malicious' if r.get('malicious') else r.get('reputation_score', 0)}</td><td>{r.get('bytes_transferred', 0)}</td></tr>"
            for r in rows[:50]
        ])
        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <title>CyberDeep Live Capture Report</title>
  <style>
    body {{ font-family: 'Inter', sans-serif; background-color: #0b0f19; color: #cbd5e1; padding: 40px; }}
    h1 {{ color: #22d3ee; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th, td {{ border: 1px solid #1e293b; padding: 12px; text-align: left; }}
    th {{ background-color: #0f172a; color: #22d3ee; }}
    tr:nth-child(even) {{ background-color: #0d1220; }}
  </style>
</head>
<body>
  <h1>CyberDeep Live Capture Report</h1>
  <p>Filename: {investigation.get('filename', 'Live Capture')}</p>
  <p>Generated: {investigation.get('created_at', '')}</p>
  <h2>Top Conversations & Destinations</h2>
  <table>
    <thead>
      <tr><th>Destination IP</th><th>Protocol</th><th>Threat Rating / Score</th><th>Bytes</th></tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</body>
</html>"""
        return Response(html_content, media_type="text/html", headers={"Content-Disposition": f"attachment; filename={investigation.get('id', 'export')}.html"})

    if file_format == "stix":
        import uuid
        from datetime import datetime, timezone
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects = []
        for r in rows:
            if r.get("malicious"):
                ip = r.get("destination_ip")
                objects.append({
                    "type": "indicator",
                    "id": f"indicator--{uuid.uuid4()}",
                    "spec_version": "2.1",
                    "created": datetime.now(timezone.utc).isoformat(),
                    "modified": datetime.now(timezone.utc).isoformat(),
                    "name": f"Malicious IP: {ip}",
                    "description": f"IP classified as malicious with reputation score {r.get('reputation_score')}",
                    "pattern": f"[ipv4-addr:value = '{ip}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.now(timezone.utc).isoformat()
                })
        if not objects:
            objects.append({
                "type": "indicator",
                "id": f"indicator--{uuid.uuid4()}",
                "spec_version": "2.1",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": "Clean Network Flow",
                "pattern": "[ipv4-addr:value = '0.0.0.0']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat()
            })
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": objects
        }
        return Response(json.dumps(bundle, indent=2), media_type="application/json", headers={"Content-Disposition": f"attachment; filename={investigation.get('id', 'export')}.stix.json"})

    if file_format == "openioc":
        import uuid
        from datetime import datetime, timezone
        ioc_id = str(uuid.uuid4())
        now_str = datetime.now(timezone.utc).isoformat()
        xml_items = []
        for r in rows:
            if r.get("malicious"):
                ip = r.get("destination_ip")
                xml_items.append(f"""      <IndicatorItem id="{uuid.uuid4()}" condition="is">
        <Context document="PortItem" search="PortItem/remoteIP" type="mir" />
        <Content type="string">{ip}</Content>
      </IndicatorItem>""")
        if not xml_items:
            xml_items.append(f"""      <IndicatorItem id="{uuid.uuid4()}" condition="is">
        <Context document="PortItem" search="PortItem/remoteIP" type="mir" />
        <Content type="string">127.0.0.1</Content>
      </IndicatorItem>""")
        xml_content = f"""<?xml version="1.0" encoding="utf-8"?>
<ioc xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="{ioc_id}" last-modified="{now_str}" xmlns="http://schemas.mandiant.com/2010/ioc">
  <short_description>Live Capture Indicators</short_description>
  <description>Threat indicators detected during live capture session.</description>
  <authored_by>CyberDeep</authored_by>
  <authored_date>{now_str}</authored_date>
  <definition>
    <Indicator operator="OR" id="{uuid.uuid4()}">
{chr(10).join(xml_items)}
    </Indicator>
  </definition>
</ioc>"""
        return Response(xml_content, media_type="application/xml", headers={"Content-Disposition": f"attachment; filename={investigation.get('id', 'export')}.ioc"})

    raise HTTPException(status_code=400, detail="Unsupported export format")


def _pdf_report(investigation: dict, frame: pd.DataFrame):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    output = io.BytesIO()
    document = SimpleDocTemplate(output, pagesize=letter, rightMargin=32, leftMargin=32)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("VoIP WireStream", styles["Title"]),
        Paragraph(f"Investigation: {investigation['filename']}", styles["Normal"]),
        Paragraph(f"Created: {investigation['created_at']}", styles["Normal"]),
        Spacer(1, 12),
    ]

    summary_rows = [[key.replace("_", " ").title(), value] for key, value in investigation["summary"].items() if not isinstance(value, list)]
    story.append(Table(summary_rows, colWidths=[220, 220]))
    story.append(Spacer(1, 16))

    if investigation.get("hosts"):
        host_rows = [["IP", "Role", "Confidence", "ASN", "Country"]]
        for host in investigation.get("hosts", [])[:12]:
            host_rows.append(
                [
                    host.get("ip", ""),
                    host.get("role", ""),
                    f"{host.get('role_confidence', 0)}%",
                    host.get("asn", ""),
                    host.get("country", ""),
                ]
            )
        story.append(Paragraph("Host Inventory", styles["Heading2"]))
        story.append(Table(host_rows, repeatRows=1))
        story.append(Spacer(1, 12))

    if investigation.get("sessions"):
        session_rows = [["Client", "Server", "Protocol", "Duration", "Bytes"]]
        for session in investigation.get("sessions", [])[:12]:
            session_rows.append(
                [
                    session.get("client_ip", ""),
                    session.get("server_ip", ""),
                    session.get("protocol", ""),
                    f"{session.get('duration_seconds', 0)}s",
                    session.get("bytes_transferred", 0),
                ]
            )
        story.append(Paragraph("Session Reconstruction", styles["Heading2"]))
        story.append(Table(session_rows, repeatRows=1))
        story.append(Spacer(1, 12))

    if investigation.get("communication_matrix"):
        matrix_rows = [["Source", "Destination", "Protocol", "Sessions", "Bytes"]]
        for item in investigation.get("communication_matrix", [])[:12]:
            matrix_rows.append(
                [
                    item.get("source_ip", ""),
                    item.get("destination_ip", ""),
                    item.get("protocol", ""),
                    item.get("session_count", 0),
                    item.get("bytes_transferred", 0),
                ]
            )
        story.append(Paragraph("Communication Matrix", styles["Heading2"]))
        story.append(Table(matrix_rows, repeatRows=1))
        story.append(Spacer(1, 12))

    if investigation.get("voip_analysis"):
        voip_rows = [["Call Type", "Caller", "Remote Peer", "Duration", "MOS"]]
        for call in investigation.get("voip_analysis", [])[:10]:
            voip_rows.append(
                [
                    call.get("call_type", ""),
                    call.get("caller", ""),
                    call.get("remote_peer", ""),
                    f"{call.get('call_duration_seconds', 0)}s",
                    call.get("mos_estimate", "n/a"),
                ]
            )
        story.append(Paragraph("VoIP Analysis", styles["Heading2"]))
        story.append(Table(voip_rows, repeatRows=1))
        story.append(Spacer(1, 12))

    evidence_rows = [["Uploaded File", "Type", "SHA-256"]]
    for evidence in investigation.get("evidence_files", []):
        evidence_rows.append([evidence["filename"], evidence["evidence_type"], evidence["sha256"][:24] + "..."])
    if len(evidence_rows) > 1:
        story.append(Paragraph("Chain of Custody", styles["Heading2"]))
        story.append(Table(evidence_rows, repeatRows=1))
        story.append(Spacer(1, 16))

    correlation_rows = [["Time", "PCAP Evidence", "TXT Evidence", "Score"]]
    for event in investigation.get("correlation", {}).get("events", [])[:20]:
        correlation_rows.append([event.get("time", ""), event.get("pcap_evidence", ""), event.get("txt_evidence", ""), event.get("match_score", "")])
    if len(correlation_rows) > 1:
        story.append(Paragraph("Evidence Correlation", styles["Heading2"]))
        story.append(Table(correlation_rows, repeatRows=1))
        story.append(Spacer(1, 16))

    table_rows = [["Destination", "ASN", "Provider", "Service", "Threat", "Bytes"]]
    for row in investigation["rows"][:35]:
        table_rows.append(
            [
                row["destination_ip"],
                row["asn"],
                row["isp"],
                row["category"],
                "Malicious" if row["malicious"] else str(row["reputation_score"]),
                row["bytes_transferred"],
            ]
        )

    table = Table(table_rows, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#94a3b8")),
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.append(table)
    document.build(story)
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={investigation['id']}.pdf"},
    )
