# IP Intelligence & Telecom Attribution Analyzer

> **Tool ID:** `ip-intel-analyzer`  
> **Category:** Network Forensics  
> **Status:** Ready  
> **Located in:** CyberDeep Dashboard → Network Forensics → IP Intelligence

---

## Overview

The **IP Intelligence & Telecom Attribution Analyzer** is a full-featured forensic investigation platform for uploading and analyzing network evidence files. It performs server-side analysis with ASN enrichment, service identification, threat intelligence correlation, and cross-evidence session reconstruction.

Supports **PCAP, PCAPNG, CSV, TSV, LOG, and TXT** evidence formats.

---

## Features

### 1. Evidence Upload
- **Drag-and-drop** file upload zone
- Supports **PCAP, PCAPNG, CSV, TSV, LOG, TXT** formats
- Multiple file upload in a single analysis run
- Chain of custody tracking (filename, SHA-256, file size, evidence type)

### 2. Summary Analytics Band
After analysis, a rich **analytics band** provides:

| Panel | Description |
|-------|-------------|
| **Host Inventory** | Lists all identified hosts with IP, role, ASN, country, peer count, and destination ports |
| **Session Reconstruction** | Bidirectional conversations between client/server with protocol, duration, bytes |
| **Packet Flow Diagram** | Source → relay → destination path visualization |
| **Protocol Mix** | Distribution of observed protocols with percentage breakdown |
| **VoIP Analysis** | SIP, RTP, STUN, TURN, ICE, WebRTC session identification with MOS estimates |
| **Anomaly Detection** | Security & protocol alerts with severity levels (high/medium/low) |

### 3. Summary Cards
- Connections count
- Packet count
- Total destinations
- Hosts identified
- Sessions reconstructed
- Threat indicators
- Countries contacted
- Traffic volume (bytes)

### 4. Destination Intelligence Table

Filterable table with columns:
- **Destination IP** + port
- **ISP / Provider**
- **Role** (client, server, C2, etc.)
- **Service / Category**
- **ASN** number and organization
- **Country**
- **Threat** level (Clean / Suspicious / Malicious)

Private unicast destinations observed in the evidence, such as LAN or direct
peer addresses in `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`, are
included as destination rows. Multicast, loopback, link-local, and broadcast
addresses are excluded from this table but remain available in packet evidence.

For captures containing STUN/TURN traffic, the analyzer separates the direct
peer from signaling infrastructure. Repeated STUN Binding Requests to a private
unicast address are marked **Primary Direct Peer**. Standard STUN/TURN service
addresses are marked **STUN/TURN Infrastructure**. The table defaults to
session traffic; unrelated discovery and background flows remain available
through the **All captured traffic** scope.

Filters:
- Text search (IP, ASN, provider)
- Port filter
- Role dropdown
- Service/Category dropdown
- Threat filter (Malicious / Score 50+ / Clean)

### 5. Detail Panel (per IP)

Click any row to open the **detail panel** with 11 tabs:

| Tab | Content |
|-----|---------|
| **Overview** | IP profile (destination/port/hostname), geo (country/region/city/coordinates), service classification |
| **Timeline** | First seen, last seen, duration, connection count, packet count, traffic volume |
| **Threat Intel** | Reputation status, threat score, abuse reports, feed context, last reported/checked |
| **WHOIS** | ASN details, registry hint, network prefix, organization attribution |
| **DNS** | Reverse DNS, provider DNS hint, observed port |
| **ASN** | Full ASN, organization, prefix, provider, country, region, city |
| **Correlation** | Session correlation table (PCAP match vs TXT match), correlation events, correlation graph (subscriber → IP → services) |
| **Report** | Attribution report with subscriber, assigned IP, correlated services, evidence, device, assessment |
| **Flows** | All raw connection records with source/destination IP, ports, protocol, timestamp, packet count, bytes, payload preview, packet details, decoded protocol information |
| **Packets** | Full Wireshark-like packet table with search and protocol filter. Each packet shows: time, flow label, protocol, decoding, payload type, length. Click any packet for detailed profile, protocol decoding, and payload view. |
| **Notes** | Freeform text area for investigator notes per IP |

### 6. Payload Inspection

Each flow and packet includes **payload analysis**:

- **DNS / Plaintext** — Readable content extracted from the payload
- **Encrypted** — Ciphertext preview (not decryptable)
- **Binary** — Non-text payload, raw hex display
- **No Payload** — Metadata-only records

### 7. Packet Decoding

Protocol-specific decoding for:
- **DNS** — Transaction ID, RCode, Questions, Answers
- **HTTP Request** — Method, Path, Host, Version, Headers, Body Preview
- **HTTP Response** — Status Code, Reason, Version, Headers, Body Preview
- **Encrypted Payload** — Ciphertext preview with decryption note

### 8. Reports & Exports

Once analysis completes, downloadable exports:
- **PDF** forensic summary
- **Excel** workbook
- **CSV** destination table
- **JSON** investigation bundle

---

## Usage

### Quick Start

1. Navigate to **IP Intelligence** in the CyberDeep dashboard
2. Drop or select evidence files (PCAP, CSV, TXT, LOG, etc.)
3. Click **ANALYZE EVIDENCE**
4. Review the analytics band and summary cards
5. Browse the destination table, click any IP for full details
6. Use the detail tabs to investigate: Overview → Timeline → Threat → Flows → Packets

### Investigating Specific IPs

1. In the destination table, **click any row** to select it
2. The right panel populates with IP details
3. Switch between **11 investigation tabs** (Overview through Notes)
4. The **Flows tab** shows all raw connections to/from this IP
5. The **Packets tab** provides Wireshark-style inspection with search

### Correlation Analysis (PCAP + CDR/TXT)

When uploading a **PCAP** alongside a **telecom CDR (TXT)** file, the system cross-correlates:
- Matched sessions between network evidence and telecom records
- Subscriber identification (name, IMEI, assigned IP)
- Attribution report with assessment
- Correlation graph showing the evidence chain

### Threat Intel Integration

The analyzer integrates with the backend's threat intelligence feeds. Each destination shows:
- Reputation score (0-100)
- Malicious flag
- Threat category
- Feed check timestamp

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/upload` | POST | Upload evidence files for analysis |
| `/api/export/{id}.{format}` | GET | Export analysis results (pdf, xlsx, csv, json) |

---

## Technical Details

- **Backend:** Python FastAPI (see `app/` directory)
- **Parsers:** `app/parsers/` — supports PCAP (via PyShark/Scapy), CSV, TSV, LOG, TXT
- **Enrichment:** `app/enrichment/` — ASN, service identification, ports, telecom
- **Correlation Engine:** `app/correlation/engine.py` — cross-evidence session matching
- **Threat Intel:** `app/threat_intel/` — CIF feed integration, local feeds, AbuseIPDB
- **Storage:** SQLite database at `data/ip_intel.sqlite3`

---

## Data Flow

```
User Upload (PCAP/CSV/TXT)
        ↓
   /api/upload
        ↓
Parser Layer (app/parsers/)
   ├── PCAP parser → packet extraction, protocol decoding
   ├── CSV parser → structured network records
   └── TXT parser → telecom CDR records
        ↓
Enrichment Pipeline (app/enrichment/)
   ├── ASN enrichment (MaxMind / IPinfo offline)
   ├── Service identification (port-based + CIF)
   ├── Port scanning & service tags
   └── Telecom enrichment (MCC-MNC, operator lookup)
        ↓
Correlation Engine (app/correlation/)
   ├── Session reconstruction
   ├── Bidirectional flow mapping
   ├── PCAP ↔ TXT cross-matching
   └── Host inventory building
        ↓
Threat Intelligence (app/threat_intel/)
   ├── CIF feed lookup
   ├── AbuseIPDB reputation
   └── Local feed matching
        ↓
Response → Dashboard Visualization
   ├── Analytics band
   ├── Destination table
   ├── Detail panel (11 tabs)
   └── Export generators
```

---

## Requirements

- Running CyberDeep backend server (`uvicorn app.main:app`)
- Evidence files: PCAP / PCAPNG / CSV / TSV / LOG / TXT formats
- Optional: MaxMind GeoLite2 databases for offline ASN resolution
- Optional: ipinfo.io token for live enrichment

---

## See Also

- [IP Sentinel (Threat Intelligence Platform)](IP_SENTINEL.md) — Multi-indicator threat lookup against 23+ CIF feeds
- [Installation Guide](INSTALLATION.md) — Setup instructions
- [Usage Guide](USAGE.md) — General application usage
