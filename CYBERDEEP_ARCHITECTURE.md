# CyberDEEP: Complete Project Reference

> **This is the absolute source of truth for the CyberDEEP project.** It documents every tool, every file, every API route, every database table, every module, and every configuration variable. Any developer or AI agent modifying this project must read this first.

---

## 📂 1. Complete Directory Map

```
d:\cyberdeep\
├── index.html                          # Main CyberDEEP dashboard (homepage SPA shell)
├── style.css                           # Dashboard CSS (dark theme, glassmorphism, cards)
├── app.js                              # Dashboard controller + TOOLS_REGISTRY (all 8 tools)
├── ip_data.js                          # Client-side IP intelligence data arrays
├── mcc_data.js                         # MCC/MNC telecom provider lookup data
├── sms_company_data.js                 # SMS header-to-company mapping data
├── mbs_mcc_mapping.csv                 # Raw MCC/MBS telecom CSV source
├── lucide.js                           # Lucide icon library (bundled)
├── tailwind.js                         # Tailwind CSS (bundled from CDN)
├── requirements.txt                    # Python dependencies
├── CYBERDEEP_ARCHITECTURE.md           # This file
│
├── app/                                # ── BACKEND (FastAPI + Python) ──
│   ├── main.py                         # FastAPI entry point, ALL route definitions
│   ├── __init__.py                     # Package init
│   ├── subdomain_scanner.py            # Sublist3r-based subdomain enumeration engine
│   │
│   ├── core/
│   │   ├── config.py                   # Environment variables, paths, timeouts
│   │   └── logging.py                  # Logging configuration
│   │
│   ├── parsers/
│   │   ├── manager.py                  # Parser dispatcher (routes files to correct parser)
│   │   ├── base.py                     # ConnectionRecord dataclass + ParserError
│   │   ├── pcap_parser.py              # PCAP/PCAPNG decoder (Scapy + PyShark)
│   │   ├── csv_parser.py               # CSV network log parser
│   │   ├── json_parser.py              # JSON network log parser
│   │   ├── zeek_parser.py              # Zeek conn.log parser
│   │   ├── firewall_parser.py          # Firewall log parser
│   │   └── telecom_parser.py           # CDR/telecom record parser
│   │
│   ├── enrichment/
│   │   ├── pipeline.py                 # Master analysis pipeline (analyze_records)
│   │   ├── online.py                   # GeoIP concurrent lookup (5 APIs in parallel)
│   │   ├── telecom.py                  # Telecom enrichment (subnet classification + online)
│   │   ├── ports.py                    # Port-to-service mapping (PORT_MAP)
│   │   └── services.py                 # Service identification rules (WhatsApp, Telegram, etc.)
│   │
│   ├── analysis/
│   │   ├── traffic.py                  # Traffic analysis engine (1542 lines, core analytics)
│   │   ├── attribution.py              # VoIP call attribution (ICE/STUN/SIP correlation)
│   │   └── graph_hooks.py              # VoIP session graph visualization hooks
│   │
│   ├── correlation/
│   │   └── engine.py                   # Evidence correlation engine (network ↔ telecom)
│   │
│   ├── dpi/
│   │   └── engine.py                   # Deep Packet Inspection rules engine
│   │
│   ├── protocols/
│   │   ├── models.py                   # VoipSession + QosMetrics dataclasses
│   │   ├── sip.py                      # SIP protocol parser
│   │   ├── rtp.py                      # RTP/RTCP QoS metrics computation
│   │   ├── stun.py                     # STUN/TURN protocol decoder
│   │   ├── turn.py                     # TURN relay detection
│   │   └── ice.py                      # ICE candidate resolution + NAT type detection
│   │
│   ├── threat_intel/
│   │   ├── manager.py                  # ThreatIntelManager (orchestrates all feeds)
│   │   ├── cif_feed.py                 # CIF (Collective Intelligence Framework) feed manager
│   │   ├── abuseipdb_feed.py           # AbuseIPDB reputation feed
│   │   ├── local_feed.py               # Local threat indicator database
│   │   ├── cidr_index.py               # CIDR block indexing for fast IP lookups
│   │   ├── scoring.py                  # Risk score calculator
│   │   └── base.py                     # Base feed interface
│   │
│   ├── cif_rules/                      # 23 YAML threat feed rule definitions
│   │   ├── spamhaus.yml, feodotracker.yml, phishtank.yml, emergingthreats.yml,
│   │   ├── bambenek.yml, csirtg.yml, dataplane.yml, openphish.yml,
│   │   ├── urlhaus_abuse_ch.yml, sslbl_abuse_ch.yml, stopforumspam.yml,
│   │   ├── torproject_org.yml, cisco_umbrella.yml, majestic.yml, tranco.yml,
│   │   ├── normshield.yml, sans_edu.yml, darklist_de.yml, danger_rules_sk.yml,
│   │   ├── sblam.yml, vxvault.yml, apwg.yml, mirc.yml
│   │
│   ├── storage/
│   │   └── database.py                 # SQLite database router, schemas, CRUD operations
│   │
│   ├── api/
│   │   └── exports.py                  # Investigation export (CSV, JSON, XLSX, PDF)
│   │
│   ├── static/
│   │   ├── assets/
│   │   │   ├── index-CgfIjOhe.js       # Compiled React bundle (IP Intel tool frontend)
│   │   │   └── index-yYTTZ2hS.css      # Compiled React CSS
│   │   ├── css/
│   │   │   ├── styles.css              # IP Intel standalone page styles
│   │   │   └── typography.css          # Inter font system (single source of truth)
│   │   └── js/
│   │       └── app.js                  # IP Intel standalone page JavaScript
│   │
│   ├── templates/
│   │   └── index.html                  # Jinja2 template for /tool route
│   │
│   └── sublist3r/                      # Sublist3r library (vendored)
│
├── police_station_finder/
│   ├── index.html                      # Standard police station finder
│   ├── google_maps.html                # Google Maps variant
│   ├── app.js                          # Finder logic (CSV, canvas map, Haversine)
│   ├── google_maps_app.js              # Google Maps markers, search, filters
│   └── styles.css                      # Finder-specific styling
│
├── scripts/
│   └── prune_data.py                   # Data retention/pruning engine
│
├── data/                               # Runtime data directory (created at startup)
│   ├── uploads/                        # Temporary PCAP upload storage
│   ├── geoip/                          # GeoIP database files
│   ├── reports/                        # Generated investigation reports
│   ├── investigations.sqlite3          # Investigation + destination records
│   ├── packets.sqlite3                 # Decoded packet rows
│   ├── payloads.sqlite3                # Raw payload blobs + entropy
│   ├── live_capture.sqlite3            # Live capture packet storage
│   ├── telecom.sqlite3                 # CDR records + operator lookup
│   ├── geoip.sqlite3                   # Endpoint + GeoIP cache
│   ├── threatintel.sqlite3             # Threat indicators from feeds
│   ├── dns.sqlite3                     # DNS cache + subdomain scan results
│   ├── users.sqlite3                   # User preferences + saved filters
│   ├── cache.sqlite3                   # Temp cache + alert records
│   └── flows.sqlite3                   # Flow sessions, RTP streams, SIP dialogs, ICE
│
├── .github/workflows/
│   └── ci.yml                          # GitHub Actions CI pipeline
│
├── src/                                # React source files (for IP Intel tool)
├── dist/                               # Vite build output
└── docs/                               # Documentation assets
```

---

## 🛠️ 2. Tool-by-Tool Breakdown

### Tool 1: IFSC Lookup (`ifsc-lookup`)
*   **Category:** Financial
*   **Purpose:** Validate Indian Financial System Codes (IFSC), retrieving bank name, branch, MICR code, contact numbers, and addresses.
*   **External API:** `https://ifsc.razorpay.com/{ifsc_code}` (Razorpay public API, no key required)
*   **Key Source:** `app.js` → `TOOLS_REGISTRY[0]` (lines 5–130)
*   **UI Elements:** `#ifsc-input`, `#ifsc-search-btn`, `#ifsc-results-container`, `#ifsc-table-body`
*   **AI Modification Guide:** To switch to offline IFSC data, replace the `fetch()` call inside `initLogic` with a local JSON lookup.

---

### Tool 2: Police Station Finder (`police-finder`)
*   **Category:** Law Enforcement
*   **Purpose:** Find nearest Indian police stations by state, district, GPS coordinates, or text search. Calculate Haversine distances. Export filtered lists.
*   **Key Files:**
    *   `police_station_finder/index.html` — Standard Leaflet/Canvas finder
    *   `police_station_finder/google_maps.html` — Google Maps API variant
    *   `police_station_finder/app.js` — CSV ingestion, canvas map drawing, pagination, geolocation, nearest-station algorithm, detail dialogs, CSV export
    *   `police_station_finder/google_maps_app.js` — Google Maps markers, search, filters, nearest station, directions links
    *   `police_station_finder/styles.css` — Dark/light theme, responsive layouts, print mode
*   **Data Source:** CSV file with columns: `police_station`, `district`, `state`, `latitude`, `longitude`, `phone`
*   **Backend Mount:** `app.mount("/police_station_finder", ...)` in `app/main.py` line 644
*   **AI Modification Guide:** To add new data columns, update CSV parsing in `police_station_finder/app.js` and add table headers in both `index.html` and `google_maps.html`.

---

### Tool 3: NCRP Intelligence (`ncrp-intelligence`)
*   **Category:** Cybercrime
*   **Purpose:** National Cyber Crime Reporting Portal (NCRP) intelligence ledger. Upload and analyze fraud reports, match suspect phone numbers, bank accounts, IPs, and UPI IDs across cases.
*   **Key Source:** `app.js` → `TOOLS_REGISTRY[2]` (lines 1352–2080)
*   **Features:** Client-side CSV parsing, suspect cross-referencing, card-based intelligence output, network link visualization
*   **Data Flow:** Entirely client-side (no backend storage yet)
*   **AI Modification Guide:** To persist NCRP data server-side, create `POST /api/ncrp/upload` in `app/main.py`, add a `ncrp_reports` table to `database.py`, and update the JS upload handler.

---

### Tool 4: MCC/MBS Lookup (`mcc-mbs-lookup`)
*   **Category:** Telecom
*   **Purpose:** Decode Mobile Country Code (MCC), Mobile Network Code (MNC), and Mobile Brand Services (MBS) to identify telecom operators, network types, and service areas.
*   **Key Files:**
    *   `mcc_data.js` — 486KB compiled JavaScript array containing all MCC/MNC entries
    *   `mbs_mcc_mapping.csv` — 210KB raw CSV source data
*   **Key Source:** `app.js` → `TOOLS_REGISTRY[3]` (lines 2081–2382)
*   **AI Modification Guide:** If new MCC/MNC allocations are issued, update `mbs_mcc_mapping.csv` and regenerate `mcc_data.js`. The JS lookup iterates over the in-memory array for instant matching.

---

### Tool 5: IP Sentinel (`ip-sentinel`)
*   **Category:** Threat Intelligence
*   **Purpose:** Reputational scanning and threat assessment for IP addresses, domains, URLs, and file hashes against 23+ threat intelligence feeds.
*   **Key Files:**
    *   `app/threat_intel/manager.py` — `ThreatIntelManager` orchestrator class
    *   `app/threat_intel/cif_feed.py` — CIF (Collective Intelligence Framework) feed manager (16KB, manages all 23 YAML feeds)
    *   `app/threat_intel/abuseipdb_feed.py` — AbuseIPDB reputation feed
    *   `app/threat_intel/local_feed.py` — Local threat database
    *   `app/threat_intel/scoring.py` — Risk score calculation (0–100)
    *   `app/threat_intel/cidr_index.py` — CIDR block fast-lookup index
    *   `app/cif_rules/*.yml` — 23 YAML feed definitions (Spamhaus, Feodo Tracker, PhishTank, Emerging Threats, Bambenek, CSIRT, Dataplane, OpenPhish, URLhaus, SSL Blacklist, StopForumSpam, Tor Exit Nodes, Cisco Umbrella, Majestic, Tranco, NormShield, SANS, DarkList, Danger.Rules.SK, Sblam, VxVault, APWG, MIRC)
*   **Key Source:** `app.js` → `TOOLS_REGISTRY[4]` (lines 2383–2966)
*   **API Routes:**
    *   `GET /api/threat_intel/lookup?indicator={value}` — Multi-indicator auto-detect lookup
    *   `GET /api/threat_intel/lookup/ip?ip={ip}` — IP-specific lookup
    *   `GET /api/threat_intel/lookup/domain?domain={domain}` — Domain lookup
    *   `GET /api/threat_intel/lookup/url?url={url}` — URL lookup
    *   `GET /api/threat_intel/lookup/hash?hash={hash}` — Hash lookup (MD5/SHA256)
    *   `GET /api/threat_intel/status` — Feed sync status + health dashboard
*   **AI Modification Guide:** To add a new feed, create a YAML rule file in `app/cif_rules/`, it will be auto-loaded by `CIFFeedManager`. To integrate VirusTotal or similar, add a new feed class in `app/threat_intel/` and register it in `manager.py`.

---

### Tool 6: SMS Header Analyzer (`sms-header-analyzer`)
*   **Category:** Telecom / Forensics
*   **Purpose:** Parse SMS sender header prefixes (e.g., `AD-KOTAKB`, `VK-IMOBIL`, `JD-PAYTMB`) to identify the registered entity (bank, company, or telecom provider).
*   **Key Files:**
    *   `sms_company_data.js` — 122KB mapping of SMS header prefixes to company names, categories, and telecom circles
*   **Key Source:** `app.js` → `TOOLS_REGISTRY[5]` (lines 2967–3641)
*   **AI Modification Guide:** When TRAI updates header allocations, add entries to `sms_company_data.js`. The lookup splits the header on `-` to extract prefix + entity code.

---

### Tool 7: IP Intelligence Analyzer (`ip-intel-analyzer`)
*   **Category:** Network Forensics (Core Tool)
*   **Purpose:** Full-stack PCAP/PCAPNG analysis pipeline: packet parsing → protocol decoding → GeoIP resolution → service identification → threat intelligence → VoIP analysis → evidence correlation → Leaflet map visualization → export.
*   **Key Files:**
    *   **Parsers:**
        *   `app/parsers/pcap_parser.py` — PCAP/PCAPNG decoder using Scapy + PyShark (35KB). Extracts TCP, UDP, DNS, HTTP, SMTP, SIP, RTP, STUN, ICE, NFS, MySQL, FTP, RDP.
        *   `app/parsers/manager.py` — Routes evidence files to correct parser (PCAP, CSV, JSON, Zeek, Firewall)
        *   `app/parsers/base.py` — `ConnectionRecord` dataclass (src_ip, dst_ip, src_port, dst_port, protocol, timestamp, length, payload)
    *   **Enrichment:**
        *   `app/enrichment/pipeline.py` — Master pipeline `analyze_records()` (53KB). Groups flows, enriches destinations, classifies services, runs DPI, calculates statistics.
        *   `app/enrichment/online.py` — **Concurrent GeoIP lookup** using `ThreadPoolExecutor` hitting 5 APIs in parallel (ipwho.is, freeipapi, api.ipapi.com, ipapi.co, ip-api.com). Includes `_geocode_city()` for OpenStreetMap Nominatim coordinate refinement. Results cached via `@lru_cache(4096)`.
        *   `app/enrichment/telecom.py` — Subnet classification (RFC1918, CGNAT, multicast) + online GeoIP provider orchestration
        *   `app/enrichment/services.py` — Service fingerprinting rules (WhatsApp AS32934, Telegram AS62041, Signal, Google, Microsoft Teams, Cloudflare, AWS)
        *   `app/enrichment/ports.py` — Port-to-service name mapping + VoIP ephemeral port detection
    *   **Analysis:**
        *   `app/analysis/traffic.py` — Core traffic analysis engine (1542 lines). Produces summary stats, bandwidth metrics, protocol distributions, anomaly detection, and VoIP session reconstruction.
        *   `app/analysis/attribution.py` — VoIP call attribution from ICE/STUN/SIP/RTP correlation
        *   `app/analysis/graph_hooks.py` — VoIP session visualization graph data
    *   **DPI:**
        *   `app/dpi/engine.py` — Deep Packet Inspection rule engine (14KB). Regex-based pattern matching for plaintext credentials, malware signatures, data exfiltration, and suspicious protocol usage.
    *   **Protocols:**
        *   `app/protocols/sip.py` — SIP message parser (INVITE, BYE, REGISTER, etc.)
        *   `app/protocols/rtp.py` — RTP/RTCP QoS metrics (jitter, packet loss, MOS score)
        *   `app/protocols/stun.py` — STUN/TURN message decoder (binding requests, XOR-mapped addresses)
        *   `app/protocols/ice.py` — ICE candidate resolution, NAT type detection
        *   `app/protocols/turn.py` — TURN relay server detection
        *   `app/protocols/models.py` — `VoipSession` + `QosMetrics` dataclasses
    *   **Correlation:**
        *   `app/correlation/engine.py` — Cross-correlates network evidence with telecom CDR records. Scores event confidence (0–100), identifies subscribers, devices, and services.
    *   **Frontend:**
        *   `app/static/assets/index-CgfIjOhe.js` — Compiled React bundle. Contains: investigation list, upload form, destination table, packet analyzer grid, analytics dashboard, IP details sidebar with Leaflet map, GeoIP & DNS tab with live query.
        *   `app/static/assets/index-yYTTZ2hS.css` — Compiled React styles
        *   `app/templates/index.html` — Jinja2 template served at `/tool`
    *   **Frontend State Hooks (React):**
        *   `f` — Currently selected IP for sidebar details panel
        *   `P` — Client-side live GeoIP lookup result (now routed to backend `/api/geoip/lookup`)
        *   `m` — Currently selected backend record from `c.rows`
        *   `A` — GeoIP & DNS tab query result
        *   `c.rows` — Backend destination list (enriched with coordinates, ISP, ASN)
*   **Key Source:** `app.js` → `TOOLS_REGISTRY[6]` (lines 3642–3972)
*   **API Routes:**
    *   `POST /api/upload` — Upload PCAP/CSV/JSON/Zeek evidence files
    *   `GET /api/investigations` — List all saved investigations
    *   `GET /api/investigations/{id}` — Get investigation details
    *   `GET /api/export/{id}.{format}` — Export investigation (csv, json, xlsx, pdf)
    *   `GET /api/geoip/lookup?ip={ip}` — Parallel GeoIP lookup with geocoding
*   **Supported File Formats:** `.pcap`, `.pcapng`, `.csv`, `.tsv`, `.log`, `.txt`, `.json`, `.zeek`
*   **Export Formats:** CSV, JSON, XLSX (via openpyxl), PDF (via ReportLab)
*   **AI Modification Guide:** For new protocols, edit `pcap_parser.py`. For new GeoIP providers, add worker functions in `online.py`. For new service fingerprints, add rules to `services.py`. For frontend changes, modify `index-CgfIjOhe.js` via string replacement or recompile from `src/`.

---

### Tool 8: Subdomain Scanner (`subdomain-scanner`)
*   **Category:** Reconnaissance
*   **Purpose:** Enumerate subdomains of a target domain using multiple OSINT search engines (Google, Yahoo, Bing, Baidu, Netcraft, etc.).
*   **Key Files:**
    *   `app/subdomain_scanner.py` — 26KB scanner engine with multi-engine support, DNS resolution, demo mode
    *   `app/sublist3r/` — Vendored Sublist3r library
*   **Key Source:** `app.js` → `TOOLS_REGISTRY[7]` (lines 3973–4672)
*   **API Routes:**
    *   `POST /api/subdomain/scan?domain={domain}&engines={engines}&demo={bool}` — Start scan
    *   `GET /api/subdomain/scan/{scan_id}` — Get scan status/results
    *   `GET /api/subdomain/scans` — List all scans
    *   `GET /api/subdomain/engines` — List available engines
*   **AI Modification Guide:** To add custom DNS resolution or brute-force wordlists, edit `app/subdomain_scanner.py`. Scan results are stored in `dns.sqlite3` → `subdomain_scans` table.

---

## 🖥️ 3. Frontend Architecture

### Main Dashboard (`index.html`)
*   **Design:** Dark theme, near-black/dark navy surfaces, cyan accent (`#00d2ff`)
*   **Font:** Inter (sole font, defined in `app/static/css/typography.css`)
*   **Icons:** Lucide icons loaded from `lucide.js`
*   **CSS Framework:** Tailwind CSS (from `tailwind.js`) + custom `style.css`
*   **Glassmorphism:** `.glass-panel` class with `backdrop-filter: blur(12px)`
*   **Skeleton Loaders:** `#tools-skeleton` with shimmer animation (400ms)
*   **Tool Loading:** `TOOLS_REGISTRY` in `app.js` → each tool has `id`, `name`, `category`, `icon`, `placeholderHtml`, `initLogic()`

### IP Intel Standalone (`/tool`)
*   **Framework:** React (compiled to `index-CgfIjOhe.js`)
*   **CSS:** Bootstrap 5.3 + custom `app/static/css/styles.css`
*   **Maps:** Leaflet.js with OpenStreetMap tiles
*   **GeoIP Queries:** Routed to backend `GET /api/geoip/lookup?ip=` (not direct to external APIs)

---

## 💾 4. Database Architecture (10 SQLite Files)

| Database File | Tables | Purpose |
|---|---|---|
| `investigations.sqlite3` | `investigations`, `destinations`, `investigation_search` (FTS5) | Master PCAP analysis records |
| `packets.sqlite3` | `packets` | Decoded packet rows (index, timestamp, protocol, ports, flags) |
| `payloads.sqlite3` | `payloads` | Raw payload blobs, preview text, MIME type, entropy |
| `live_capture.sqlite3` | `live_capture_packets`, `capture_statistics` | Real-time capture storage |
| `telecom.sqlite3` | `cdr_records`, `operator_lookup` | CDR records (IMSI, IMEI, cell_id) + MCC/MNC mapping |
| `geoip.sqlite3` | `endpoints`, `geoip_lookup` | IP endpoint cache + GeoIP coordinate cache with TTL |
| `threatintel.sqlite3` | `threat_indicators` | Threat IOCs (indicator, type, severity, STIX ID, tags) |
| `dns.sqlite3` | `dns_cache`, `subdomain_scans` | DNS resolution cache + subdomain scan results |
| `users.sqlite3` | `user_preferences`, `saved_filters` | User settings storage |
| `cache.sqlite3` | `temp_cache`, `alerts` | Temporary cache + alert records (severity, rule, confidence) |
| `flows.sqlite3` | `sessions`, `rtp_streams`, `sip_dialogs`, `ice_sessions` | Flow sessions, VoIP streams, SIP dialogs, ICE negotiations |

Every database includes a `schema_info` table for version tracking. The `DatabaseRouter` class in `database.py` maps table names to database files via `TABLE_MAP`.

---

## 🌐 5. Complete API Route Map

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/` | Serve main CyberDEEP dashboard (`index.html`) |
| `GET` | `/tool` | Serve IP Intelligence standalone workspace |
| `POST` | `/api/upload` | Upload and analyze evidence files |
| `GET` | `/api/investigations` | List all saved investigations |
| `GET` | `/api/investigations/{id}` | Get investigation by ID |
| `GET` | `/api/export/{id}.{format}` | Export investigation (csv/json/xlsx/pdf) |
| `GET` | `/api/threat_intel/lookup` | Multi-indicator threat lookup (auto-detect type) |
| `GET` | `/api/threat_intel/lookup/ip` | IP-specific threat lookup |
| `GET` | `/api/threat_intel/lookup/domain` | Domain-specific threat lookup |
| `GET` | `/api/threat_intel/lookup/url` | URL-specific threat lookup |
| `GET` | `/api/threat_intel/lookup/hash` | Hash-specific threat lookup |
| `GET` | `/api/threat_intel/status` | CIF feed sync status |
| `GET` | `/api/geoip/lookup` | Parallel GeoIP lookup (5 providers + geocoding) |
| `POST` | `/api/subdomain/scan` | Start subdomain enumeration |
| `GET` | `/api/subdomain/scan/{id}` | Get scan status/results |
| `GET` | `/api/subdomain/scans` | List all subdomain scans |
| `GET` | `/api/subdomain/engines` | List available scan engines |

### Static File Mounts (order matters — defined after routes):
1. `/static` → `app/static/` (CSS/JS for `/tool` page)
2. `/data` → `data/` (CSV files, police station data)
3. `/police_station_finder` → `police_station_finder/`
4. `/docs_static` → `docs/`
5. `/` → project root (catch-all for `app.js`, `style.css`, data JS files)

---

## ⚙️ 6. Configuration & Environment Variables

Defined in `app/core/config.py`:

| Variable | Default | Purpose |
|---|---|---|
| `ONLINE_ENRICHMENT_ENABLED` | `true` | Enable/disable live GeoIP API queries |
| `LIVE_LOOKUP_TIMEOUT_SECONDS` | `4.0` | Network timeout for each GeoIP provider |
| `IPINFO_TOKEN` | `""` | IPInfo.io API token (optional) |
| `ABUSEIPDB_API_KEY` | `""` | AbuseIPDB API key (optional) |

### Hardcoded API Keys:
*   `api.ipapi.com` access key: `aaa1119c0fa056fe2253d2034216f78a` (in `online.py`)

### Paths:
*   `BASE_DIR` → `d:\cyberdeep`
*   `DATA_DIR` → `d:\cyberdeep\data`
*   `GEOIP_DIR` → `d:\cyberdeep\data\geoip`
*   `UPLOAD_DIR` → `d:\cyberdeep\data\uploads`
*   `REPORT_DIR` → `d:\cyberdeep\data\reports`

---

## 📦 7. Python Dependencies

```
fastapi==0.115.6          # Web framework
uvicorn[standard]==0.34.0 # ASGI server
python-multipart==0.0.20  # File upload support
jinja2==3.1.5             # HTML templating
pandas==2.2.3             # Data manipulation (exports)
scapy==2.6.1              # Packet parsing (PCAP)
pyshark==0.6              # Packet parsing (PyShark wrapper)
openpyxl==3.1.5           # Excel export
reportlab==4.2.5          # PDF report generation
python-dateutil==2.9.0    # Date parsing
pydantic==2.10.4          # Data validation
httpx==0.28.1             # HTTP client (GeoIP lookups)
PyYAML>=6.0               # YAML parsing (CIF rules)
dnspython>=2.4            # DNS resolution
requests>=2.31.0          # HTTP requests (legacy)
```

---

## 🧪 8. CI/CD Pipeline

**File:** `.github/workflows/ci.yml`

*   **Trigger:** Push or PR to `main` branch
*   **Runner:** `ubuntu-latest`
*   **Python:** 3.11
*   **Steps:**
    1. Checkout code
    2. Install Python dependencies from `requirements.txt`
    3. Run `python scratch/verify_database.py --init-dummy`
*   **`--init-dummy` flag:** Creates empty database files with correct schemas so tests pass without 2.8GB MaxMind GeoIP databases.

---

## 🧹 9. Data Maintenance

### Pruning Engine (`scripts/prune_data.py`)
*   **Purpose:** Delete old records to prevent disk exhaustion
*   **Targets:** `packets.sqlite3`, `live_capture.sqlite3`, `flows.sqlite3`
*   **Default retention:** 30 days (`--days 30`)
*   **Post-delete optimization:** Runs `VACUUM`, `ANALYZE`, `PRAGMA optimize`
*   **Dry run:** `python scripts/prune_data.py --dry-run`

### Upload Cleanup
*   `_cleanup_uploads(keep=5)` in `main.py` automatically deletes all but the 5 most recent uploads after each analysis.

---

## 🔒 10. Security Notes
*   CORS is set to allow all origins (`allow_origins=["*"]`). Restrict in production.
*   The `api.ipapi.com` access key is hardcoded in `online.py`. Move to environment variable for production.
*   Upload directory accepts `.pcap`, `.pcapng`, `.csv`, `.tsv`, `.log`, `.txt`, `.json`, `.zeek` only.
*   SHA-256 hash is computed for every uploaded file (chain of custody).

---
**End of Document.** *This file must be kept in sync with the codebase. Update it when adding new tools, routes, or database tables.*
