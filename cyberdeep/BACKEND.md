# CyberDeep Backend Developer Manual

This document outlines the architecture, layout, core service components, APIs, database schema mappings, configuration settings, and security guidelines of the CyberDeep backend platform.

---

## 🛠️ 1. Technical Stack

* **Core Framework**: [FastAPI](https://fastapi.tiangolo.com/) (Asynchronous HTTP web framework)
* **Execution Server**: [Uvicorn](https://www.uvicorn.org/) (ASGI web server implementation)
* **Packet Capture & Decoding**: [Scapy](https://scapy.net/) (for packet sniffing and file writing) and [PyShark](https://kiminewt.github.io/pyshark/) (tshark wrapper for offline analysis)
* **Database Engine**: [SQLite](https://www.sqlite.org/) (partitioned databases managed via a custom database router)
* **Intelligence Tools**: [Sublist3r](https://github.com/aboul3la/Sublist3r) (subdomain enumeration) and [Collective Intelligence Framework (CIF)](https://github.com/csirtgadgets/massive-octo-spice) (threat feeds aggregator)

---

## 📁 2. Backend Module Map

The backend code is housed inside the `/app` directory:

```
app/
├── main.py                         # FastAPI App entrypoint, endpoints, and middleware
├── subdomain_scanner.py            # Async subdomain scanner wrapper
│
├── core/
│   ├── config.py                   # Environment configuration variables and paths
│   ├── logging.py                  # Logger definitions
│   ├── auth.py                     # API key authentication & WS single-use ticket management
│   ├── capture_manager.py          # Sniffer loop, ring buffers, and PCAP write controllers
│   ├── bridge.py                   # WebSocket connection registry & packet broadcasters
│   ├── flow_engine.py              # Threaded packet analyzer queuing raw packets
│   ├── pipeline.py                 # Live packet analysis orchestration
│   └── enrichment.py               # Asynchronous threat lookup & OUI/GeoIP enrichment
│
├── parsers/
│   ├── manager.py                  # Parser dispatcher
│   ├── base.py                     # Dataclasses & errors
│   ├── pcap_parser.py              # PCAP file parsing (Scapy/PyShark)
│   ├── csv_parser.py               # CSV log files parser
│   ├── firewall_parser.py          # Syslog / firewall log parser
│   └── telecom_parser.py           # CDR / telecom file parser
│
├── storage/
│   └── database.py                 # Partitioned SQLite database connections router
│
├── threat_intel/
│   ├── manager.py                  # Threat Intelligence controller
│   └── abuseipdb_feed.py           # Reputation IP lookup queries
│
└── integrations/
    └── tshark_mcp/
        ├── service.py              # TShark file parsing service
        └── server.py               # TShark MCP JSON-RPC subprocess server
```

---

## 🔑 3. Authentication & Security (Hardened)

All sensitive endpoints require authentication using a Bearer token:

### 3.1 Verification Hook
* Endpoint routes are decorated with `dependencies=[Depends(verify_token)]`.
* Checks if `Authorization` header contains `Bearer <STATIC_API_KEY>`.
* The `STATIC_API_KEY` is loaded from the SQLite database `user_preferences`. If not present, a cryptographically secure 40-char key is generated using `secrets.token_hex(20)` and output directly to console stdout on first boot.

### 3.2 WebSocket Authentication (Single-Use Tickets)
1. The client requests a WebSocket ticket via authenticated `POST /api/auth/ticket`.
2. The server generates a random URL-safe ticket token using `secrets.token_urlsafe(32)` and saves it inside `temp_cache` with a 30-second TTL.
3. The client initiates WebSocket handshake: `ws://127.0.0.1:8000/api/capture/live?ticket=<token>`.
4. The server validates the ticket, immediately deletes it (single-use constraint), and accepts the connection.
5. A background loop automatically purges expired tickets from the database every 5 minutes.

---

## 🗄️ 4. Partitioned Database Architecture

To maximize write throughput during heavy capture logging, data is partitioned across specialized SQLite databases located in `/data`:

| Database Filename | Alias | Purpose |
|-------------------|-------|---------|
| `ip_intel.sqlite3` | `users_db` | User preferences, API keys, custom DPI rules, and saved filters |
| `cache.sqlite3` | `cache_db` | Threat intel lookup cache, DNS resolutions, and active scans |
| `flows.sqlite3` | `flows_db` | Parsed network connections, flows, VoIP calls, and alert logs |
| `payloads.sqlite3` | `payloads_db` | Raw TCP/UDP packet payloads (compressed using `zlib`) |

### 4.1 Database Router (`DatabaseRouter`)
Database connection is abstracted through the `router` singleton inside [database.py](file:///d:/cyberdeep/app/storage/database.py). 

For cross-database queries (e.g. joining `packets` in `flows.sqlite3` with `payload_blob` in `payloads.sqlite3`), the router parses the SQL query and automatically issues `ATTACH DATABASE` statements.

> [!IMPORTANT]
> **Defensive ATTACH Guard**: To prevent SQL Injection vulnerabilities, dynamic ATTACH statements are gated by a strict whitelisting check verifying target database aliases against `VALID_ALIASES`.

---

## 🌐 5. Endpoints & Route Index

| Route | Method | Auth | Description |
|-------|--------|------|-------------|
| `/` | `GET` | None | Returns the unified dashboard console HTML |
| `/api/auth/ticket` | `POST` | ✅ | Generates a 30s TTL WebSocket ticket |
| `/api/interfaces` | `GET` | ✅ | Lists capture-ready physical interfaces |
| `/api/capture/start` | `POST` | ✅ | Starts background packet sniffer |
| `/api/capture/stop` | `POST` | ✅ | Stops packet sniffer |
| `/api/capture/status` | `GET` | ✅ | Returns packet metrics |
| `/api/capture/promote` | `POST` | ✅ | Saves temp capture to investigations DB |
| `/api/capture/stream/follow`| `GET` | ✅ | Reconstructs payload streams for a flow |
| `/api/upload` | `POST` | ✅ | PCAP/CSV/Zeek file ingestion (magic byte verified) |
| `/api/investigations` | `GET` | ✅ | Lists all saved investigations |
| `/api/geoip/lookup` | `GET` | ✅ | Resolves GeoIP data from cache and local providers |
| `/api/subdomain/scan` | `POST` | ✅ | Triggers background subdomain scan |
| `/api/mcp/analyze` | `POST` | ✅ | Runs TShark analysis engine |

---

## ⚙️ 6. Environment Settings

Backend variables are loaded from the environment:

* `IPINFO_TOKEN`: Token for online GeoIP database lookup.
* `ABUSEIPDB_API_KEY`: API key for malicious IP reputation searches.
* `GROQ_API_KEY`: Auth token for AI forensic investigator LLM queries.
* `ONLINE_ENRICHMENT_ENABLED`: Toggle local cache vs online DNS lookup (`true`/`false`).
* `LIVE_LOOKUP_TIMEOUT_SECONDS`: Subprocess network timeout limit (default `4`).
