# AGENTS.md — CyberDEEP Workspace Guide for AI Agents

Welcome to **CyberDEEP**, a high-performance Network Forensics & WebRTC Attribution Platform designed for real-time deep packet inspection (DPI), VoIP protocol analysis, encrypted traffic fingerprinting, and forensic participant attribution.

This document serves as the primary guidance file for AI agentic assistants (Antigravity, Claude, Codex, etc.) working on this codebase.

---

## 🏛 Project Overview & Architecture

CyberDEEP combines high-throughput zero-drop packet sniffing with asynchronous stream reassembly, deep packet inspection, and real-time WebRTC/VoIP forensic attribution.

### Core Stack
* **Language & Runtime:** Python 3.10+ (Python 3.13 supported)
* **Web Framework:** [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/)
* **Packet Capture & Dissection:** [Scapy](https://scapy.net/) + [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) (PyShark integration)
* **Storage Engine:** SQLite3 (Multi-database architecture split across `data/` directory)
* **Frontend:** Vanilla HTML5, CSS3, & Modern JS rendered directly via FastAPI templates ([app/templates/unified.html](file:///d:/cyberdeep/app/templates/unified.html))

---

## 📁 Repository Directory Structure

```
d:\cyberdeep\
├── app/
│   ├── main.py                     # FastAPI application entry point & API router setup
│   ├── analysis/
│   │   ├── attribution_engine.py   # WebRTC/STUN/TURN/ICE forensic participant attribution
│   │   └── cli.py                  # Standalone CLI for offline PCAP forensic processing
│   ├── core/
│   │   ├── bridge.py               # Non-blocking WebSocket packet bridge (100k queue)
│   │   ├── capture_manager.py      # Hot-path packet sniffer & queue manager (<2μs/pkt)
│   │   ├── fingerprint.py          # JA3, JA4 (TLS 1.3), JA3S, JA4S, & HASSH fingerprinters
│   │   └── flow_engine.py          # TCP state machine & flow metrics tracking
│   ├── dpi/
│   │   └── engine.py               # Deep Packet Inspection (entropy & protocol signatures)
│   ├── protocols/
│   │   ├── tcp_media.py            # Stream reassembly & frame unmasking
│   │   └── voip_manager.py         # Live VoIP indexing & session state management
│   ├── storage/
│   │   └── database.py             # SQLite connection pools, schema migrations & batch writer
│   └── templates/
│       └── unified.html            # Real-time single-page console UI
├── data/                           # Active SQLite databases & exported PCAP captures
├── tests/                          # Automated unit test suite
│   ├── test_attribution_engine.py
│   ├── test_fingerprint.py
│   └── test_tcp_media.py
├── IMPORTANT_README.md             # Production deployment & system tuning guide
├── START.md                        # Quick start runner documentation
├── BACKEND.md                      # Backend API specification & endpoints
└── AGENTS.md                       # This agent guideline document
```

---

## ⚙️ Development Environment & Core Commands

### 1. Starting the Application
```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
* **Main UI:** `http://127.0.0.1:8000/`
* **OpenAPI Docs:** `http://127.0.0.1:8000/docs`
* **Health Check:** `http://127.0.0.1:8000/healthz`

### 2. Running Unit Tests
Always run the test suite after modifying core logic or storage handlers:
```powershell
python -m unittest discover tests
```

---

## 🗄 Storage Architecture (SQLite Databases)

CyberDEEP uses an isolated multi-database design located in `data/`:
* **`investigations.sqlite3`**: Forensic investigation cases, destinations, and FTS5 search indexes.
* **`live_capture.sqlite3`**: Transient live packet capture buffers & real-time statistics.
* **`packets.sqlite3`**: Decoded packet headers & metadata.
* **`payloads.sqlite3`**: Raw and decoded packet payloads (linked via `packet_id`).
* **`flows.sqlite3`**: Reassembled TCP/UDP sessions, SIP dialogs, and RTP streams.
* **`cache.sqlite3`**: Real-time alert notifications and temporary state caches.
* **`geoip.sqlite3`**: GeoIP lookup tables & IP endpoint metadata.
* **`dns.sqlite3`**: DNS query/answer caches and domain scans.

---

## 💡 Rules & Best Practices for AI Agents

1. **Zero-Drop Capture Integrity:**
   * Do NOT add synchronous file I/O, heavy parsing, or blocking calls directly inside `app/core/capture_manager.py`'s packet callback.
   * Maintain the `<2μs` hot-path latency by pushing raw items directly to `_capture_queue`.

2. **Database Batch Operations:**
   * All packet and payload inserts must use batching or background worker threads (`asyncio.to_thread` / transaction locks) to prevent database lock contention.
   * Ensure `packet_id` referential integrity between `packets.sqlite3` and `payloads.sqlite3`.

3. **Protocol Standards & Magic Bytes:**
   * Preserve STUN RFC 5389 magic cookie (`0x2112A442`) validation in [app/dpi/engine.py](file:///d:/cyberdeep/app/dpi/engine.py).
   * Respect TLS 1.3 `supported_versions` extension parsing when updating [app/core/fingerprint.py](file:///d:/cyberdeep/app/core/fingerprint.py).

4. **Verification & Testing:**
   * Always execute `python -m unittest discover tests` after modifying files in `app/core/`, `app/analysis/`, `app/protocols/`, or `app/dpi/`.
   * Verify that any UI modifications in `app/templates/unified.html` do not break WebSocket event streams (`/api/capture/live`).

5. **Windows & TShark Path Handling:**
   * CyberDEEP dynamically resolves `tshark` using `shutil.which("tshark")`. Maintain cross-platform compatibility without hardcoding Windows-only executable paths.
