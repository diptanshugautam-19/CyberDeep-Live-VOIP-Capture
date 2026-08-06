# IMPORTANT — CyberDEEP Production Deployment & Technical Handoff Guide

Comprehensive guide for deployment, environment setup, system tuning, and technical handoff of the **CyberDEEP** Network Forensics & WebRTC Attribution Platform.

---

## 🚀 Quick Start (Current Machine)

The application is already fully configured and ready.

1. **Start Server**:
   ```powershell
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
2. **Access Dashboard**:
   Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/) in your web browser.
3. **Run Unit Tests**:
   ```powershell
   python -m unittest discover tests
   ```

---

## 📋 New Machine Setup & Project Handoff

When deploying CyberDEEP to a new machine or handing over to another engineering team, follow these setup steps:

### 1. Prerequisites
- **Python 3.10+** (Python 3.13 recommended)
- **Wireshark / TShark** (for deep packet dissection)
- **Npcap** (Windows) or **libpcap** (Linux/macOS)

### 2. Installing & Configuring TShark (New Machine)

CyberDEEP uses Python's `shutil.which("tshark")` to dynamically locate TShark on any operating system.

#### Windows Setup:
1. Download & install Wireshark from [wireshark.org](https://www.wireshark.org/download.html). Ensure **TShark** is checked during installation.
2. Add Wireshark directory (e.g. `C:\Program Files\Wireshark\` or `D:\Wireshark\`) to System **`PATH`**:
   - Press `Win + R` → type `sysdm.cpl` → **Advanced** tab → **Environment Variables**.
   - Under **System variables**, select `Path` → **Edit** → **New** → paste Wireshark folder path.
3. Verify in Command Prompt/PowerShell:
   ```cmd
   tshark -v
   ```

#### Linux (Ubuntu/Debian) Setup:
```bash
sudo apt update && sudo apt install -y tshark wireshark
tshark -v
```

---

## ⚡ High-Speed Gbps Tuning (Npcap Buffer Setup)

For capturing high-speed **1Gbps / 10Gbps** network interfaces without kernel-level drops:

### 1. Npcap Installer Setting
During Npcap installation on Windows, ensure this box is checked:
- ✅ **"Install Npcap in WinPcap API-compatible Mode"**

### 2. High-Speed Kernel Buffer Code Setting
`app/core/capture_manager.py` is pre-configured with a **64 MB kernel socket buffer**:
```python
# app/core/capture_manager.py
from scapy.all import conf as scapy_conf
scapy_conf.bufsize = 64 * 1024 * 1024  # 64 MB kernel buffer
```

### 3. Windows System Registry Tuning (Optional for 24/7 high-load nodes)
Open **Command Prompt as Administrator**:
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters" /v MaxBufferSize /t REG_DWORD /d 67108864 /f
net stop npcap
net start npcap
```

---

## 🏗 Architecture & Key File Reference

### 1. Zero-Drop Packet Capture Architecture
- **[app/core/capture_manager.py](file:///d:/cyberdeep/app/core/capture_manager.py)**: Hot-path callback (`<2μs` per packet), 200,000-item capture queue (`_capture_queue`), dedicated consumer thread, and fast raw-byte VoIP prioritization filter (`_fast_is_voip`).
- **[app/core/bridge.py](file:///d:/cyberdeep/app/core/bridge.py)**: 100,000-item `PacketBridge` queue, dedicated pump thread, and non-blocking WebSocket priority broadcast snapshots (20ms batch interval).

### 2. Analysis & Protocols
- **[app/core/flow_engine.py](file:///d:/cyberdeep/app/core/flow_engine.py)**: Atomic `cursor.lastrowid` persistence, TCP state machine, and flow metrics.
- **[app/analysis/attribution_engine.py](file:///d:/cyberdeep/app/analysis/attribution_engine.py)**: Forensic STUN/TURN/ICE/SDP remote participant IP attribution.
- **[app/analysis/cli.py](file:///d:/cyberdeep/app/analysis/cli.py)**: Standalone CLI runner for PCAP forensic attribution.
- **[app/protocols/voip_manager.py](file:///d:/cyberdeep/app/protocols/voip_manager.py)**: Live VoIP manager with $O(1)$ endpoint indexing (`endpoint_index`), async `to_thread` database writes, and throttled WebSocket updates.
- **[app/protocols/tcp_media.py](file:///d:/cyberdeep/app/protocols/tcp_media.py)**: $O(1)$ `bytearray` stream reassembly, fast unmasking, and 1MB DoS buffer caps.
- **[app/dpi/engine.py](file:///d:/cyberdeep/app/dpi/engine.py)**: DPI engine with `collections.Counter` entropy and STUN RFC 5389 magic cookie (`0x2112A442`) validation.
- **[app/core/fingerprint.py](file:///d:/cyberdeep/app/core/fingerprint.py)**: JA3, JA4 (TLS 1.3 `supported_versions`), JA3S, JA4S, and HASSH fingerprint extraction.

### 3. API & Web UI
- **[app/main.py](file:///d:/cyberdeep/app/main.py)**: FastAPI entry point with sanitized exception handlers, CORS controls, and cross-platform TShark path resolution.
- **[app/templates/unified.html](file:///d:/cyberdeep/app/templates/unified.html)**: Real-Time Web Console UI with live packet stream, graph attribution, map markers, and forensic inspection.

---

## 🧪 Testing Suite

Run full automated tests:
```powershell
python -m unittest discover tests
```
Test modules included:
- `tests/test_tcp_media.py` (Framing detection & WebSocket unmasking)
- `tests/test_fingerprint.py` (TLS/SSH fingerprint parsers)
- `tests/test_attribution_engine.py` (STUN message & bogon IP checks)
