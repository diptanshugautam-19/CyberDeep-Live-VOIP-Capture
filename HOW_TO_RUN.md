# 🚀 How to Run CyberDEEP (Quick Start Guide)

Welcome to **CyberDEEP** (DeepLive VOIP Capture & Military-Grade Forensic Console). 
Follow these quick steps to get the application up and running on your machine.

---

## 📋 Prerequisites

1. **Python 3.10+** (Python 3.10 - 3.13 supported)
2. **Wireshark / TShark** *(Optional, required only for live interface packet sniffing)*:
   - **Windows:** Download & install [Wireshark](https://www.wireshark.org/download.html) (make sure Npcap & TShark options are checked during installation).
   - **Linux:** `sudo apt install tshark wireshark`
   - **macOS:** `brew install tshark`

---

## ⚡ Setup & Launch Instructions

### Step 1: Open Terminal in Project Folder
Open your terminal (PowerShell / Command Prompt / Terminal) inside the extracted project directory.

### Step 2: (Recommended) Create Virtual Environment
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment:
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# Linux / macOS:
source .venv/bin/activate
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Start the Web Server & Console
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 🌐 Accessing the Application

Once the server is running, open your web browser and navigate to:

- **Main Dashboard & Forensic Console:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive OpenAPI Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check Status:** [http://127.0.0.1:8000/healthz](http://127.0.0.1:8000/healthz)

---

## 💡 Troubleshooting & Notes

- **Live Capture Permission:** On Linux/macOS, packet capture on raw network sockets may require elevated privileges (`sudo`).
- **Database Storage:** Database files are stored locally under the `data/` folder.
