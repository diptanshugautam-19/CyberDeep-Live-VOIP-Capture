# Installation Guide

## Prerequisites

- Python 3.11 or newer
- Wireshark/tshark if you plan to use PyShark in future parser extensions
- Optional MaxMind GeoLite2 ASN and City databases for full offline attribution

## Windows PowerShell Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The application starts at `http://127.0.0.1:8000`.

## Optional Live Enrichment

To enable real-time online intelligence, configure:

```powershell
$env:IPINFO_TOKEN="your_ipinfo_token"
$env:ABUSEIPDB_API_KEY="your_abuseipdb_key"
$env:ONLINE_ENRICHMENT_ENABLED="true"
```

With these values set, the app uses live providers for:

- ASN and provider enrichment via `IPinfo`
- reputation scoring via `AbuseIPDB`

Without the keys, the app automatically falls back to local offline enrichment.

## Production Notes

- Run behind a reverse proxy with HTTPS.
- Store API keys for AbuseIPDB, OTX, and other feeds outside the repository.
- Replace `data/geoip/local_networks.json` with a production lookup dataset derived from GeoLite2.
- Keep uploaded evidence and SQLite databases on encrypted storage when handling sensitive investigations.
