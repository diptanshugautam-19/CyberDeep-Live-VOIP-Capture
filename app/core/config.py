import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
GEOIP_DIR = DATA_DIR / "geoip"
DB_PATH = DATA_DIR / "ip_intel.sqlite3"
UPLOAD_DIR = DATA_DIR / "uploads"
REPORT_DIR = DATA_DIR / "reports"
APP_NAME = "VoIP WireStream"
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ONLINE_ENRICHMENT_ENABLED = os.getenv("ONLINE_ENRICHMENT_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
LIVE_LOOKUP_TIMEOUT_SECONDS = float(os.getenv("LIVE_LOOKUP_TIMEOUT_SECONDS", "4"))

for directory in (DATA_DIR, GEOIP_DIR, UPLOAD_DIR, REPORT_DIR):
    directory.mkdir(parents=True, exist_ok=True)
