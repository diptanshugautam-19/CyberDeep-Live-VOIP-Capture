import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.enrichment.telecom import enrich_telecom
print(enrich_telecom("157.240.240.35"))
