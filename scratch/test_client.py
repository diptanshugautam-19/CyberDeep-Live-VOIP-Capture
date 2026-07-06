import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

# 1. Fetch investigations
res = client.get("/api/investigations")
print("Investigations endpoint status:", res.status_code)
if res.status_code == 200:
    data = res.json()
    print(f"Investigations returned: {len(data)}")
    if data:
        print("First 3 investigations:")
        for idx, inv in enumerate(data[:3]):
            print(f"  [{idx+1}] ID: {inv['id']} | Filename: {inv['filename']} | Created: {inv['created_at']}")
else:
    print("Failed to fetch investigations:", res.text)
