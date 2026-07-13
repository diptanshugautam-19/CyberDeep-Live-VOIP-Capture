import httpx

url = "http://127.0.0.1:8000/api/geoip/lookup?ip=Not%20Observable"
print(f"Requesting GET {url}...")
try:
    resp = httpx.get(url)
    print(f"Status Code: {resp.status_code}")
    print(f"JSON Response: {resp.json()}")
except Exception as e:
    print(f"Request failed: {e}")
