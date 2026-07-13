import time
import asyncio
import logging
from datetime import datetime, timezone
import httpx
from app.storage.database import router
from app.threat_intel.manager import ThreatIntelManager
from app.core.bridge import broadcast_manager
from app.enrichment.online import _parse_ip_api_result, _asn_number
from collections import defaultdict
import json

logger = logging.getLogger(__name__)

def classify_endpoint(ip: str) -> str:
    """Intelligent Endpoint Classification heuristics."""
    if ip.startswith("127.") or ip == "::1":
        return "Local Device"
    if ip.startswith("169.254."):
        return "Link-Local Device"
    if ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and len(ip.split(".")) == 4 and 16 <= int(ip.split(".")[1]) <= 31):
        if ip.endswith(".1") or ip.endswith(".254"):
            return "Gateway / Router"
        return "Internal Host"
    return "External Host"

class EnrichmentEngine:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.running = False
        self._worker_task = None
        self.threat_manager = ThreatIntelManager()
        self.seen_ips = set()
        self.connection_counts = defaultdict(int)

    def trigger_ai_hook(self, event_type: str, data: dict):
        """Structured JSON callbacks prepared for drop-in AI modules."""
        payload = json.dumps({"event": event_type, "data": data})
        # Future: send to AI clustering/NLP engine (e.g., via Kafka, RabbitMQ, or direct HTTP POST)
        logger.debug(f"AI Hook Triggered [{event_type}]: {payload}")

    def start(self):
        self.running = True
        self._worker_task = asyncio.create_task(self._worker_loop())
        logger.info("EnrichmentEngine worker loop started")

    async def stop(self):
        self.running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

    def enqueue_ip(self, ip: str, flow_id: str):
        """Enqueues an IP for asynchronous threat and geoip lookup."""
        self.connection_counts[ip] += 1
        
        # Non-blocking enqueue
        if ip not in self.seen_ips:
            self.seen_ips.add(ip)
            self.queue.put_nowait((ip, flow_id))
            
            # Trigger AI anomaly hook on high frequency
            if self.connection_counts[ip] == 1000:
                self.trigger_ai_hook("high_frequency_connection", {"ip": ip, "count": 1000})

    async def _worker_loop(self):
        async with httpx.AsyncClient(timeout=4.0) as client:
            while self.running:
                try:
                    ip, flow_id = await self.queue.get()
                    
                    # 1. GeoIP Lookup (Cache read-through + concurrent APIs)
                    geo_info = await self.lookup_geoip(client, ip)
                    
                    # 2. Threat Intel Lookup (wrapped in thread to prevent blocking event loop)
                    threat_info = await asyncio.to_thread(self.threat_manager.lookup, ip)
                    
                    endpoint_type = classify_endpoint(ip)
                    connections = self.connection_counts[ip]
                    
                    self.trigger_ai_hook("endpoint_enriched", {"ip": ip, "type": endpoint_type, "threat": threat_info})

                    # 3. Broadcast enriched details to UI (Priority 2)
                    await broadcast_manager.broadcast({
                        "type": "enrichment",
                        "flow_id": flow_id,
                        "ip": ip,
                        "geoip": geo_info,
                        "threat": threat_info,
                        "classification": endpoint_type,
                        "history_count": connections

                    }, priority=2)
                    
                    self.queue.task_done()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in Enrichment worker: {e}", exc_info=True)

    async def lookup_geoip(self, client: httpx.AsyncClient, ip: str) -> dict:
        """Looks up GeoIP using cached SQLite data, falling back to concurrent async APIs."""
        if ip.startswith(("127.", "192.168.", "10.", "172.16.", "169.254.")):
            return {
                "isp": "LAN/Local Network",
                "asn": "AS0",
                "country": "LAN",
                "region": "Local",
                "city": "Private subnet",
                "latitude": 0.0,
                "longitude": 0.0,
                "ip_source": "Local lookup"
            }

        now_timestamp = int(time.time())
        
        # 1. Check geoip.sqlite3 cache
        try:
            cached = router.execute(
                "geoip_lookup",
                "SELECT country, city, asn, latitude, longitude, updated_at, ttl FROM geoip_lookup WHERE ip = ?",
                (ip,)
            )
            if cached:
                row = cached[0]
                updated_at_str = row["updated_at"]
                ttl = row["ttl"]
                
                # Parse updated_at ISO string
                try:
                    updated_at_ts = datetime.fromisoformat(updated_at_str).timestamp()
                except ValueError:
                    updated_at_ts = now_timestamp
                
                # Check expiration
                if now_timestamp - updated_at_ts < ttl:
                    return {
                        "isp": row["asn"] or "",
                        "asn": row["asn"] or "",
                        "country": row["country"] or "",
                        "city": row["city"] or "",
                        "latitude": row["latitude"],
                        "longitude": row["longitude"],
                        "ip_source": "Local GeoIP Cache"
                    }
        except Exception as e:
            logger.error(f"Error checking GeoIP cache: {e}")

        # 2. Cache miss -> Hit concurrent APIs in parallel
        geo_data = await self._query_apis_concurrently(client, ip)
        if not geo_data:
            return {}

        # 3. Cache the result in geoip_lookup
        try:
            router.execute(
                "geoip_lookup",
                """INSERT OR REPLACE INTO geoip_lookup 
                (ip, country, city, asn, latitude, longitude, updated_at, ttl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ip,
                    geo_data.get("country"),
                    geo_data.get("city"),
                    geo_data.get("asn"),
                    geo_data.get("latitude"),
                    geo_data.get("longitude"),
                    datetime.now(timezone.utc).isoformat(),
                    86400  # 24 hours TTL
                )
            )
        except Exception as e:
            logger.error(f"Error saving GeoIP cache: {e}")

        return geo_data

    async def _query_apis_concurrently(self, client: httpx.AsyncClient, ip: str) -> dict:
        """Queries 5 GeoIP APIs in parallel using httpx.AsyncClient and returns the first success."""
        
        async def fetch_ipwhois():
            try:
                r = await client.get(f"https://ipwho.is/{ip}")
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, dict) and data.get("success") is True:
                        data["_source"] = "ipwhois"
                        return data
            except:
                pass
            return None

        async def fetch_freeipapi():
            try:
                r = await client.get(f"https://free.freeipapi.com/api/json/{ip}")
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, dict) and "ipAddress" in data:
                        data["_source"] = "freeipapi"
                        return data
            except:
                pass
            return None

        async def fetch_ipapi_com():
            try:
                r = await client.get(f"https://api.ipapi.com/api/{ip}?access_key=aaa1119c0fa056fe2253d2034216f78a")
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, dict) and not data.get("error") and "latitude" in data:
                        data["_source"] = "ipapi_com"
                        return data
            except:
                pass
            return None

        async def fetch_ipapi_co():
            try:
                r = await client.get(f"https://ipapi.co/{ip}/json/")
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, dict) and not data.get("error") and "country_name" in data:
                        data["_source"] = "ipapi.co"
                        return data
            except:
                pass
            return None

        async def fetch_ip_api_com():
            try:
                r = await client.get(f"http://ip-api.com/json/{ip}")
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, dict) and data.get("status") == "success":
                        data["_source"] = "ip-api.com"
                        return data
            except:
                pass
            return None

        tasks = [
            fetch_ipwhois(),
            fetch_freeipapi(),
            fetch_ipapi_com(),
            fetch_ipapi_co(),
            fetch_ip_api_com()
        ]

        # In order to return the first successful lookup:
        # We run them using asyncio.as_completed
        for completed in asyncio.as_completed(tasks):
            try:
                result = await completed
                if result:
                    # Parse using existing online.py mapping
                    return _parse_ip_api_result(result)
            except:
                pass
                
        return {}

# Singleton
enrichment_engine = EnrichmentEngine()
