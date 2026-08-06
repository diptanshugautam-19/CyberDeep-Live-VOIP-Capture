"""
IPv4 Enrichment Engine
======================
Production-grade worker pool + bounded job queue + async event bus +
IPv4-only GeoIP resolver with tiered fallback (SQLite cache → live APIs → offline ASN).

External dependencies:  httpx
Internal dependencies: app.storage.database.router, app.enrichment.asn_lookup
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, replace
from enum import Enum, auto
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

import httpx

from app.storage.database import router
from app.enrichment.asn_lookup import lookup_asn
from app.core.bridge import broadcast_manager

logger = logging.getLogger(__name__)

__all__ = [
    "IPv4EnrichmentEngine",
    "EnrichmentConfig",
    "EventType",
    "EnrichmentResult",
    "EnrichmentJob",
    "classify_endpoint",
    "EnrichmentEngine",
    "enrichment_engine",
]


# ============================================================================
# CLASSIFICATION HEURISTICS
# ============================================================================

def classify_endpoint(ip: str) -> str:
    """Intelligent Endpoint Classification heuristics for IPv4 & IPv6 addresses."""
    if ip.startswith("127.") or ip == "::1":
        return "Local Device"
    if ip.startswith("169.254."):
        return "Link-Local Device"
    if ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and len(ip.split(".")) == 4 and 16 <= int(ip.split(".")[1]) <= 31):
        if ip.endswith(".1") or ip.endswith(".254"):
            return "Gateway / Router"
        return "Internal Host"
    return "External Host"


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass(frozen=True)
class EnrichmentConfig:
    """Immutable runtime configuration for the enrichment pipeline."""

    worker_count: int = 4
    queue_max_size: int = 10_000
    provider_cooldown_seconds: int = 300
    cache_ttl_seconds: int = 604_800          # 7 days for live API hits
    offline_cache_ttl_seconds: int = 86_400   # 1 day for offline ASN fallback
    request_timeout: float = 10.0
    job_timeout_seconds: float = 30.0
    drain_timeout_seconds: float = 5.0
    user_agent: Optional[str] = None


# ============================================================================
# EVENTS & BROADCASTING
# ============================================================================

class EventType(Enum):
    """Lifecycle events emitted by the enrichment pipeline."""

    JOB_STARTED = auto()
    JOB_COMPLETED = auto()
    JOB_FAILED = auto()


@dataclass(frozen=True)
class EnrichmentJob:
    """Unit of work submitted to the engine."""

    job_id: str
    ip: str
    enqueued_at: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EnrichmentResult:
    """Outcome of a single enrichment job."""

    job: EnrichmentJob
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0
    source: str = ""
    event_type: EventType = EventType.JOB_COMPLETED


class EventBus:
    """Fire-and-forget async pub/sub with subscriber fault isolation.

    ``publish`` is synchronous and schedules callbacks in the background so
    producers (workers) never block on slow subscribers.
    """

    def __init__(self) -> None:
        self._subs: Dict[EventType, List[Callable[[EnrichmentResult], Awaitable[None]]]] = {
            et: [] for et in EventType
        }
        self._lock = asyncio.Lock()
        self._pending: Set[asyncio.Task[None]] = set()

    async def subscribe(
        self,
        event_type: EventType,
        callback: Callable[[EnrichmentResult], Awaitable[None]],
    ) -> None:
        """Register an async callback for a given event type."""
        async with self._lock:
            self._subs[event_type].append(callback)

    async def unsubscribe(
        self,
        event_type: EventType,
        callback: Callable[[EnrichmentResult], Awaitable[None]],
    ) -> None:
        """Remove a previously registered callback."""
        async with self._lock:
            try:
                self._subs[event_type].remove(callback)
            except ValueError:
                pass

    def publish(self, result: EnrichmentResult) -> None:
        """Schedule subscriber callbacks without blocking the caller."""
        callbacks = list(self._subs.get(result.event_type, []))
        if not callbacks:
            return

        async def _fire() -> None:
            await asyncio.gather(
                *[self._safe_call(cb, result) for cb in callbacks],
                return_exceptions=True,
            )

        try:
            task = asyncio.create_task(_fire())
        except RuntimeError:
            logger.debug("Dropping event %s: event loop not running.", result.event_type)
            return

        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def _safe_call(
        self,
        callback: Callable[[EnrichmentResult], Awaitable[None]],
        result: EnrichmentResult,
    ) -> None:
        try:
            await callback(result)
        except Exception:
            logger.exception("Event subscriber failed for job %s", result.job.job_id)

    async def wait_for_pending(self, timeout: Optional[float] = None) -> None:
        """Gracefully await any in-flight subscriber tasks."""
        if not self._pending:
            return
        try:
            await asyncio.wait_for(
                asyncio.gather(*self._pending, return_exceptions=True),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("Timed out waiting for pending event subscribers.")


# ============================================================================
# QUEUE  (bounded + in-flight deduplication)
# ============================================================================

class JobQueue:
    """Bounded asyncio queue with IP-level deduplication.

    An IP is considered "in flight" from the moment it is accepted into the
    queue until the worker calls ``task_done``. Duplicate submissions are
    silently dropped.
    """

    def __init__(self, max_size: int = 10_000) -> None:
        self._queue: asyncio.Queue[EnrichmentJob] = asyncio.Queue(maxsize=max_size)
        self._in_flight: Set[str] = set()
        self._lock = asyncio.Lock()

    async def enqueue(self, ip: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Enqueue an IP if it is not already pending and the queue is not full.

        Returns the generated ``job_id`` or ``None`` if the IP was dropped.
        """
        ip = ip.strip()
        if not ip:
            return None

        async with self._lock:
            if ip in self._in_flight:
                logger.debug("Duplicate enrichment for %s dropped.", ip)
                return None

            self._in_flight.add(ip)
            try:
                job = EnrichmentJob(
                    job_id=str(uuid.uuid4()),
                    ip=ip,
                    enqueued_at=time.time(),
                    metadata=metadata or {},
                )
                self._queue.put_nowait(job)
                return job.job_id
            except asyncio.QueueFull:
                self._in_flight.discard(ip)
                logger.warning("Enrichment queue full; dropping %s", ip)
                return None

    async def get(self) -> EnrichmentJob:
        """Block until a job is available."""
        return await self._queue.get()

    def task_done(self, ip: str) -> None:
        """Mark a job as finished and release the IP lock."""
        self._in_flight.discard(ip)
        self._queue.task_done()

    async def join(self) -> None:
        """Wait until all items in the queue have been processed."""
        await self._queue.join()

    @property
    def size(self) -> int:
        return self._queue.qsize()

    @property
    def in_flight_count(self) -> int:
        return len(self._in_flight)


# ============================================================================
# GEOIP ENGINE  (IPv4 ONLY)
# ============================================================================

@dataclass(frozen=True)
class _GeoIPData:
    """Normalized internal schema — immutable once built."""

    isp: str = ""
    asn: str = ""
    asn_number: str = ""
    asn_org: str = ""
    country: str = ""
    city: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    source: str = ""

    def normalize(self) -> Dict[str, Any]:
        """Export to the public dict schema with empty-string coalescing."""
        return {
            "isp": self.isp or self.asn_org,
            "asn": self.asn,
            "asn_number": self.asn_number,
            "asn_org": self.asn_org or self.isp,
            "country": self.country,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "ip_source": self.source,
        }


@dataclass(frozen=True)
class _Provider:
    """Descriptor for a single upstream GeoIP source."""

    name: str
    url_template: str
    validator: Callable[[Any], bool]
    parser: Callable[[Dict[str, Any]], _GeoIPData]


def _to_float(value: Any) -> Optional[float]:
    """Safely coerce an API scalar to float or None."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# --- Per-provider parsers ---------------------------------------------------

def _parse_ipwhois(data: Dict[str, Any]) -> _GeoIPData:
    conn = data.get("connection") or {}
    return _GeoIPData(
        isp=conn.get("isp", ""),
        asn=str(conn.get("asn") or ""),
        asn_number=str(conn.get("asn") or ""),
        asn_org=conn.get("org", ""),
        country=data.get("country", ""),
        city=data.get("city", ""),
        latitude=_to_float(data.get("latitude")),
        longitude=_to_float(data.get("longitude")),
    )


def _parse_freeipapi(data: Dict[str, Any]) -> _GeoIPData:
    return _GeoIPData(
        isp=data.get("ispName", ""),
        asn=str(data.get("asn") or ""),
        asn_number=str(data.get("asn") or ""),
        asn_org=data.get("asnOrg", ""),
        country=data.get("countryName", ""),
        city=data.get("cityName", ""),
        latitude=_to_float(data.get("latitude")),
        longitude=_to_float(data.get("longitude")),
    )


def _parse_ipapico(data: Dict[str, Any]) -> _GeoIPData:
    return _GeoIPData(
        isp=data.get("org", ""),
        asn=str(data.get("asn") or ""),
        asn_number=str(data.get("asn") or ""),
        asn_org=data.get("org", ""),
        country=data.get("country_name", ""),
        city=data.get("city", ""),
        latitude=_to_float(data.get("latitude")),
        longitude=_to_float(data.get("longitude")),
    )


def _parse_ip_api_com(data: Dict[str, Any]) -> _GeoIPData:
    as_field = data.get("as") or ""
    parts = as_field.split(None, 1)
    asn_number = parts[0].lstrip("AS") if parts else ""
    asn_org = parts[1] if len(parts) > 1 else ""
    return _GeoIPData(
        isp=data.get("isp", ""),
        asn=asn_number,
        asn_number=asn_number,
        asn_org=asn_org,
        country=data.get("country", ""),
        city=data.get("city", ""),
        latitude=_to_float(data.get("lat")),
        longitude=_to_float(data.get("lon")),
    )


# --- Provider registry ------------------------------------------------------

_IPV4_PROVIDERS: Tuple[_Provider, ...] = (
    _Provider(
        name="ipwhois",
        url_template="https://ipwho.is/{ip}",
        validator=lambda d: isinstance(d, dict) and d.get("success") is True,
        parser=_parse_ipwhois,
    ),
    _Provider(
        name="freeipapi",
        url_template="https://free.freeipapi.com/api/json/{ip}",
        validator=lambda d: isinstance(d, dict) and "ipAddress" in d,
        parser=_parse_freeipapi,
    ),
    _Provider(
        name="ipapi.co",
        url_template="https://ipapi.co/{ip}/json/",
        validator=lambda d: isinstance(d, dict) and not d.get("error") and "country_name" in d,
        parser=_parse_ipapico,
    ),
    _Provider(
        name="ip-api.com",
        url_template="http://ip-api.com/json/{ip}",
        validator=lambda d: isinstance(d, dict) and d.get("status") == "success",
        parser=_parse_ip_api_com,
    ),
)


def _is_public_ip(ip: str) -> bool:
    """Return ``True`` for valid, globally routable IPv4 or IPv6 addresses."""
    if not isinstance(ip, str) or not ip.strip():
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
        return addr.is_global and not addr.is_multicast
    except ValueError:
        return False


class GeoIPClient:
    """Universal IPv4 and IPv6 resolver: SQLite cache → live APIs → offline ASN fallback."""

    def __init__(self, config: EnrichmentConfig) -> None:
        self._cfg = config
        self._disabled: Dict[str, float] = {}
        self._http: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> GeoIPClient:
        headers = {"User-Agent": self._cfg.user_agent or "IPv4EnrichmentEngine/1.0"}
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(self._cfg.request_timeout, connect=5.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            headers=headers,
            follow_redirects=False,
        )
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def resolve(self, ip: str) -> _GeoIPData:
        """Resolve GeoIP for *ip* through cache, live APIs, or offline ASN."""
        if not _is_public_ip(ip):
            return _GeoIPData(source="invalid")

        cached = await self._read_cache(ip)
        if cached is not None:
            return replace(cached, source="Local GeoIP Cache")

        live = await self._query_live(ip)
        if live is not None:
            await self._write_cache(ip, live, self._cfg.cache_ttl_seconds)
            return live

        offline = await self._offline_asn(ip)
        if offline is not None:
            await self._write_cache(ip, offline, self._cfg.offline_cache_ttl_seconds)
            return offline

        return _GeoIPData(source="unresolved")

    # -- cache layer ---------------------------------------------------------

    async def _read_cache(self, ip: str) -> Optional[_GeoIPData]:
        try:
            rows = await asyncio.to_thread(
                router.execute,
                "geoip_lookup",
                "SELECT country, city, asn, isp, asn_org, latitude, longitude, "
                "updated_at, ttl FROM geoip_lookup WHERE ip = ?",
                (ip,),
            )
            if not rows:
                return None

            row = rows[0]
            updated_at = row.get("updated_at") or 0
            ttl = row.get("ttl") or 0
            if ttl > 0 and (int(time.time()) - updated_at) > ttl:
                return None

            return _GeoIPData(
                isp=row.get("isp") or row.get("asn") or "",
                asn=row.get("asn") or "",
                asn_org=row.get("asn_org") or "",
                country=row.get("country") or "",
                city=row.get("city") or "",
                latitude=_to_float(row.get("latitude")),
                longitude=_to_float(row.get("longitude")),
            )
        except Exception as e:
            logger.error("Cache read error for %s: %s", ip, e)
            return None

    async def _write_cache(self, ip: str, data: _GeoIPData, ttl: int) -> None:
        try:
            await asyncio.to_thread(
                router.execute,
                "geoip_lookup",
                "INSERT OR REPLACE INTO geoip_lookup "
                "(ip, country, city, asn, isp, asn_org, latitude, longitude, updated_at, ttl) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ip,
                    data.country,
                    data.city,
                    data.asn,
                    data.isp,
                    data.asn_org,
                    data.latitude,
                    data.longitude,
                    int(time.time()),
                    ttl,
                ),
            )
        except Exception as e:
            logger.error("Cache write error for %s: %s", ip, e)

    # -- live API layer ------------------------------------------------------

    async def _query_live(self, ip: str) -> Optional[_GeoIPData]:
        if self._http is None:
            return None

        now_ts = time.time()
        for provider in _IPV4_PROVIDERS:
            if self._disabled.get(provider.name, 0) > now_ts:
                continue

            try:
                resp = await self._http.get(provider.url_template.format(ip=ip))
            except httpx.TimeoutException as e:
                logger.debug("Provider %s timed out for %s: %s", provider.name, ip, e)
                continue
            except httpx.HTTPError as e:
                logger.debug("Provider %s HTTP error for %s: %s", provider.name, ip, e)
                continue

            if resp.status_code == 429:
                self._disabled[provider.name] = now_ts + self._cfg.provider_cooldown_seconds
                logger.info(
                    "Provider %s rate-limited; cooldown %ds.",
                    provider.name,
                    self._cfg.provider_cooldown_seconds,
                )
                continue
            if resp.status_code != 200:
                continue

            try:
                payload = resp.json()
            except ValueError as e:
                logger.debug("Provider %s returned invalid JSON for %s: %s", provider.name, ip, e)
                continue

            if not provider.validator(payload):
                continue

            parsed = provider.parser(payload)
            return replace(parsed, source=provider.name)

        return None

    # -- offline fallback ----------------------------------------------------

    async def _offline_asn(self, ip: str) -> Optional[_GeoIPData]:
        try:
            asn = await asyncio.to_thread(lookup_asn, ip)
            if not asn.get("asn_number"):
                return None
            return _GeoIPData(
                isp=asn.get("asn_org", ""),
                asn=asn.get("asn", ""),
                asn_number=str(asn.get("asn_number", "")),
                asn_org=asn.get("asn_org", ""),
                country=asn.get("asn_cc", ""),
                source="offline-db-ip",
            )
        except Exception as e:
            logger.error("Offline ASN lookup failed for %s: %s", ip, e)
            return None


# ============================================================================
# WORKER POOL
# ============================================================================

class WorkerPool:
    """Manages a fixed pool of asyncio workers that consume from a ``JobQueue``."""

    def __init__(self, queue: JobQueue, bus: EventBus, config: EnrichmentConfig) -> None:
        self._queue = queue
        self._bus = bus
        self._cfg = config
        self._geoip = GeoIPClient(config)
        self._tasks: List[asyncio.Task[None]] = []
        self._shutdown = asyncio.Event()

    async def start(self) -> None:
        """Spawn workers and open the GeoIP HTTP client."""
        await self._geoip.__aenter__()
        for i in range(self._cfg.worker_count):
            t = asyncio.create_task(
                self._loop(f"worker-{i}"),
                name=f"ipv4-enrichment-worker-{i}",
            )
            self._tasks.append(t)
        logger.info("IPv4 enrichment pool started (%d workers).", self._cfg.worker_count)

    async def stop(self, drain_timeout: Optional[float] = None) -> None:
        """Signal shutdown, optionally drain in-flight jobs, then clean up."""
        self._shutdown.set()
        timeout = drain_timeout if drain_timeout is not None else self._cfg.drain_timeout_seconds

        try:
            await asyncio.wait_for(self._queue.join(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("Drain timeout expired; forcing worker cancellation.")

        for t in self._tasks:
            if not t.done():
                t.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        await self._geoip.__aexit__(None, None, None)
        logger.info("IPv4 enrichment pool stopped.")

    async def _loop(self, worker_id: str) -> None:
        """Main worker loop — resilient to cancellation and exceptions."""
        while not self._shutdown.is_set():
            job: Optional[EnrichmentJob] = None
            try:
                job = await self._queue.get()
            except asyncio.CancelledError:
                break

            try:
                await self._process(worker_id, job)
            finally:
                if job is not None:
                    self._queue.task_done(job.ip)

    async def _process(self, worker_id: str, job: EnrichmentJob) -> None:
        """Execute a single enrichment job and publish lifecycle events."""
        t0 = time.perf_counter()

        self._bus.publish(
            EnrichmentResult(job=job, success=True, event_type=EventType.JOB_STARTED)
        )

        try:
            geo = await asyncio.wait_for(
                self._geoip.resolve(job.ip),
                timeout=self._cfg.job_timeout_seconds,
            )
        except asyncio.TimeoutError:
            elapsed = (time.perf_counter() - t0) * 1000
            self._bus.publish(
                EnrichmentResult(
                    job=job,
                    success=False,
                    error=f"Job timed out after {self._cfg.job_timeout_seconds}s",
                    duration_ms=elapsed,
                    source="timeout",
                    event_type=EventType.JOB_FAILED,
                )
            )
            return
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            logger.exception(
                "Worker %s crashed on job %s (IP %s): %s",
                worker_id,
                job.job_id,
                job.ip,
                e,
            )
            self._bus.publish(
                EnrichmentResult(
                    job=job,
                    success=False,
                    error=str(e),
                    duration_ms=elapsed,
                    source="worker-error",
                    event_type=EventType.JOB_FAILED,
                )
            )
            return

        elapsed = (time.perf_counter() - t0) * 1000

        if geo.source == "invalid":
            self._bus.publish(
                EnrichmentResult(
                    job=job,
                    success=False,
                    error="Not a valid public IPv4 address",
                    duration_ms=elapsed,
                    source="validation",
                    event_type=EventType.JOB_FAILED,
                )
            )
        elif geo.source == "unresolved":
            self._bus.publish(
                EnrichmentResult(
                    job=job,
                    success=False,
                    error="All providers and offline fallback exhausted",
                    duration_ms=elapsed,
                    source="unresolved",
                    event_type=EventType.JOB_FAILED,
                )
            )
        else:
            self._bus.publish(
                EnrichmentResult(
                    job=job,
                    success=True,
                    data=geo.normalize(),
                    duration_ms=elapsed,
                    source=geo.source,
                    event_type=EventType.JOB_COMPLETED,
                )
            )


# ============================================================================
# PUBLIC API & BACKWARD COMPATIBILITY BRIDGE
# ============================================================================

class IPv4EnrichmentEngine:
    """High-level orchestrator for IPv4 GeoIP enrichment.

    Usage::

        async with IPv4EnrichmentEngine() as engine:
            job_id = await engine.submit("8.8.8.8")
            await engine.subscribe(EventType.JOB_COMPLETED, my_handler)
    """

    def __init__(self, config: Optional[EnrichmentConfig] = None) -> None:
        self._cfg = config or EnrichmentConfig()
        self._queue = JobQueue(max_size=self._cfg.queue_max_size)
        self._bus = EventBus()
        self._pool = WorkerPool(self._queue, self._bus, self._cfg)
        self._running = False

    async def __aenter__(self) -> IPv4EnrichmentEngine:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> None:
        await self.shutdown()

    async def start(self) -> None:
        """Start the worker pool and open network resources."""
        if self._running:
            return
        self._running = True
        await self._pool.start()

    async def shutdown(self, drain_timeout: Optional[float] = None) -> None:
        """Gracefully stop workers, drain events, and release resources."""
        if not self._running:
            return
        await self._pool.stop(drain_timeout=drain_timeout)
        await self._bus.wait_for_pending(timeout=5.0)
        self._running = False

    async def submit(self, ip: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Submit an IP for enrichment.

        Returns a ``job_id`` or ``None`` if the IP was dropped (duplicate,
        invalid, or queue full).
        """
        if not self._running:
            await self.start()
        return await self._queue.enqueue(ip, metadata)

    async def subscribe(
        self,
        event_type: EventType,
        callback: Callable[[EnrichmentResult], Awaitable[None]],
    ) -> None:
        """Subscribe to enrichment lifecycle events."""
        await self._bus.subscribe(event_type, callback)

    async def unsubscribe(
        self,
        event_type: EventType,
        callback: Callable[[EnrichmentResult], Awaitable[None]],
    ) -> None:
        """Unsubscribe from enrichment lifecycle events."""
        await self._bus.unsubscribe(event_type, callback)

    @property
    def queue_size(self) -> int:
        """Number of jobs currently waiting in the queue."""
        return self._queue.size

    @property
    def in_flight(self) -> int:
        """Number of jobs currently queued or being processed."""
        return self._queue.in_flight_count


class EnrichmentEngine:
    """Compatibility bridge wrapping IPv4EnrichmentEngine for application integration."""

    def __init__(self) -> None:
        self.seen_ips: Set[str] = set()
        self.connection_counts: Dict[str, int] = defaultdict(int)
        self.inner_engine = IPv4EnrichmentEngine()
        self.running = False

    def trigger_ai_hook(self, event_type: str, data: dict) -> None:
        """Structured JSON callbacks prepared for drop-in AI modules."""
        payload = json.dumps({"event": event_type, "data": data})
        logger.debug(f"AI Hook Triggered [{event_type}]: {payload}")

    def start(self) -> None:
        self.running = True
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.inner_engine.start())
            loop.create_task(self._subscribe_events())
        except RuntimeError:
            pass
        logger.info("EnrichmentEngine (IPv4) started")

    async def _subscribe_events(self) -> None:
        async def _on_completed(res: EnrichmentResult) -> None:
            ip = res.job.ip
            flow_id = res.job.metadata.get("flow_id", "")
            endpoint_type = classify_endpoint(ip)
            connections = self.connection_counts[ip]
            
            geo_info = res.data if res.success else {}
            
            self.trigger_ai_hook("endpoint_enriched", {"ip": ip, "type": endpoint_type})
            
            await broadcast_manager.broadcast({
                "type": "enrichment",
                "flow_id": flow_id,
                "ip": ip,
                "geoip": geo_info,
                "classification": endpoint_type,
                "history_count": connections
            }, priority=2)

        await self.inner_engine.subscribe(EventType.JOB_COMPLETED, _on_completed)

    async def stop(self) -> None:
        self.running = False
        await self.inner_engine.shutdown()

    def enqueue_ip(self, ip: str, flow_id: str) -> None:
        """Enqueues an IP for non-blocking asynchronous enrichment."""
        self.connection_counts[ip] += 1
        if ip not in self.seen_ips:
            self.seen_ips.add(ip)
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.inner_engine.submit(ip, metadata={"flow_id": flow_id}))
            except RuntimeError:
                pass


enrichment_engine = EnrichmentEngine()

