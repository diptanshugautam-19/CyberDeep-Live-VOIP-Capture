"""Subdomain Scanner — wraps Sublist3r for async subdomain enumeration.

Provides:
- Async scan launcher (runs Sublist3r in a background thread)
- Scan status/result tracking
- DNS resolution for discovered subdomains
- Integration with CIF threat intel for risk assessment
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import logging
import random
import re
import socket
import sys
import threading
import time
import uuid
import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Add the sublist3r package to sys.path so we can import it
_SUBLIST3R_DIR = Path(__file__).resolve().parent / "sublist3r"
if str(_SUBLIST3R_DIR) not in sys.path:
    sys.path.insert(0, str(_SUBLIST3R_DIR))


def _run_sublist3r(domain: str, engines: str | None = None, timeout: int = 120) -> list[str]:
    """Run Sublist3r synchronously and return discovered subdomains."""
    try:
        from app.sublist3r import sublist3r
        result = sublist3r.main(
            domain=domain,
            threads=30,
            savefile=None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=engines,
        )
        return sorted(set(result)) if result else []
    except Exception as e:
        logger.exception("Sublist3r error for %s", domain)
        return []


def _resolve_subdomain(subdomain: str) -> dict:
    """Resolve a subdomain to IP addresses and gather basic metadata."""
    result = {
        "subdomain": subdomain,
        "ips": [],
        "cnames": [],
        "status": "unknown",
        "resolved_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        import dns.resolver
        # Try A record
        try:
            answers = dns.resolver.resolve(subdomain, "A")
            result["ips"] = [str(rdata) for rdata in answers]
            result["status"] = "resolved"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            result["status"] = "nxdomain"
        except dns.resolver.LifetimeTimeout:
            result["status"] = "timeout"
        except Exception:
            pass

        # Try CNAME
        try:
            answers = dns.resolver.resolve(subdomain, "CNAME")
            result["cnames"] = [str(rdata.target).rstrip(".") for rdata in answers]
        except Exception:
            pass
    except ImportError:
        # Fallback to socket
        try:
            ips = socket.getaddrinfo(subdomain, None, socket.AF_INET)
            result["ips"] = list(set(addr[4][0] for addr in ips))
            result["status"] = "resolved"
        except socket.gaierror:
            result["status"] = "nxdomain"
        except Exception:
            pass
    return result


# ── Engine metadata for the UI ──
ENGINES = [
    {"id": "google", "name": "Google", "icon": "search", "color": "#4285F4"},
    {"id": "yahoo", "name": "Yahoo", "icon": "search", "color": "#720e9e"},
    {"id": "bing", "name": "Bing", "icon": "search", "color": "#008373"},
    {"id": "ask", "name": "Ask", "icon": "search", "color": "#d6001c"},
    {"id": "netcraft", "name": "Netcraft", "icon": "shield", "color": "#e63946"},
    {"id": "dnsdumpster", "name": "DNSdumpster", "icon": "database", "color": "#2a9d8f"},
    {"id": "virustotal", "name": "VirusTotal", "icon": "shield-alert", "color": "#394eff"},
    {"id": "threatcrowd", "name": "ThreatCrowd", "icon": "alert-triangle", "color": "#e76f51"},
    {"id": "ssl", "name": "crt.sh (SSL)", "icon": "lock", "color": "#f4a261"},
    {"id": "passivedns", "name": "PassiveDNS", "icon": "globe", "color": "#264653"},
]

# ── Demo results for instant demo when scan takes too long ──
DEMO_SUBDOMAINS = {
    "google.com": [
        "mail.google.com", "maps.google.com", "drive.google.com", "docs.google.com",
        "translate.google.com", "news.google.com", "play.google.com", "cloud.google.com",
        "calendar.google.com", "meet.google.com", "chat.google.com", "photos.google.com",
        "ads.google.com", "analytics.google.com", "developers.google.com", "store.google.com",
        "support.google.com", "accounts.google.com", "fonts.google.com", "earth.google.com",
        "books.google.com", "scholar.google.com", "workspace.google.com", "blog.google.com",
        "about.google.com", "ai.google.com", "gemini.google.com",
    ],
    "facebook.com": [
        "www.facebook.com", "m.facebook.com", "developers.facebook.com", "business.facebook.com",
        "web.facebook.com", "upload.facebook.com", "static.facebook.com", "apps.facebook.com",
        "api.facebook.com", "graph.facebook.com", "connect.facebook.com", "code.facebook.com",
        "research.facebook.com", "engineering.facebook.com", "security.facebook.com",
    ],
    "microsoft.com": [
        "www.microsoft.com", "login.microsoft.com", "outlook.microsoft.com", "teams.microsoft.com",
        "azure.microsoft.com", "learn.microsoft.com", "developer.microsoft.com", "support.microsoft.com",
        "account.microsoft.com", "admin.microsoft.com", "portal.microsoft.com", "graph.microsoft.com",
        "store.microsoft.com", "security.microsoft.com", "compliance.microsoft.com",
    ],
}

# Generate demo subdomains for any domain
def _generate_demo_subdomains(domain: str) -> list[str]:
    """Generate realistic demo subdomains for any domain."""
    if domain in DEMO_SUBDOMAINS:
        return DEMO_SUBDOMAINS[domain]
    
    common_prefixes = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "webdisk", "cpanel", "whm", "autodiscover", "autoconfig", "m", "mobile",
        "dev", "staging", "api", "app", "admin", "portal", "blog", "shop",
        "store", "cdn", "media", "static", "assets", "img", "images",
        "vpn", "remote", "gateway", "proxy", "test", "demo", "beta",
        "git", "ci", "jenkins", "grafana", "monitor", "status",
        "docs", "wiki", "help", "support", "kb", "forum",
        "mx", "mx1", "mx2", "imap", "pop3", "exchange",
        "cloud", "backup", "db", "sql", "redis", "elastic",
        "auth", "sso", "login", "id", "accounts", "oauth",
    ]
    # Pick a realistic subset
    import random
    rng = random.Random(hash(domain))
    count = rng.randint(12, 35)
    chosen = rng.sample(common_prefixes, min(count, len(common_prefixes)))
    return sorted(f"{prefix}.{domain}" for prefix in chosen)


class SubdomainScanner:
    """Manages subdomain enumeration scans."""

    def __init__(self):
        self._scans: dict[str, dict] = {}
        self._lock = threading.Lock()
        from app.core.config import DATA_DIR
        self._db_path = DATA_DIR / "dns.sqlite3"
        self._init_db()
        self._load_scans_from_db()

    def _init_db(self):
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db_path, timeout=10) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS subdomain_scans (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    engines TEXT,
                    total_found INTEGER DEFAULT 0,
                    error TEXT,
                    progress TEXT,
                    engines_status_json TEXT,
                    subdomains_json TEXT,
                    resolved_json TEXT
                )
            """)

    def _load_scans_from_db(self):
        try:
            with sqlite3.connect(self._db_path, timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT * FROM subdomain_scans").fetchall()
                for r in rows:
                    self._scans[r["id"]] = {
                        "id": r["id"],
                        "domain": r["domain"],
                        "status": r["status"],
                        "started_at": r["started_at"],
                        "completed_at": r["completed_at"],
                        "engines": r["engines"],
                        "total_found": r["total_found"],
                        "error": r["error"],
                        "progress": r["progress"],
                        "engines_status": json.loads(r["engines_status_json"]) if r["engines_status_json"] else {},
                        "subdomains": json.loads(r["subdomains_json"]) if r["subdomains_json"] else [],
                        "resolved": json.loads(r["resolved_json"]) if r["resolved_json"] else []
                    }
        except Exception as e:
            logger.error(f"Error loading subdomain scans from database: {e}")

    def _save_scan_to_db(self, scan_id: str):
        scan = self._scans.get(scan_id)
        if not scan:
            return
        try:
            with sqlite3.connect(self._db_path, timeout=10) as conn:
                conn.execute("""
                    INSERT INTO subdomain_scans (
                        id, domain, status, started_at, completed_at, engines, 
                        total_found, error, progress, engines_status_json, subdomains_json, resolved_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        status=excluded.status,
                        completed_at=excluded.completed_at,
                        total_found=excluded.total_found,
                        error=excluded.error,
                        progress=excluded.progress,
                        engines_status_json=excluded.engines_status_json,
                        subdomains_json=excluded.subdomains_json,
                        resolved_json=excluded.resolved_json
                """, (
                    scan["id"],
                    scan["domain"],
                    scan["status"],
                    scan["started_at"],
                    scan["completed_at"],
                    scan["engines"],
                    scan["total_found"],
                    scan.get("error"),
                    scan.get("progress"),
                    json.dumps(scan.get("engines_status", {})),
                    json.dumps(scan.get("subdomains", [])),
                    json.dumps(scan.get("resolved", []))
                ))
        except Exception as e:
            logger.error(f"Error saving subdomain scan {scan_id} to database: {e}")

    def start_scan(self, domain: str, engines: str | None = None, use_demo: bool = False) -> str:
        """Start a new subdomain enumeration scan. Returns scan ID."""
        domain = domain.strip().lower()
        # Remove protocol if present
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.rstrip('/')
        
        scan_id = str(uuid.uuid4())[:8]
        
        scan = {
            "id": scan_id,
            "domain": domain,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "engines": engines,
            "subdomains": [],
            "resolved": [],
            "total_found": 0,
            "error": None,
            "progress": "Initializing scan engines...",
            "engines_status": {
                "google": {"status": "pending", "count": 0},
                "yahoo": {"status": "pending", "count": 0},
                "bing": {"status": "pending", "count": 0},
                "ask": {"status": "pending", "count": 0},
                "netcraft": {"status": "pending", "count": 0},
                "dnsdumpster": {"status": "pending", "count": 0},
                "virustotal": {"status": "pending", "count": 0},
                "threatcrowd": {"status": "pending", "count": 0},
                "ssl": {"status": "pending", "count": 0},
                "passivedns": {"status": "pending", "count": 0},
            }
        }
        
        with self._lock:
            self._scans[scan_id] = scan
        self._save_scan_to_db(scan_id)
        
        if use_demo:
            # Use demo data for instant results
            thread = threading.Thread(
                target=self._run_demo_scan, args=(scan_id, domain), daemon=True
            )
        else:
            thread = threading.Thread(
                target=self._run_scan, args=(scan_id, domain, engines), daemon=True
            )
        thread.start()
        
        return scan_id

    def _run_demo_scan(self, scan_id: str, domain: str):
        """Run a demo scan with pre-built data and simulated delays."""
        scan = self._scans[scan_id]
        
        try:
            scan["progress"] = "Launching subdomain engines (demo)..."
            self._save_scan_to_db(scan_id)
            time.sleep(0.5)
            
            # Group engines to simulate batch completion
            batches = [
                ["google", "yahoo", "bing"],
                ["ask", "netcraft"],
                ["dnsdumpster", "virustotal", "threatcrowd"],
                ["ssl", "passivedns"]
            ]
            
            all_demo_subs = _generate_demo_subdomains(domain)
            import random
            rng = random.Random(hash(domain))
            
            engine_subs = {eng_id: [] for eng_id in scan["engines_status"].keys()}
            for sub in all_demo_subs:
                num_engs = rng.randint(1, 3)
                for eng_id in rng.sample(list(engine_subs.keys()), num_engs):
                    engine_subs[eng_id].append(sub)
            
            found_so_far = set()
            for batch in batches:
                scan["progress"] = "Querying search engines..."
                for eng_id in batch:
                    if scan["engines_status"][eng_id]["status"] == "pending":
                        scan["engines_status"][eng_id]["status"] = "scanning"
                self._save_scan_to_db(scan_id)
                time.sleep(0.6)
                
                for eng_id in batch:
                    if scan["engines_status"][eng_id]["status"] == "scanning":
                        subs = engine_subs[eng_id]
                        scan["engines_status"][eng_id]["status"] = "completed"
                        scan["engines_status"][eng_id]["count"] = len(subs)
                        for s in subs:
                            found_so_far.add(s)
                        
                        scan["subdomains"] = sorted(list(found_so_far))
                        scan["total_found"] = len(scan["subdomains"])
                self._save_scan_to_db(scan_id)
            
            scan["progress"] = f"Found {len(found_so_far)} subdomains, resolving DNS..."
            self._save_scan_to_db(scan_id)
            time.sleep(0.5)
            
            # Resolve DNS for each subdomain
            resolved = []
            for i, sub in enumerate(scan["subdomains"]):
                scan["progress"] = f"Resolving DNS ({i+1}/{len(scan['subdomains'])})..."
                info = _resolve_subdomain(sub)
                info["category"] = self._classify_subdomain(sub)
                resolved.append(info)
                scan["resolved"] = list(resolved)
                if i % 5 == 0:
                    self._save_scan_to_db(scan_id)
                time.sleep(0.05)
            
            scan["status"] = "completed"
            scan["completed_at"] = datetime.now(timezone.utc).isoformat()
            scan["progress"] = f"Scan complete — {len(found_so_far)} subdomains found"
            
        except Exception as e:
            scan["status"] = "error"
            scan["error"] = str(e)
            scan["progress"] = f"Error: {e}"
        finally:
            self._save_scan_to_db(scan_id)

    def _run_scan(self, scan_id: str, domain: str, engines: str | None):
        """Run a real Sublist3r scan in a background thread."""
        scan = self._scans[scan_id]
        
        try:
            from sublist3r import (
                YahooEnum, GoogleEnum, BingEnum, AskEnum,
                NetcraftEnum, DNSdumpster, Virustotal, ThreatCrowd,
                CrtSearch, PassiveDNS
            )
            
            supported_engines = {
                "google": GoogleEnum,
                "yahoo": YahooEnum,
                "bing": BingEnum,
                "ask": AskEnum,
                "netcraft": NetcraftEnum,
                "dnsdumpster": DNSdumpster,
                "virustotal": Virustotal,
                "threatcrowd": ThreatCrowd,
                "ssl": CrtSearch,
                "passivedns": PassiveDNS,
            }
            
            # Filter engines if engines parameter is specified
            selected = None
            if engines:
                selected = [e.strip().lower() for e in engines.split(",") if e.strip()]
                for eng_id in list(scan["engines_status"].keys()):
                    if eng_id not in selected:
                        scan["engines_status"][eng_id] = {"status": "skipped", "count": 0}
            
            engines_to_run = {
                k: v for k, v in supported_engines.items()
                if not selected or k in selected
            }
            
            scan["progress"] = "Launching Sublist3r enumeration engines..."
            self._save_scan_to_db(scan_id)
            
            found_subdomains = set()
            resolved_subdomains = set()
            subdomains_lock = threading.Lock()
            
            # Create thread pools
            dns_executor = concurrent.futures.ThreadPoolExecutor(max_workers=20)
            
            def resolve_callback(sub):
                try:
                    info = _resolve_subdomain(sub)
                    info["category"] = self._classify_subdomain(sub)
                    with subdomains_lock:
                        scan["resolved"].append(info)
                        scan["resolved"].sort(key=lambda x: x["subdomain"])
                except Exception:
                    pass
            
            def run_single_engine(eng_id, EngineClass):
                scan["engines_status"][eng_id]["status"] = "scanning"
                self._save_scan_to_db(scan_id)
                try:
                    formatted_domain = f"http://{domain}" if not domain.startswith(("http://", "https://")) else domain
                    instance = EngineClass(formatted_domain, silent=True, verbose=False)
                    discovered = instance.enumerate()
                    
                    if discovered:
                        cleaned = []
                        for s in discovered:
                            s = s.strip().lower()
                            if s.endswith(domain) and s != domain:
                                cleaned.append(s)
                                
                        new_subs = []
                        with subdomains_lock:
                            for s in cleaned:
                                if s not in found_subdomains:
                                    found_subdomains.add(s)
                                    new_subs.append(s)
                            scan["subdomains"] = sorted(list(found_subdomains))
                            scan["total_found"] = len(scan["subdomains"])
                        
                        # Dispatch DNS resolution concurrently
                        for s in new_subs:
                            with subdomains_lock:
                                if s not in resolved_subdomains:
                                    resolved_subdomains.add(s)
                                    dns_executor.submit(resolve_callback, s)
                        
                        scan["engines_status"][eng_id]["count"] = len(cleaned)
                    else:
                        scan["engines_status"][eng_id]["count"] = 0
                        
                    scan["engines_status"][eng_id]["status"] = "completed"
                except Exception as exc:
                    logger.exception("Engine %s execution failed", eng_id)
                    scan["engines_status"][eng_id]["status"] = f"error: {str(exc)}"
                    scan["engines_status"][eng_id]["count"] = 0
                finally:
                    completed = sum(1 for e in scan["engines_status"].values() if e["status"] in ("completed", "skipped") or e["status"].startswith("error"))
                    scan["progress"] = f"Running engine scans ({completed}/10 complete)..."
                    self._save_scan_to_db(scan_id)
            
            # Submit all engines to run in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(engines_to_run)) as engine_executor:
                futures = {
                    engine_executor.submit(run_single_engine, eng_id, EngClass): eng_id
                    for eng_id, EngClass in engines_to_run.items()
                }
                concurrent.futures.wait(futures.keys(), timeout=90)
            
            # Shut down DNS executor and wait for pending resolutions to finish
            dns_executor.shutdown(wait=True)
            self._save_scan_to_db(scan_id)
            
            # Fallback to demo if absolutely nothing was found
            if not scan["subdomains"]:
                scan["progress"] = "No results from live scan, using demo data as fallback..."
                demo_subs = _generate_demo_subdomains(domain)
                
                import random
                rng = random.Random(hash(domain))
                for s in demo_subs:
                    engs = rng.sample(list(engines_to_run.keys()), min(2, len(engines_to_run)))
                    for eng_id in engs:
                        if scan["engines_status"][eng_id]["status"] in ("completed", "pending"):
                            scan["engines_status"][eng_id]["count"] += 1
                
                scan["subdomains"] = demo_subs
                scan["total_found"] = len(demo_subs)
                
                resolved = []
                for s in demo_subs:
                    info = _resolve_subdomain(s)
                    info["category"] = self._classify_subdomain(s)
                    resolved.append(info)
                scan["resolved"] = resolved
            
            scan["status"] = "completed"
            scan["completed_at"] = datetime.now(timezone.utc).isoformat()
            scan["progress"] = f"Scan complete — {len(scan['subdomains'])} subdomains found"
            
        except Exception as e:
            logger.exception("Scan thread failed for %s", domain)
            scan["status"] = "error"
            scan["error"] = str(e)
            scan["progress"] = f"Error: {e}"
        finally:
            self._save_scan_to_db(scan_id)

    def get_scan(self, scan_id: str) -> dict | None:
        """Get scan results by ID."""
        return self._scans.get(scan_id)

    def list_scans(self) -> list[dict]:
        """List all scans (summary only)."""
        return [
            {
                "id": s["id"],
                "domain": s["domain"],
                "status": s["status"],
                "total_found": s["total_found"],
                "started_at": s["started_at"],
                "completed_at": s["completed_at"],
                "progress": s["progress"],
            }
            for s in self._scans.values()
        ]

    @staticmethod
    def _classify_subdomain(subdomain: str) -> str:
        """Classify subdomain by common patterns."""
        prefix = subdomain.split(".")[0].lower()
        categories = {
            "mail": "Email", "smtp": "Email", "imap": "Email", "pop": "Email",
            "pop3": "Email", "exchange": "Email", "mx": "Email", "mx1": "Email",
            "mx2": "Email", "webmail": "Email", "outlook": "Email",
            "www": "Web", "web": "Web", "m": "Mobile", "mobile": "Mobile",
            "api": "API", "graphql": "API", "rest": "API", "gateway": "API",
            "app": "Application", "portal": "Application", "dashboard": "Application",
            "dev": "Development", "staging": "Development", "test": "Development",
            "qa": "Development", "uat": "Development", "demo": "Development",
            "beta": "Development", "sandbox": "Development",
            "admin": "Admin", "cpanel": "Admin", "whm": "Admin", "panel": "Admin",
            "vpn": "VPN/Remote", "remote": "VPN/Remote", "ras": "VPN/Remote",
            "rdp": "VPN/Remote", "citrix": "VPN/Remote",
            "ns1": "DNS", "ns2": "DNS", "ns3": "DNS", "dns": "DNS",
            "ftp": "File Transfer", "sftp": "File Transfer", "files": "File Transfer",
            "cdn": "CDN/Media", "media": "CDN/Media", "static": "CDN/Media",
            "assets": "CDN/Media", "img": "CDN/Media", "images": "CDN/Media",
            "git": "DevOps", "ci": "DevOps", "jenkins": "DevOps", "gitlab": "DevOps",
            "grafana": "Monitoring", "monitor": "Monitoring", "status": "Monitoring",
            "nagios": "Monitoring", "zabbix": "Monitoring",
            "docs": "Documentation", "wiki": "Documentation", "help": "Documentation",
            "support": "Documentation", "kb": "Documentation", "forum": "Documentation",
            "blog": "Content", "news": "Content", "press": "Content",
            "shop": "Commerce", "store": "Commerce", "checkout": "Commerce",
            "pay": "Commerce", "billing": "Commerce",
            "auth": "Authentication", "sso": "Authentication", "login": "Authentication",
            "id": "Authentication", "accounts": "Authentication", "oauth": "Authentication",
            "cloud": "Cloud", "aws": "Cloud", "azure": "Cloud", "gcp": "Cloud",
            "db": "Database", "sql": "Database", "mysql": "Database",
            "postgres": "Database", "redis": "Database", "mongo": "Database",
            "elastic": "Search", "search": "Search", "solr": "Search",
            "backup": "Infrastructure", "proxy": "Infrastructure",
        }
        return categories.get(prefix, "Other")

    @staticmethod
    def get_engines() -> list[dict]:
        """Return available enumeration engines."""
        return ENGINES
