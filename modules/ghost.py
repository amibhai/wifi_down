"""
GHOST SIGNAL TRACKER — CVE + firmware vulnerability intelligence.

Queries three sources in parallel (asyncio):
  1. NVD API (nvd.nist.gov) — CVE lookup by vendor keyword
  2. RouterSploit module index (local JSON cache, refreshed monthly)
  3. Shodan InternetDB API (free, no key) — exposed services by public IP

Caches all API responses to ~/.wifi-auditor/ghost_cache.db (SQLite, 7-day TTL).
Results surface as a GHOST column in the scan table and feed into the report.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

AUDIT_HOME  = Path.home() / ".wifi-auditor"
CACHE_DB    = AUDIT_HOME / "ghost_cache.db"
CACHE_TTL_S = 7 * 24 * 3600  # 7 days

NVD_API_URL          = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
ROUTERSPLOIT_CACHE_URL = (
    "https://raw.githubusercontent.com/threat9/routersploit/master/routersploit/"
    "modules/exploits/routers/__index__.json"
)


# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class CVEEntry:
    cve_id: str
    cvss_score: float
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    published: str
    patch_available: bool = False

    @property
    def badge(self) -> str:
        colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "dim"}
        c = colors.get(self.severity, "dim")
        return f"[{c}]{self.cve_id} CVSS {self.cvss_score}[/{c}]"


@dataclass
class RouterSploitEntry:
    module_path: str
    vendor: str
    description: str


@dataclass
class GhostReport:
    bssid: str
    vendor: str
    model: str
    cves: list[CVEEntry]              = field(default_factory=list)
    routersploit_modules: list[RouterSploitEntry] = field(default_factory=list)
    shodan_ports: list[int]           = field(default_factory=list)
    shodan_vulns: list[str]           = field(default_factory=list)
    public_ip: Optional[str]          = None
    queried_at: str                   = ""

    @property
    def badge_text(self) -> str:
        n = len(self.cves)
        if n == 0:
            return "[green]✅ Clean[/green]"
        if any(c.severity == "CRITICAL" for c in self.cves):
            return f"[bold red]🔴 {n} CVE{'s' if n > 1 else ''}[/bold red]"
        if any(c.severity == "HIGH" for c in self.cves):
            return f"[orange3]🟡 {n} CVE{'s' if n > 1 else ''}[/orange3]"
        return f"[yellow]🟡 {n} CVE{'s' if n > 1 else ''}[/yellow]"

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "vendor": self.vendor,
            "model": self.model,
            "cve_count": len(self.cves),
            "cves": [
                {"id": c.cve_id, "cvss": c.cvss_score, "severity": c.severity,
                 "description": c.description[:200]}
                for c in self.cves
            ],
            "routersploit_modules": [
                {"path": r.module_path, "description": r.description}
                for r in self.routersploit_modules
            ],
            "public_ip": self.public_ip,
            "shodan_ports": self.shodan_ports,
            "queried_at": self.queried_at,
        }


# ─── SQLite cache ─────────────────────────────────────────────────────────────

def _db_connect() -> sqlite3.Connection:
    AUDIT_HOME.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(CACHE_DB))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ghost_cache (
            cache_key TEXT PRIMARY KEY,
            payload   TEXT NOT NULL,
            cached_at INTEGER NOT NULL
        )
    """)
    conn.commit()
    return conn


def _cache_get(key: str) -> Optional[dict]:
    try:
        conn = _db_connect()
        row = conn.execute(
            "SELECT payload, cached_at FROM ghost_cache WHERE cache_key = ?", (key,)
        ).fetchone()
        conn.close()
        if row and (time.time() - row[1]) < CACHE_TTL_S:
            return json.loads(row[0])
    except Exception as exc:
        logger.debug("cache get %s: %s", key, exc)
    return None


def _cache_set(key: str, data: dict) -> None:
    try:
        conn = _db_connect()
        conn.execute(
            "INSERT OR REPLACE INTO ghost_cache (cache_key, payload, cached_at) VALUES (?,?,?)",
            (key, json.dumps(data), int(time.time())),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        logger.debug("cache set %s: %s", key, exc)


def _cache_key(source: str, query: str) -> str:
    return hashlib.sha256(f"{source}:{query}".encode()).hexdigest()[:24]


# ─── Async query functions ────────────────────────────────────────────────────

async def _query_nvd(vendor: str, model: str) -> list[CVEEntry]:
    """Query NVD CVE 2.0 API for vendor + optional model."""
    keyword = f"{vendor} {model}".strip() if model else vendor
    ck = _cache_key("nvd", keyword.lower())
    cached = _cache_get(ck)
    if cached:
        logger.debug("ghost: NVD cache hit for %s", keyword)
        return [CVEEntry(**c) for c in cached.get("cves", [])]

    try:
        import httpx
    except ImportError:
        # Fallback to requests (sync, wrapped in thread)
        return await asyncio.get_event_loop().run_in_executor(
            None, _query_nvd_sync, vendor, model, ck
        )

    entries: list[CVEEntry] = []
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 20,
            "startIndex": 0,
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(NVD_API_URL, params=params)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    c = vuln.get("cve", {})
                    cve_id = c.get("id", "")
                    desc   = ""
                    for d in c.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break
                    metrics  = c.get("metrics", {})
                    cvss     = 0.0
                    severity = "LOW"
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        arr = metrics.get(key, [])
                        if arr:
                            cvss_data = arr[0].get("cvssData", {})
                            cvss      = cvss_data.get("baseScore", 0.0)
                            severity  = cvss_data.get("baseSeverity",
                                        arr[0].get("baseSeverity", "LOW")).upper()
                            break
                    published = c.get("published", "")[:10]
                    entries.append(CVEEntry(
                        cve_id=cve_id,
                        cvss_score=cvss,
                        severity=severity,
                        description=desc[:300],
                        published=published,
                    ))

        _cache_set(ck, {"cves": [
            {"cve_id": e.cve_id, "cvss_score": e.cvss_score, "severity": e.severity,
             "description": e.description, "published": e.published}
            for e in entries
        ]})
    except Exception as exc:
        logger.warning("ghost: NVD query failed: %s", exc)

    return entries


def _query_nvd_sync(vendor: str, model: str, cache_key: str) -> list[CVEEntry]:
    """Synchronous NVD fallback using requests."""
    keyword = f"{vendor} {model}".strip() if model else vendor
    try:
        import requests
        resp = requests.get(
            NVD_API_URL,
            params={"keywordSearch": keyword, "resultsPerPage": 20, "startIndex": 0},
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        entries = []
        for vuln in resp.json().get("vulnerabilities", []):
            c      = vuln.get("cve", {})
            cve_id = c.get("id", "")
            desc   = next((d["value"] for d in c.get("descriptions", [])
                           if d.get("lang") == "en"), "")
            metrics = c.get("metrics", {})
            cvss, severity = 0.0, "LOW"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key, [])
                if arr:
                    d2 = arr[0].get("cvssData", {})
                    cvss     = d2.get("baseScore", 0.0)
                    severity = d2.get("baseSeverity",
                               arr[0].get("baseSeverity", "LOW")).upper()
                    break
            entries.append(CVEEntry(
                cve_id=cve_id, cvss_score=cvss, severity=severity,
                description=desc[:300], published=c.get("published", "")[:10],
            ))
        _cache_set(cache_key, {"cves": [
            {"cve_id": e.cve_id, "cvss_score": e.cvss_score, "severity": e.severity,
             "description": e.description, "published": e.published}
            for e in entries
        ]})
        return entries
    except Exception as exc:
        logger.warning("ghost: NVD sync query failed: %s", exc)
        return []


async def _query_routersploit(vendor: str) -> list[RouterSploitEntry]:
    """Check RouterSploit module index for vendor exploits (local cache)."""
    ck = _cache_key("routersploit", vendor.lower())
    cached = _cache_get(ck)
    if cached:
        return [RouterSploitEntry(**r) for r in cached.get("modules", [])]

    entries: list[RouterSploitEntry] = []
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(ROUTERSPLOIT_CACHE_URL)
            if resp.status_code == 200:
                data = resp.json() if isinstance(resp.json(), list) else []
                vendor_lower = vendor.lower()
                for mod in data:
                    mod_str = str(mod).lower()
                    if vendor_lower in mod_str:
                        entries.append(RouterSploitEntry(
                            module_path=str(mod),
                            vendor=vendor,
                            description=f"RouterSploit module for {vendor}",
                        ))
        _cache_set(ck, {"modules": [
            {"module_path": m.module_path, "vendor": m.vendor, "description": m.description}
            for m in entries
        ]})
    except Exception as exc:
        logger.debug("ghost: RouterSploit index query failed: %s", exc)

    return entries


async def _query_shodan_internetdb(ip: str) -> tuple[list[int], list[str]]:
    """Query Shodan InternetDB for exposed ports / known vulns (free, no key)."""
    if not ip or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return [], []

    ck = _cache_key("shodan", ip)
    cached = _cache_get(ck)
    if cached:
        return cached.get("ports", []), cached.get("vulns", [])

    ports: list[int]  = []
    vulns: list[str]  = []
    try:
        import httpx
        url = SHODAN_INTERNETDB_URL.format(ip=ip)
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data  = resp.json()
                ports = data.get("ports", [])
                vulns = data.get("vulns", [])
        _cache_set(ck, {"ports": ports, "vulns": vulns})
    except Exception as exc:
        logger.debug("ghost: Shodan InternetDB query failed for %s: %s", ip, exc)

    return ports, vulns


async def _get_public_ip_from_traceroute(target_ip: Optional[str] = None) -> Optional[str]:
    """Attempt to determine public IP via traceroute (best-effort, silent fail)."""
    return None  # Passive default — no active probing without user intent


# ─── Main Ghost runner ────────────────────────────────────────────────────────

async def _run_ghost_async(
    bssid: str,
    vendor: str,
    model: str = "",
    public_ip: Optional[str] = None,
) -> GhostReport:
    """Run all three source queries in parallel and aggregate results."""
    vendor_clean = re.sub(r"[^\w\s-]", "", vendor).strip()

    tasks = [
        _query_nvd(vendor_clean, model),
        _query_routersploit(vendor_clean),
        _query_shodan_internetdb(public_ip or ""),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    cves:      list[CVEEntry]           = results[0] if not isinstance(results[0], Exception) else []
    rs_mods:   list[RouterSploitEntry]  = results[1] if not isinstance(results[1], Exception) else []
    shodan_r   = results[2] if not isinstance(results[2], tuple) else results[2]
    if isinstance(shodan_r, Exception):
        shodan_r = ([], [])
    s_ports, s_vulns = shodan_r

    return GhostReport(
        bssid=bssid,
        vendor=vendor,
        model=model,
        cves=sorted(cves, key=lambda c: c.cvss_score, reverse=True),
        routersploit_modules=rs_mods,
        shodan_ports=s_ports,
        shodan_vulns=s_vulns,
        public_ip=public_ip,
        queried_at=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def run_ghost_tracker(
    bssid: str,
    vendor: str,
    model: str = "",
    public_ip: Optional[str] = None,
) -> GhostReport:
    """Synchronous wrapper around the async ghost runner."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(
                    asyncio.run,
                    _run_ghost_async(bssid, vendor, model, public_ip),
                )
                return fut.result(timeout=30)
        else:
            return loop.run_until_complete(
                _run_ghost_async(bssid, vendor, model, public_ip)
            )
    except Exception as exc:
        logger.warning("ghost tracker failed: %s", exc)
        return GhostReport(bssid=bssid, vendor=vendor, model=model)


# ─── Rich display ─────────────────────────────────────────────────────────────

def display_ghost_report(report: GhostReport) -> None:
    console.print()
    console.print(Panel(
        f"[bold #00D4AA]GHOST SIGNAL TRACKER[/bold #00D4AA]\n\n"
        f"  Vendor:   [cyan]{report.vendor or 'unknown'}[/cyan]\n"
        f"  Model:    [dim]{report.model or 'unknown'}[/dim]\n"
        f"  BSSID:    [dim]{report.bssid}[/dim]\n"
        f"  Status:   {report.badge_text}\n"
        f"  Queried:  [dim]{report.queried_at}[/dim]",
        border_style="#00D4AA",
    ))

    if report.cves:
        cve_table = Table(
            title=f"CVE Intelligence — {report.vendor}",
            box=box.ROUNDED,
            border_style="dim cyan",
            header_style="bold #00D4AA",
        )
        cve_table.add_column("CVE ID",   style="bold", width=18)
        cve_table.add_column("CVSS",     justify="center", width=6)
        cve_table.add_column("Severity", width=10)
        cve_table.add_column("Published", width=12)
        cve_table.add_column("Description", width=50)

        sev_colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "dim"}
        for c in report.cves[:10]:
            sc = sev_colors.get(c.severity, "dim")
            cve_table.add_row(
                c.cve_id,
                f"[{sc}]{c.cvss_score:.1f}[/{sc}]",
                f"[{sc}]{c.severity}[/{sc}]",
                c.published,
                c.description[:80] + ("…" if len(c.description) > 80 else ""),
            )
        console.print(cve_table)

    if report.routersploit_modules:
        console.print(f"\n  [bold yellow]RouterSploit modules ({len(report.routersploit_modules)}):[/bold yellow]")
        for m in report.routersploit_modules[:5]:
            console.print(f"  • [dim]{m.module_path}[/dim]")

    if report.shodan_ports:
        console.print(f"\n  [bold]Shodan — exposed ports on {report.public_ip}:[/bold]")
        console.print(f"  [cyan]{', '.join(str(p) for p in report.shodan_ports)}[/cyan]")

    if not report.cves and not report.routersploit_modules:
        console.print("\n  [green]No known CVEs or exploit modules found for this vendor.[/green]")

    console.print()


# ─── CLI entry point ──────────────────────────────────────────────────────────

def ghost_menu(target: Optional[dict]) -> Optional[GhostReport]:
    """Interactive Ghost Signal Tracker launcher."""
    console.print()
    console.print(Panel(
        "[bold #00D4AA]GHOST SIGNAL TRACKER[/bold #00D4AA]\n\n"
        "[dim]Queries NVD, RouterSploit index, and Shodan InternetDB\n"
        "in parallel to surface CVEs and known exploits for the target vendor.\n"
        "All results cached locally for 7 days.[/dim]",
        border_style="#00D4AA",
    ))
    console.print()

    if not target:
        console.print("[red]  No target selected. Scan first.[/red]")
        return None

    bssid  = target.get("bssid", "")
    vendor = target.get("vendor") or ""
    ssid   = target.get("ssid", "")

    if not vendor:
        console.print(f"  [yellow][!][/yellow] Vendor unknown for {bssid}")
        try:
            vendor = input("  Enter vendor name (e.g. TP-Link, Netgear): ").strip()
        except (KeyboardInterrupt, EOFError):
            return None

    model = ""
    try:
        model_in = input(f"  Model hint (optional, press Enter to skip): ").strip()
        model = model_in
    except (KeyboardInterrupt, EOFError):
        pass

    console.print(f"\n  [cyan][*][/cyan] Querying intelligence sources for [white]{vendor}[/white]...")

    report = run_ghost_tracker(bssid=bssid, vendor=vendor, model=model)

    display_ghost_report(report)

    # Audit log
    logger.info(
        "GHOST_TRACKER bssid=%s vendor=%s cves=%d rs_modules=%d",
        bssid, vendor, len(report.cves), len(report.routersploit_modules),
    )

    return report
