"""OUI vendor intelligence — IEEE database + router default password lookup."""
from __future__ import annotations

import csv
import io
import logging
import sqlite3
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

OUI_DB_PATH  = Path.home() / ".wifi-auditor" / "oui.db"
OUI_URL      = "https://standards-oui.ieee.org/oui/oui.csv"
CACHE_TTL    = 30 * 86400   # 30 days in seconds
DEFAULTS_FILE = Path(__file__).parent.parent / "data" / "router_defaults.yaml"


# ─── Database helpers ─────────────────────────────────────────────────────────

def _db() -> sqlite3.Connection:
    OUI_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(OUI_DB_PATH))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS oui "
        "(prefix TEXT PRIMARY KEY, vendor TEXT)"
    )
    conn.commit()
    return conn


def _needs_refresh() -> bool:
    if not OUI_DB_PATH.exists():
        return True
    age = time.time() - OUI_DB_PATH.stat().st_mtime
    return age > CACHE_TTL


def refresh_database(force: bool = False) -> bool:
    """Download and cache the IEEE OUI database. Returns True on success."""
    if not force and not _needs_refresh():
        return True

    try:
        import requests
        logger.info("Downloading IEEE OUI database from %s ...", OUI_URL)
        resp = requests.get(OUI_URL, timeout=30)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("Could not download OUI database: %s", exc)
        return False

    rows: list[tuple[str, str]] = []
    try:
        reader = csv.DictReader(io.StringIO(resp.text))
        for row in reader:
            prefix = row.get("Assignment", "").upper().replace("-", ":")
            vendor = row.get("Organization Name", "").strip()
            if prefix and vendor:
                rows.append((prefix[:8], vendor))
    except Exception as exc:
        logger.warning("OUI CSV parse error: %s", exc)
        return False

    conn = _db()
    conn.execute("DELETE FROM oui")
    conn.executemany("INSERT OR REPLACE INTO oui VALUES (?,?)", rows)
    conn.commit()
    conn.close()
    logger.info("OUI database refreshed: %d vendors", len(rows))
    return True


# ─── Public API ───────────────────────────────────────────────────────────────

def get_vendor(bssid: str) -> Optional[str]:
    """Return the IEEE-registered vendor name for the given BSSID, or None."""
    if _needs_refresh():
        refresh_database()

    prefix = bssid.upper()[:8]   # e.g. "AA:BB:CC"
    try:
        conn = _db()
        row = conn.execute(
            "SELECT vendor FROM oui WHERE prefix=?", (prefix,)
        ).fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as exc:
        logger.debug("OUI lookup error: %s", exc)
        return None


def get_vendor_wordlist(bssid: str) -> list[str]:
    """
    Return a list of default password candidates derived from the router's
    vendor (Strategy 11 in wordlist.py).  {last4mac} is replaced with the
    last 4 hex chars of the BSSID.
    """
    vendor = get_vendor(bssid) or ""
    last4  = bssid.replace(":", "").lower()[-4:]

    try:
        import yaml
        with open(DEFAULTS_FILE) as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        logger.debug("router_defaults.yaml load error: %s", exc)
        return []

    passwords: list[str] = []
    for pattern, entry in data.get("vendor_defaults", {}).items():
        if pattern.lower() in vendor.lower():
            for pwd in entry.get("passwords", []):
                passwords.append(str(pwd).replace("{last4mac}", last4))
            break   # only first matching vendor

    # Deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for p in passwords:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result
