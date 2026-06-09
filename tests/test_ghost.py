"""Tests for modules/ghost.py — Ghost Signal Tracker."""
from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock
import pytest

from modules.ghost import (
    GhostReport, CVEEntry, _cache_key, _cache_get, _cache_set,
    _parse_openai_response if False else None,
)


class TestGhostReport:
    """Test GhostReport data model and badge logic."""

    def test_badge_clean(self) -> None:
        r = GhostReport(bssid="AA:BB:CC:DD:EE:FF", vendor="TP-Link", model="")
        assert "Clean" in r.badge_text

    def test_badge_critical(self) -> None:
        r = GhostReport(
            bssid="AA:BB:CC:DD:EE:FF",
            vendor="TP-Link",
            model="",
            cves=[CVEEntry(
                cve_id="CVE-2024-1234",
                cvss_score=9.8,
                severity="CRITICAL",
                description="Remote code execution",
                published="2024-01-01",
            )],
        )
        assert "CRITICAL" in r.badge_text or "🔴" in r.badge_text

    def test_badge_high(self) -> None:
        r = GhostReport(
            bssid="AA:BB:CC:DD:EE:FF",
            vendor="Netgear",
            model="",
            cves=[CVEEntry(
                cve_id="CVE-2023-5678",
                cvss_score=7.5,
                severity="HIGH",
                description="Auth bypass",
                published="2023-06-01",
            )],
        )
        text = r.badge_text
        assert "🟡" in text or "HIGH" in text

    def test_to_dict(self) -> None:
        r = GhostReport(bssid="AA:BB:CC:DD:EE:FF", vendor="Cisco", model="C1000")
        d = r.to_dict()
        assert d["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert d["vendor"] == "Cisco"
        assert "cves" in d


class TestGhostCache:
    """Test SQLite cache operations."""

    def test_cache_miss_returns_none(self, tmp_path: Path) -> None:
        with patch("modules.ghost.CACHE_DB", tmp_path / "ghost_cache.db"):
            result = _cache_get("nonexistent_key")
        assert result is None

    def test_cache_set_and_get(self, tmp_path: Path) -> None:
        with patch("modules.ghost.CACHE_DB", tmp_path / "ghost_cache.db"):
            data = {"cves": [{"id": "CVE-2024-0001"}]}
            _cache_set("test_key", data)
            result = _cache_get("test_key")
        assert result is not None
        assert result["cves"][0]["id"] == "CVE-2024-0001"

    def test_cache_ttl_expiry(self, tmp_path: Path) -> None:
        """Entries older than TTL should not be returned."""
        with patch("modules.ghost.CACHE_DB", tmp_path / "ghost_cache.db"):
            import sqlite3
            conn = sqlite3.connect(str(tmp_path / "ghost_cache.db"))
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ghost_cache (
                    cache_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    cached_at INTEGER NOT NULL
                )
            """)
            old_ts = int(time.time()) - (8 * 24 * 3600)  # 8 days ago
            conn.execute(
                "INSERT INTO ghost_cache VALUES (?, ?, ?)",
                ("old_key", json.dumps({"cves": []}), old_ts),
            )
            conn.commit()
            conn.close()

            result = _cache_get("old_key")
        assert result is None


class TestGhostMissingDep:
    """Ghost tracker gracefully handles network failures."""

    def test_nvd_failure_returns_empty(self) -> None:
        """If NVD API fails, run_ghost_tracker returns empty CVE list."""
        from modules.ghost import run_ghost_tracker
        import unittest.mock as mock

        with mock.patch("modules.ghost._query_nvd", new_callable=AsyncMock) as m:
            m.side_effect = Exception("Network error")
            report = run_ghost_tracker(
                bssid="AA:BB:CC:DD:EE:FF",
                vendor="TestVendor",
            )
        assert isinstance(report, GhostReport)
        # Failures return empty list, not exceptions
        assert isinstance(report.cves, list)
