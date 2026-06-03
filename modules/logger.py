#!/usr/bin/env python3
"""
modules/logger.py — Structured session logger for WiFi Auditor
────────────────────────────────────────────────────────────────
Writes a timestamped JSON log for every auditing session.
Results (cracked keys, captured files) are appended as events.

Usage (internal):
    from modules.logger import SessionLogger
    log = SessionLogger(ssid="HomeNet")
    log.event("handshake_captured", file="captures/HomeNet-01.cap")
    log.event("key_found", key="p@ssw0rd")
    log.close()
"""

import json
import os
import time
from datetime import datetime, timezone


_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


class SessionLogger:
    """Append-only JSON-lines session log."""

    def __init__(self, ssid: str | None = None):
        os.makedirs(_LOG_DIR, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_ssid = (ssid or "unknown").replace("/", "_").replace(" ", "_")
        fname = f"session_{safe_ssid}_{ts}.jsonl"
        self._path = os.path.join(_LOG_DIR, fname)
        self._start = time.monotonic()
        self._ssid = ssid
        self._write({"event": "session_start", "ssid": ssid})

    # ── public API ──────────────────────────────────────────────────────────

    def event(self, name: str, **kwargs):
        """Record a named event with optional keyword metadata."""
        self._write({"event": name, **kwargs})

    def close(self, success: bool = False):
        elapsed = round(time.monotonic() - self._start, 2)
        self._write({"event": "session_end", "success": success, "elapsed_s": elapsed})

    # ── internals ───────────────────────────────────────────────────────────

    def _write(self, record: dict):
        record["ts"] = datetime.now(timezone.utc).isoformat()
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    @property
    def path(self) -> str:
        return self._path
