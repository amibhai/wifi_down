"""Tests for HMAC chain algorithm — tamper detection."""
from __future__ import annotations

import hashlib
import hmac
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _make_key(machine_id: str = "test-machine", version: str = "2.0.0") -> bytes:
    return hashlib.sha256(f"{machine_id}:{version}".encode()).digest()


# ── Chain verification logic ─────────────────────────────────────────────────

def _build_chain(lines: list[str], key: bytes) -> tuple[list[str], str]:
    sigs: list[str] = []
    prev = ""
    for line in lines:
        sig = hmac.new(key, (prev + line).encode(), hashlib.sha256).hexdigest()
        sigs.append(sig)
        prev = sig
    return sigs, prev


def _verify_chain(log_lines: list[str], key: bytes, stored_final_sig: str) -> bool:
    prev = ""
    for line in log_lines:
        sig = hmac.new(key, (prev + line).encode(), hashlib.sha256).hexdigest()
        prev = sig
    return prev == stored_final_sig


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_chain_intact():
    key   = _make_key()
    lines = ["INFO|utils|Session started", "INFO|utils|Scan complete", "INFO|utils|Key found"]
    sigs, final_sig = _build_chain(lines, key)
    assert _verify_chain(lines, key, final_sig)


def test_chain_detects_tampered_line():
    key   = _make_key()
    lines = ["INFO|utils|Session started", "INFO|utils|Scan complete", "INFO|utils|Key found"]
    _, final_sig = _build_chain(lines, key)

    tampered = ["INFO|utils|Session started", "INFO|utils|TAMPERED LINE", "INFO|utils|Key found"]
    assert not _verify_chain(tampered, key, final_sig)


def test_chain_detects_deleted_line():
    key   = _make_key()
    lines = ["INFO|utils|Session started", "INFO|utils|Scan complete", "INFO|utils|Key found"]
    _, final_sig = _build_chain(lines, key)

    deleted = ["INFO|utils|Session started", "INFO|utils|Key found"]
    assert not _verify_chain(deleted, key, final_sig)


def test_chain_detects_appended_line():
    key   = _make_key()
    lines = ["INFO|utils|Session started", "INFO|utils|Scan complete"]
    _, final_sig = _build_chain(lines, key)

    appended = lines + ["INFO|utils|Extra line injected"]
    assert not _verify_chain(appended, key, final_sig)


def test_empty_chain_is_valid():
    key = _make_key()
    assert _verify_chain([], key, "")


def test_chain_consistent_across_calls():
    key   = _make_key()
    lines = ["DEBUG|deauth|Attack started bssid=AA:BB:CC:DD:EE:FF"]
    _, sig1 = _build_chain(lines, key)
    _, sig2 = _build_chain(lines, key)
    assert sig1 == sig2
